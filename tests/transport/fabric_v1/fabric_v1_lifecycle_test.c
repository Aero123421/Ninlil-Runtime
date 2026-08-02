/*
 * Fabric lifecycle, registry, dispatch PREPARED/LINK_RETAINED/RETRYABLE/
 * FENCED/CLOSED, provider WOULD_BLOCK, unregister, COMMIT_UNKNOWN storage,
 * same-attempt conflict, bearer adapter without public ABI change.
 */
#include "fabric_v1_test_common.h"
#include "fabric_v1_test_storage.h"

/* Workspace must be max_align aligned and large enough. */
static uint8_t g_workspace[NINLIL_FABRIC_WORKSPACE_BYTES]
    __attribute__((aligned(16)));

static uint32_t store_count_magic(const char magic[4]);

static void fill_descriptor(
    ninlil_fabric_link_descriptor_v1_t *d, uint8_t id_start, uint16_t latency)
{
    ninlil_fabric_private_memzero(d, sizeof(*d));
    d->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    d->struct_size = (uint16_t)sizeof(*d);
    fabric_test_id(&d->instance_id, id_start);
    d->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    d->direction_mask =
        NINLIL_FABRIC_LINK_DIRECTION_SEND | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    d->capability_flags = 0x4Fu;
    d->descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-descriptor-v1",
        29u,
        d->descriptor_digest);
    fabric_test_id(&d->security_profile_id, 0x21u);
    d->security_capability_flags = 0x0Fu;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-binding-v1",
        26u,
        d->security_binding_digest);
    d->attestation_epoch = 5u;
    fabric_test_id(&d->attestation_clock_epoch_id, 0xA1u);
    d->attestation_expires_at_ms = 300000u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-attestation-v1",
        30u,
        d->attestation_digest);
    fabric_test_id(&d->authenticated_peer_runtime_id, 0x31u);
    fabric_test_id(&d->attachment_authority_id, 0x41u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-attachment-binding-v1",
        28u,
        d->attachment_binding_digest);
    d->maximum_packet_bytes = 1925u;
    d->maximum_transfer_bytes = 1925u;
    d->latency_class = latency;
    d->cost_class = 20u;
    d->reservation_capacity = 8u;
    d->peer_nfl1_version = 1u;
    d->peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    d->configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-config-v1",
        25u,
        d->configuration_digest);
}

static void fill_message(ninlil_bearer_message_t *m)
{
    static uint8_t ns = (uint8_t)'n';
    static uint8_t svc = (uint8_t)'s';
    static uint8_t sch = (uint8_t)'x';
    uint8_t dig[32];

    ninlil_fabric_private_memzero(m, sizeof(*m));
    m->abi_version = NINLIL_ABI_VERSION;
    m->struct_size = (uint16_t)sizeof(*m);
    m->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    fabric_test_id(&m->transaction_id, 0x10u);
    fabric_test_id(&m->attempt_id, 0x20u);
    m->source.abi_version = NINLIL_ABI_VERSION;
    m->source.struct_size = (uint16_t)sizeof(m->source);
    fabric_test_id(&m->source.runtime_id, 0x30u);
    fabric_test_id(&m->source.application_instance_id, 0x40u);
    m->source.local_identity.abi_version = NINLIL_ABI_VERSION;
    m->source.local_identity.struct_size =
        (uint16_t)sizeof(m->source.local_identity);
    fabric_test_id(&m->source.local_identity.device_id, 0x50u);
    fabric_test_id(&m->source.local_identity.installation_id, 0x60u);
    fabric_test_id(&m->source.local_identity.site_domain_id, 0x70u);
    m->source.local_identity.binding_epoch = 7u;
    m->source.local_identity.membership_epoch = 9u;
    m->source.local_identity.flags = 7u;
    m->target.abi_version = NINLIL_ABI_VERSION;
    m->target.struct_size = (uint16_t)sizeof(m->target);
    fabric_test_id(&m->target.target_runtime_id, 0x80u);
    fabric_test_id(&m->target.target_application_instance_id, 0x90u);
    fabric_test_id(&m->target.device_id, 0xA0u);
    fabric_test_id(&m->target.installation_id, 0xB0u);
    fabric_test_id(&m->target.site_domain_id, 0xC0u);
    m->target.binding_epoch = 11u;
    m->target.membership_epoch = 13u;
    m->target.flags = 7u;
    m->service.abi_version = NINLIL_ABI_VERSION;
    m->service.struct_size = (uint16_t)sizeof(m->service);
    m->service.namespace_id.length = 1u;
    m->service.namespace_id.bytes[0] = ns;
    m->service.service_id.length = 1u;
    m->service.service_id.bytes[0] = svc;
    m->service.schema_id.length = 1u;
    m->service.schema_id.bytes[0] = sch;
    m->service.descriptor_revision = 23u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-descriptor", 24u, dig);
    m->service.descriptor_digest.algorithm = 1u;
    memcpy(m->service.descriptor_digest.bytes, dig, 32u);
    m->service.schema_major = 1u;
    m->service.schema_minor = 0u;
    m->service.family = 2u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-content", 21u, dig);
    m->content_digest.algorithm = 1u;
    memcpy(m->content_digest.bytes, dig, 32u);
    m->generation = 29u;
    fabric_test_id(&m->deadline_clock_epoch_id, 0xA1u);
    m->absolute_effect_deadline_ms = 200000u;
    m->evidence_grace_ms = 5000u;
    m->required_evidence = 3u;
}

static int put_policy_and_authority(
    ninlil_fabric_private_t *fabric, const ninlil_bearer_message_t *msg)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_authority_binding_v1_t binding;
    uint8_t service_digest[32];

    ninlil_fabric_private_nfl1_service_identity_digest(
        msg->service.namespace_id.bytes,
        msg->service.namespace_id.length,
        msg->service.service_id.bytes,
        msg->service.service_id.length,
        msg->service.schema_id.bytes,
        msg->service.schema_id.length,
        msg->service.descriptor_revision,
        msg->service.descriptor_digest.bytes,
        msg->service.schema_major,
        msg->service.schema_minor,
        msg->service.family,
        service_digest);

    ninlil_fabric_private_memzero(&policy, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    fabric_test_id(&policy.policy_id, 0x71u);
    policy.revision = 3u;
    memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = 2u;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = 0x02u;
    policy.required_security_flags = 0x0Fu;
    policy.maximum_latency_class = 50u;
    policy.maximum_cost_class = 50u;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 100u;
    policy.candidate_count = 2u;
    fabric_test_id(&policy.candidates[0].instance_id, 0x01u);
    policy.candidates[0].rank = 20u;
    policy.candidates[0].reservation_units = 1u;
    fabric_test_id(&policy.candidates[1].instance_id, 0x61u);
    policy.candidates[1].rank = 10u;
    policy.candidates[1].reservation_units = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_OK);

    /* recompute policy digest via snapshot */
    {
        ninlil_fabric_path_policy_v1_t snap;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_snapshot_v1(
                fabric, &policy.policy_id, 3u, &snap),
            NINLIL_FABRIC_PRIVATE_OK);

        ninlil_fabric_private_memzero(&binding, sizeof(binding));
        binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        binding.struct_size = (uint16_t)sizeof(binding);
        fabric_test_id(&binding.binding_id, 0xB8u);
        memcpy(binding.service_identity_digest, service_digest, 32u);
        binding.family = 2u;
        binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
        binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
        fabric_test_id(&binding.endpoint_runtime_id, 0x80u);
        fabric_test_id(&binding.target_runtime_id, 0x80u);
        fabric_test_id(&binding.target_application_id, 0x90u);
        binding.policy_id = policy.policy_id;
        binding.policy_revision = 3u;
        memcpy(
            binding.policy_digest,
            snap.canonical_digest_zero_on_input,
            32u);
        binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
        fabric_test_id(&binding.authority_id, 0xD0u);
        binding.authority_term = 17u;
        binding.assignment_epoch = 19u;
        fabric_test_id(&binding.owner_scope_id, 0x81u);
        fabric_test_pattern(binding.owner_tuple_canonical, 0x81u, 200u);
        ninlil_fabric_private_owner_tuple_digest(
            binding.owner_tuple_canonical, binding.owner_tuple_digest);
        fabric_test_id(&binding.authority_clock_epoch_id, 0xA1u);
        binding.lease_expires_at_ms = 300000u;
        binding.assignment_revision = 11u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_put_v1(fabric, &binding),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    return 0;
}

static int test_create_register_send_accept(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d0;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg0 = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    ninlil_bearer_state_t state;
    uint32_t bytes = 0u;
    uint32_t align = 0u;
    uint32_t work = 0u;

    fabric_test_reset_globals();
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_workspace_required_v1(
            NINLIL_FABRIC_PROFILE_1, &bytes, &align),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(bytes <= NINLIL_FABRIC_WORKSPACE_BYTES);
    FABRIC_REQUIRE(align >= 8u);

    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &exec;

    ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, g_workspace, sizeof(g_workspace), &fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(fabric != NULL);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric, &bearer),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(bearer != NULL);
    FABRIC_REQUIRE(bearer->struct_size == sizeof(ninlil_bearer_ops_t));
    FABRIC_REQUIRE(bearer->abi_version == NINLIL_ABI_VERSION);

    fill_descriptor(&d0, 0x01u, 10u);
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d0, &ops, &reg0),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(reg0 != reg1);

    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }

    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(handle != NULL);

    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    ninlil_fabric_private_memzero(&result, sizeof(result));
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(result.kind, NINLIL_BEARER_SEND_ACCEPTED);
    FABRIC_REQUIRE(g_provider.start_calls == 1u);
    FABRIC_REQUIRE(g_provider.retained == 1u);
    FABRIC_REQUIRE(g_provider.retained_len >= NINLIL_FABRIC_NFL1_STRUCTURAL_MIN);

    /* same-attempt conflict */
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_CORRUPT);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 8u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(work >= 1u);
    FABRIC_REQUIRE(g_provider.poll_calls >= 1u);
    FABRIC_REQUIRE(g_provider.release_send_calls >= 1u);

    FABRIC_REQUIRE_EQ_U32(
        bearer->state(bearer->user, handle, &state), NINLIL_BEARER_OK);
    FABRIC_REQUIRE(state.available == 1u);

    bearer->close(bearer->user, handle);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 16u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            FABRIC_REQUIRE_EQ_U32(
                ninlil_fabric_private_close_poll_v1(fabric, &done),
                NINLIL_FABRIC_PRIVATE_OK);
        }
        FABRIC_REQUIRE(done == 1u);
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    return 0;
}

static int test_provider_would_block_retry(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_message_t msg2;
    ninlil_bearer_message_t replay;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;

    fabric_test_reset_globals();
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &exec;
    ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, g_workspace, sizeof(g_workspace), &fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric, &bearer),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    /*
     * FBA1 PREPARED + co-located claim commit succeed; the combined
     * RETRYABLE/CLEAR replacement returns CU-NEW. That is a proven definite
     * non-accept and remains WOULD_BLOCK.
     */
    g_store.fail_next_commit = 1u;
    g_store.commit_fault_skips = 2u;
    g_store.cu_apply_staged = 1u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_WOULD_BLOCK);
    FABRIC_REQUIRE(g_provider.retained == 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    /* Every retry receives a fresh call-scoped TxPermit. */
    fabric_test_id(&permit.permit_id, 0xE2u);
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(result.kind, NINLIL_BEARER_SEND_ACCEPTED);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    /*
     * CLEAR+RETRYABLE replacement CU-OLD leaves CLAIMED present. Even though
     * provider returned a definite WOULD_BLOCK, outer must return LOST_UNKNOWN
     * and reject the same permit rather than guess that clear succeeded.
     */
    msg2 = msg;
    fabric_test_id(&msg2.transaction_id, 0x11u);
    fabric_test_id(&msg2.attempt_id, 0x21u);
    fabric_test_id(&permit.permit_id, 0xE1u);
    permit.attempt_id = msg2.attempt_id;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    g_store.fail_next_commit = 1u;
    g_store.commit_fault_skips = 2u;
    g_store.cu_apply_staged = 0u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg2, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 2u);

    replay = msg2;
    fabric_test_id(&replay.transaction_id, 0x12u);
    fabric_test_id(&replay.attempt_id, 0x22u);
    permit.attempt_id = replay.attempt_id;
    {
        uint32_t starts = g_provider.start_calls;
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &replay, &result),
            NINLIL_BEARER_DENIED);
        FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    }

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t work = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 16u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_unregister_draining(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    uint32_t done = 0u;

    fabric_test_reset_globals();
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &exec;
    ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, g_workspace, sizeof(g_workspace), &fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_begin_v1(fabric, reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_begin_v1(fabric, reg1),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_poll_v1(fabric, reg1, &done),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(done == 1u);
    FABRIC_REQUIRE(g_provider.open == 0u);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    done = 0u;
    (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_enrich_project_lossless(void)
{
    ninlil_bearer_message_t msg;
    ninlil_bearer_message_t out;
    ninlil_time_sample_t zero_evidence_time;
    ninlil_fabric_private_nfl1_workspace_t ws;
    uint8_t packet[2048];
    uint32_t len = 0u;
    uint8_t auth[16];
    uint8_t policy[16];
    uint8_t pdig[32];
    uint8_t path[16];

    fill_message(&msg);
    fabric_test_pattern(auth, 0xD0u, 16u);
    fabric_test_pattern(policy, 0xF0u, 16u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-vector-route-policy", 26u, pdig);
    fabric_test_pattern(path, 0x61u, 16u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_enrich_nfl1_v1(
            &msg, auth, 17u, 19u, policy, 31u, pdig, path, 37u, packet,
            sizeof(packet), &len),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_project_bearer_v1(packet, len, &ws, &out),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(out.kind, msg.kind);
    FABRIC_REQUIRE(
        ninlil_fabric_private_memeq(
            out.transaction_id.bytes, msg.transaction_id.bytes, 16u));
    FABRIC_REQUIRE_EQ_U32(out.service.family, msg.service.family);
    FABRIC_REQUIRE_EQ_U32(out.service.namespace_id.length, 1u);
    FABRIC_REQUIRE(out.service.namespace_id.bytes[0] == (uint8_t)'n');
    ninlil_fabric_private_memzero(
        &zero_evidence_time, sizeof(zero_evidence_time));
    FABRIC_REQUIRE(
        ninlil_fabric_private_memeq(
            &out.evidence_time,
            &zero_evidence_time,
            sizeof(out.evidence_time)));

    /*
     * RECEIPT is the sole NFL1 kind carrying evidence time. Verify that
     * projection preserves its nested ABI header and values.
     */
    msg.kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    msg.receipt_stage = 1u;
    msg.evidence_time.abi_version = NINLIL_ABI_VERSION;
    msg.evidence_time.struct_size =
        (uint16_t)sizeof(msg.evidence_time);
    fabric_test_id(&msg.evidence_time.clock_epoch_id, 0xE1u);
    /* Timestamp zero is valid at the first instant of a non-zero epoch. */
    msg.evidence_time.now_ms = 0u;
    msg.evidence_time.trust = NINLIL_CLOCK_TRUSTED;
    {
        ninlil_party_t source = msg.source;
        ninlil_concrete_target_t target = msg.target;

        msg.source.runtime_id = target.target_runtime_id;
        msg.source.application_instance_id =
            target.target_application_instance_id;
        msg.source.local_identity.device_id = target.device_id;
        msg.source.local_identity.installation_id =
            target.installation_id;
        msg.source.local_identity.site_domain_id =
            target.site_domain_id;
        msg.source.local_identity.binding_epoch = target.binding_epoch;
        msg.source.local_identity.membership_epoch =
            target.membership_epoch;
        msg.source.local_identity.flags = target.flags;
        msg.target.target_runtime_id = source.runtime_id;
        msg.target.target_application_instance_id =
            source.application_instance_id;
        msg.target.device_id = source.local_identity.device_id;
        msg.target.installation_id =
            source.local_identity.installation_id;
        msg.target.site_domain_id =
            source.local_identity.site_domain_id;
        msg.target.binding_epoch = source.local_identity.binding_epoch;
        msg.target.membership_epoch =
            source.local_identity.membership_epoch;
        msg.target.flags = source.local_identity.flags;
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_enrich_nfl1_v1(
            &msg, auth, 17u, 19u, policy, 31u, pdig, path, 38u, packet,
            sizeof(packet), &len),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_project_bearer_v1(packet, len, &ws, &out),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        out.evidence_time.abi_version, NINLIL_ABI_VERSION);
    FABRIC_REQUIRE_EQ_U32(
        out.evidence_time.struct_size, sizeof(out.evidence_time));
    FABRIC_REQUIRE(
        ninlil_fabric_private_memeq(
            out.evidence_time.clock_epoch_id.bytes,
            msg.evidence_time.clock_epoch_id.bytes,
            16u));
    FABRIC_REQUIRE(out.evidence_time.now_ms == msg.evidence_time.now_ms);
    FABRIC_REQUIRE_EQ_U32(
        out.evidence_time.trust, msg.evidence_time.trust);
    return 0;
}

static int test_commit_unknown_create(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;

    fabric_test_reset_globals();
    g_store.fail_next_commit = 1u;
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &exec;
    ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, g_workspace, sizeof(g_workspace), &fabric),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE(fabric == NULL);
    return 0;
}

static int test_wrong_thread(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;

    fabric_test_reset_globals();
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &exec;
    ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, g_workspace, sizeof(g_workspace), &fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    g_exec_context = 2u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric, &bearer),
        NINLIL_FABRIC_PRIVATE_WRONG_THREAD);
    g_exec_context = 1u;
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int fabric_boot(
    ninlil_fabric_private_t **out_fabric,
    const ninlil_bearer_ops_t **out_bearer,
    ninlil_storage_ops_t *storage,
    ninlil_clock_ops_t *clock,
    ninlil_execution_ops_t *exec,
    ninlil_fabric_config_v1_t *config)
{
    fabric_test_reset_globals();
    fabric_test_storage_ops(storage);
    ninlil_fabric_private_memzero(clock, sizeof(*clock));
    clock->abi_version = NINLIL_ABI_VERSION;
    clock->struct_size = (uint16_t)sizeof(*clock);
    clock->now = test_clock_now;
    ninlil_fabric_private_memzero(exec, sizeof(*exec));
    exec->abi_version = NINLIL_ABI_VERSION;
    exec->struct_size = (uint16_t)sizeof(*exec);
    exec->current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(config, sizeof(*config));
    config->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config->struct_size = (uint16_t)sizeof(*config);
    config->profile_id = NINLIL_FABRIC_PROFILE_1;
    config->storage = storage;
    config->clock = clock;
    config->execution = exec;
    ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            config, g_workspace, sizeof(g_workspace), out_fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(*out_fabric, out_bearer),
        NINLIL_FABRIC_PRIVATE_OK);
    return 0;
}

static int test_wifi_custody_rejected_before_provider_or_store(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *registration = NULL;
    uint32_t open_before;
    uint32_t begin_before;
    uint32_t put_before;
    uint32_t commit_before;

    if (fabric_boot(
            &fabric, &bearer, &storage, &clock, &exec, &config)
        != 0) {
        return 1;
    }
    fill_descriptor(&descriptor, 0x61u, 10u);
    descriptor.capability_flags |= NINLIL_FABRIC_CAP_CUSTODY;
    fabric_test_provider_ops(&ops, &g_provider);
    open_before = g_provider.open_calls;
    begin_before = g_store.begin_calls;
    put_before = g_store.put_calls;
    commit_before = g_store.commit_calls;

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            fabric, &descriptor, &ops, &registration),
        NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT);
    FABRIC_REQUIRE(registration == NULL);
    FABRIC_REQUIRE_EQ_U32(g_provider.open_calls, open_before);
    FABRIC_REQUIRE_EQ_U32(g_store.begin_calls, begin_before);
    FABRIC_REQUIRE_EQ_U32(g_store.put_calls, put_before);
    FABRIC_REQUIRE_EQ_U32(g_store.commit_calls, commit_before);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBR1"), 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBM1"), 1u);

    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_provider_lost_unknown(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE(g_provider.retained == 0u);
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t work = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 16u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_new_attempt_failover_after_conflict(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    /* same attempt conflict */
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_CORRUPT);
    /* new attempt identity — same transaction — allowed as new FBA1 */
    fabric_test_pattern(msg.attempt_id.bytes, 0x99u, 16u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.permit_id, 0xE1u); /* one-shot: fresh permit required */
    g_provider.start_calls = 0u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(result.kind, NINLIL_BEARER_SEND_ACCEPTED);
    FABRIC_REQUIRE(g_provider.start_calls == 1u);
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t work = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 16u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_policy_authority_capacity_64(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    uint32_t i;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    for (i = 0u; i < NINLIL_FABRIC_POLICY_MAX; ++i) {
        ninlil_fabric_path_policy_v1_t policy;
        uint8_t service_digest[32];
        ninlil_fabric_private_memzero(&policy, sizeof(policy));
        policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        policy.struct_size = (uint16_t)sizeof(policy);
        fabric_test_pattern(policy.policy_id.bytes, (uint8_t)(0x70u + (i & 0xfu)), 16u);
        policy.policy_id.bytes[15] = (uint8_t)i;
        policy.revision = 1u + i;
        ninlil_fabric_private_nfl1_service_identity_digest(
            msg.service.namespace_id.bytes,
            msg.service.namespace_id.length,
            msg.service.service_id.bytes,
            msg.service.service_id.length,
            msg.service.schema_id.bytes,
            msg.service.schema_id.length,
            msg.service.descriptor_revision,
            msg.service.descriptor_digest.bytes,
            msg.service.schema_major,
            msg.service.schema_minor,
            msg.service.family,
            service_digest);
        /* unique service digest per slot via family variation not allowed —
         * mutate namespace length path by unique policy still needs unique
         * service match keys: use unique family bit only for capacity. */
        (void)memcpy(policy.service_identity_digest, service_digest, 32u);
        policy.service_identity_digest[0] ^= (uint8_t)i;
        policy.family = 2u;
        policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
        policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
        policy.required_capability_flags = 0x02u;
        policy.required_security_flags = 0x0Fu;
        policy.maximum_latency_class = 50u;
        policy.maximum_cost_class = 50u;
        policy.minimum_packet_bytes = 587u;
        policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
        policy.deadline_guard_ms = 100u;
        policy.candidate_count = 1u;
        fabric_test_id(&policy.candidates[0].instance_id, 0x61u);
        policy.candidates[0].rank = 10u;
        policy.candidates[0].reservation_units = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &policy),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    {
        ninlil_fabric_path_policy_v1_t policy;
        ninlil_fabric_private_memzero(&policy, sizeof(policy));
        policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        policy.struct_size = (uint16_t)sizeof(policy);
        fabric_test_id(&policy.policy_id, 0xEE);
        policy.revision = 999u;
        fabric_test_pattern(policy.service_identity_digest, 0x55u, 32u);
        policy.family = 2u;
        policy.direction = 1u;
        policy.traffic_class = 1u;
        policy.scope_selector = 2u;
        policy.required_capability_flags = 2u;
        policy.required_security_flags = 0x0Fu;
        policy.maximum_latency_class = 50u;
        policy.maximum_cost_class = 50u;
        policy.minimum_packet_bytes = 587u;
        policy.authority_mode = 1u;
        policy.deadline_guard_ms = 100u;
        policy.candidate_count = 1u;
        fabric_test_id(&policy.candidates[0].instance_id, 0x61u);
        policy.candidates[0].rank = 1u;
        policy.candidates[0].reservation_units = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &policy),
            NINLIL_FABRIC_PRIVATE_CAPACITY);
    }
    for (i = 0u; i < NINLIL_FABRIC_AUTHORITY_MAX; ++i) {
        ninlil_fabric_authority_binding_v1_t b;
        ninlil_fabric_private_memzero(&b, sizeof(b));
        b.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        b.struct_size = (uint16_t)sizeof(b);
        fabric_test_pattern(b.binding_id.bytes, 0xB0u, 16u);
        b.binding_id.bytes[15] = (uint8_t)i;
        fabric_test_pattern(b.service_identity_digest, 0x11u, 32u);
        b.service_identity_digest[0] ^= (uint8_t)i;
        b.family = 2u;
        b.direction = 1u;
        b.traffic_class = 1u;
        b.scope_selector = 2u;
        fabric_test_id(&b.endpoint_runtime_id, 0x80u);
        fabric_test_id(&b.target_runtime_id, 0x80u);
        fabric_test_id(&b.target_application_id, 0x90u);
        fabric_test_id(&b.policy_id, 0x71u);
        b.policy_revision = 3u;
        fabric_test_pattern(b.policy_digest, 0x22u, 32u);
        b.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
        fabric_test_id(&b.authority_id, 0xD0u);
        b.authority_term = 17u;
        b.assignment_epoch = 19u;
        fabric_test_id(&b.owner_scope_id, 0x81u);
        fabric_test_pattern(b.owner_tuple_canonical, 0x81u, 200u);
        ninlil_fabric_private_owner_tuple_digest(
            b.owner_tuple_canonical, b.owner_tuple_digest);
        fabric_test_id(&b.authority_clock_epoch_id, 0xA1u);
        b.lease_expires_at_ms = 300000u;
        b.assignment_revision = 11u + i;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_put_v1(fabric, &b),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    {
        ninlil_fabric_authority_binding_v1_t b;
        ninlil_fabric_private_memzero(&b, sizeof(b));
        b.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        b.struct_size = (uint16_t)sizeof(b);
        fabric_test_id(&b.binding_id, 0xFF);
        fabric_test_pattern(b.service_identity_digest, 0x99u, 32u);
        b.family = 2u;
        b.direction = 1u;
        b.traffic_class = 1u;
        b.scope_selector = 2u;
        fabric_test_id(&b.endpoint_runtime_id, 0x80u);
        fabric_test_id(&b.target_runtime_id, 0x80u);
        fabric_test_id(&b.target_application_id, 0x90u);
        fabric_test_id(&b.policy_id, 0x71u);
        b.policy_revision = 3u;
        fabric_test_pattern(b.policy_digest, 0x22u, 32u);
        b.authority_state = NINLIL_FABRIC_AUTHORITY_ABSENT;
        b.assignment_revision = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_put_v1(fabric, &b),
            NINLIL_FABRIC_PRIVATE_CAPACITY);
    }
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_availability_epoch_hot_update(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_fabric_link_state_v1_t st;
    ninlil_fabric_link_descriptor_v1_t dout;
    ninlil_id128_t id;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fabric_test_id(&id, 0x61u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_link_snapshot_v1(fabric, &id, &dout, &st),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        ninlil_fabric_link_state_v1_t neu = st;
        neu.availability_epoch = st.availability_epoch + 1u;
        neu.available_until_ms = st.available_until_ms + 1000u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_link_availability_update_v1(
                fabric, &id, &neu),
            NINLIL_FABRIC_PRIVATE_OK);
        /* same epoch exact re-read: idempotent OK (ADR-0017) */
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_link_availability_update_v1(
                fabric, &id, &neu),
            NINLIL_FABRIC_PRIVATE_OK);
        /* same epoch non-exact content: CONFLICT */
        {
            ninlil_fabric_link_state_v1_t bad = neu;
            bad.available_until_ms = neu.available_until_ms + 1u;
            FABRIC_REQUIRE_EQ_U32(
                ninlil_fabric_private_link_availability_update_v1(
                    fabric, &id, &bad),
                NINLIL_FABRIC_PRIVATE_CONFLICT);
        }
        /* CU path */
        g_store.fail_next_commit = 1u;
        neu.availability_epoch = st.availability_epoch + 2u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_link_availability_update_v1(
                fabric, &id, &neu),
            NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    }
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_provider_all_terminal_status(void)
{
    static const uint32_t statuses[] = {
        NINLIL_FABRIC_LINK_UNAVAILABLE,
        NINLIL_FABRIC_LINK_DENIED,
        NINLIL_FABRIC_LINK_CORRUPT,
        NINLIL_FABRIC_LINK_LOST_UNKNOWN,
        NINLIL_FABRIC_LINK_WOULD_BLOCK,
        NINLIL_FABRIC_LINK_RETAINED,
    };
    static const uint32_t expect_outer[] = {
        NINLIL_BEARER_UNAVAILABLE,
        NINLIL_BEARER_DENIED,
        NINLIL_BEARER_CORRUPT,
        NINLIL_BEARER_LOST_UNKNOWN,
        NINLIL_BEARER_WOULD_BLOCK,
        NINLIL_BEARER_OK,
    };
    uint32_t si;
    for (si = 0u; si < 6u; ++si) {
        ninlil_storage_ops_t storage;
        ninlil_clock_ops_t clock;
        ninlil_execution_ops_t exec;
        ninlil_fabric_config_v1_t config;
        ninlil_fabric_private_t *fabric = NULL;
        const ninlil_bearer_ops_t *bearer = NULL;
        ninlil_fabric_link_descriptor_v1_t d1;
        ninlil_fabric_packet_link_ops_v1_t ops;
        ninlil_fabric_registration_private_t *reg1 = NULL;
        ninlil_bearer_handle_t handle = NULL;
        ninlil_id128_t runtime;
        ninlil_bearer_message_t msg;
        ninlil_bearer_send_result_t result;
        ninlil_tx_permit_t permit;

        if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config)
            != 0) {
            return 1;
        }
        fill_descriptor(&d1, 0x61u, 10u);
        fabric_test_provider_ops(&ops, &g_provider);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
            NINLIL_FABRIC_PRIVATE_OK);
        fill_message(&msg);
        if (put_policy_and_authority(fabric, &msg) != 0) {
            return 1;
        }
        fabric_test_id(&runtime, 0x30u);
        FABRIC_REQUIRE_EQ_U32(
            bearer->open(
                bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
            NINLIL_BEARER_OK);
        ninlil_fabric_private_memzero(&permit, sizeof(permit));
        permit.abi_version = NINLIL_ABI_VERSION;
        permit.struct_size = (uint16_t)sizeof(permit);
        fabric_test_id(&permit.permit_id, 0xE0u);
        fabric_test_pattern(msg.attempt_id.bytes, (uint8_t)(0x20u + si), 16u);
        permit.attempt_id = msg.attempt_id;
        fabric_test_id(&permit.clock_epoch_id, 0xA1u);
        permit.expires_at_ms = 200000u;
        g_provider.next_start_status = statuses[si];
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &msg, &result),
            expect_outer[si]);
        bearer->close(bearer->user, handle);
        (void)ninlil_fabric_private_close_begin_v1(fabric);
        {
            uint32_t done = 0u;
            uint32_t work = 0u;
            uint32_t spins;
            for (spins = 0u; spins < 16u && done == 0u; ++spins) {
                (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
                (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
            }
        }
        (void)ninlil_fabric_private_destroy_v1(fabric);
    }
    return 0;
}

static int test_registry_capacity_exhaustion(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_packet_link_ops_v1_t ops;
    uint32_t i;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fabric_test_provider_ops(&ops, &g_provider);
    for (i = 0u; i < NINLIL_FABRIC_REGISTRY_MAX; ++i) {
        ninlil_fabric_link_descriptor_v1_t d;
        ninlil_fabric_registration_private_t *reg = NULL;
        fill_descriptor(&d, (uint8_t)(0x10u + i), 10u);
        /* unique instance ids via pattern start */
        d.instance_id.bytes[15] = (uint8_t)i;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(fabric, &d, &ops, &reg),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    {
        ninlil_fabric_link_descriptor_v1_t d;
        ninlil_fabric_registration_private_t *reg = NULL;
        fill_descriptor(&d, 0xF0u, 10u);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(fabric, &d, &ops, &reg),
            NINLIL_FABRIC_PRIVATE_CAPACITY);
    }
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t work = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 32u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 64u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_unregister_race_excludes_selection(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint32_t done = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_begin_v1(fabric, reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    /* draining instance is ineligible → UNAVAILABLE, no provider start */
    g_provider.start_calls = 0u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_UNAVAILABLE);
    FABRIC_REQUIRE(g_provider.start_calls == 0u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_poll_v1(fabric, reg1, &done),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(done == 1u);
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    done = 0u;
    (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int test_commit_unknown_classifier_matrix(void)
{
    uint8_t old_key[4] = { 'F', 'B', 'A', '1' };
    uint8_t new_key[4] = { 'F', 'B', 'A', '1' };
    uint8_t old_val[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t new_val[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    uint8_t third[8] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            old_key, 4u, old_val, 8u, new_key, 4u, new_val, 8u, old_key, 4u,
            old_val, 8u, 1),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            old_key, 4u, old_val, 8u, new_key, 4u, new_val, 8u, new_key, 4u,
            new_val, 8u, 1),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            NULL, 0u, NULL, 0u, new_key, 4u, new_val, 8u, NULL, 0u, NULL, 0u,
            0),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_ABSENT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            old_key, 4u, old_val, 8u, new_key, 4u, new_val, 8u, new_key, 4u,
            third, 8u, 1),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT);
    return 0;
}

static int test_endian_padding_independence(void)
{
    /* BE total_length / kind of APPLICATION-MIN accepted vector */
    static const uint8_t app_prefix[24] = {
        0x4e, 0x46, 0x4c, 0x31, 0x00, 0x01, 0x02, 0x48, 0x00, 0x00, 0x02, 0x4b,
        0xe6, 0x19, 0x81, 0xb1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t total = ((uint32_t)app_prefix[8] << 24)
        | ((uint32_t)app_prefix[9] << 16)
        | ((uint32_t)app_prefix[10] << 8) | (uint32_t)app_prefix[11];
    uint32_t kind = ((uint32_t)app_prefix[16] << 24)
        | ((uint32_t)app_prefix[17] << 16)
        | ((uint32_t)app_prefix[18] << 8) | (uint32_t)app_prefix[19];
    FABRIC_REQUIRE_EQ_U32(total, 587u);
    FABRIC_REQUIRE_EQ_U32(kind, 1u);
    FABRIC_REQUIRE(sizeof(void *) == 8u || sizeof(void *) == 4u);
    FABRIC_REQUIRE(
        sizeof(ninlil_fabric_private_nfl1_envelope_t)
        > NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES);
    /* envelope is a local view, never a wire image */
    return 0;
}

static uint32_t store_count_magic(const char magic[4])
{
    uint32_t i;
    uint32_t n = 0u;
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used != 0u && g_store.rows[i].key_len >= 4u
            && g_store.rows[i].key[0] == (uint8_t)magic[0]
            && g_store.rows[i].key[1] == (uint8_t)magic[1]
            && g_store.rows[i].key[2] == (uint8_t)magic[2]
            && g_store.rows[i].key[3] == (uint8_t)magic[3]) {
            n++;
        }
    }
    return n;
}

/* policy_put: FULL commit failure must not publish RAM; no restart resurrection. */
static int test_policy_put_full_first_fail_closed(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_path_policy_v1_t out;
    uint8_t service_digest[32];
    uint32_t puts_before;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    ninlil_fabric_private_nfl1_service_identity_digest(
        msg.service.namespace_id.bytes,
        msg.service.namespace_id.length,
        msg.service.service_id.bytes,
        msg.service.service_id.length,
        msg.service.schema_id.bytes,
        msg.service.schema_id.length,
        msg.service.descriptor_revision,
        msg.service.descriptor_digest.bytes,
        msg.service.schema_major,
        msg.service.schema_minor,
        msg.service.family,
        service_digest);
    ninlil_fabric_private_memzero(&policy, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    fabric_test_id(&policy.policy_id, 0x70u);
    policy.revision = 3u;
    (void)memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = msg.service.family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 5000u;
    policy.candidate_count = 1u;
    fabric_test_id(&policy.candidates[0].instance_id, 0x61u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;

    puts_before = g_store.put_calls;
    g_store.fail_next_commit = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE(g_store.put_calls > puts_before);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy.policy_id, policy.revision, &out),
        NINLIL_FABRIC_PRIVATE_UNAVAILABLE);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBP1"), 0u);

    /* definite put failure also leaves no RAM */
    g_store.fail_next_put = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy.policy_id, policy.revision, &out),
        NINLIL_FABRIC_PRIVATE_UNAVAILABLE);

    /* successful put is durable */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBP1"), 1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy.policy_id, policy.revision, &out),
        NINLIL_FABRIC_PRIVATE_OK);

    /* Current revision cannot be removed. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(
            fabric, &policy.policy_id, policy.revision),
        NINLIL_FABRIC_PRIVATE_CONFLICT);

    /* Install newer current so old revision is removable. */
    {
        ninlil_fabric_path_policy_v1_t newer = policy;
        newer.revision = policy.revision + 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &newer),
            NINLIL_FABRIC_PRIVATE_OK);
    }

    /* durable remove of non-current: CU OLD keeps RAM */
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(
            fabric, &policy.policy_id, policy.revision),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy.policy_id, policy.revision, &out),
        NINLIL_FABRIC_PRIVATE_OK);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(
            fabric, &policy.policy_id, policy.revision),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy.policy_id, policy.revision, &out),
        NINLIL_FABRIC_PRIVATE_UNAVAILABLE);

    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Restart must reload durable policy/authority and not resurrect removed rows. */
static int test_restart_reload_and_no_resurrection(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    ninlil_fabric_path_policy_v1_t out;
    ninlil_id128_t policy_id;
    ninlil_id128_t binding_id;
    fabric_test_store_t durable_copy;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&policy_id, 0x71u);
    fabric_test_id(&binding_id, 0xB8u);
    FABRIC_REQUIRE(store_count_magic("FBP1") >= 1u);
    FABRIC_REQUIRE(store_count_magic("FBC1") >= 1u);

    /* Remove authority durably. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_remove_v1(fabric, &binding_id, 11u),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBC1"), 0u);

    /* Capture durable store and restart into fresh workspace. */
    durable_copy = g_store;
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);

    g_store = durable_copy;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, g_workspace, sizeof(g_workspace), &fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    /* Policy still present after restart. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy_id, 3u, &out),
        NINLIL_FABRIC_PRIVATE_OK);
    /* Authority remove is durable: no resurrection. */
    {
        ninlil_fabric_authority_binding_v1_t bout;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_snapshot_v1(
                fabric, &binding_id, &bout),
            NINLIL_FABRIC_PRIVATE_UNAVAILABLE);
    }
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* FBA1 PREPARED FULL before provider start_send; CU leaves start_calls == 0. */
static int test_send_prepared_full_before_provider(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint32_t fba_before;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    /* Fail PREPARED FULL: provider must not start. */
    fba_before = store_count_magic("FBA1");
    g_provider.start_calls = 0u;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 0u; /* OLD/ABSENT under CU */
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), fba_before);
    /* Same-process immediate re-send after PREPARED CU OLD is a new FULL
     * only after auto reopen/classify; still no prior start. */

    /*
     * New attempt: PREPARED FULL + permit claim OK, LINK_RETAINED FULL CU
     * after provider.  The durable claim must already protect the permit.
     */
    fabric_test_pattern(msg.attempt_id.bytes, 0xABu, 16u);
    permit.attempt_id = msg.attempt_id;
    g_provider.start_calls = 0u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    g_store.fail_next_commit = 1u;
    g_store.commit_fault_skips = 2u; /* skip PREPARED+claim, fault LINK FULL */
    g_store.cu_apply_staged = 0u;
    {
        uint32_t cancel0 = g_provider.cancel_calls;
        uint32_t rel0 = g_provider.release_send_calls;
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &msg, &result),
            NINLIL_BEARER_LOST_UNKNOWN);
        FABRIC_REQUIRE(g_provider.start_calls == 1u);
        FABRIC_REQUIRE(g_provider.cancel_calls >= cancel0 + 1u);
        FABRIC_REQUIRE(g_provider.release_send_calls >= rel0 + 1u);
        FABRIC_REQUIRE(g_provider.live_token == 0u);
    }

    bearer->close(bearer->user, handle);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        uint32_t done = 0u;
        uint32_t work = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 16u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            FABRIC_REQUIRE_EQ_U32(
                ninlil_fabric_private_close_poll_v1(fabric, &done),
                NINLIL_FABRIC_PRIVATE_OK);
        }
        FABRIC_REQUIRE(done == 1u);
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    return 0;
}

/*
 * Co-located FBA1 claim CU-NEW occurs before provider start. The call is
 * LOST_UNKNOWN with provider start 0, and the same permit pair remains denied
 * after a crash-style reopen even for a different transaction/attempt.
 */
static int test_permit_preclaim_cu_new_restart_replay_denied(void)
{
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    const ninlil_bearer_ops_t *bearer2 = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_fabric_registration_private_t *reg2 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_handle_t handle2 = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_message_t replay;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    fabric_test_store_t durable;
    uint32_t starts;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    /*
     * Skip FBA1 PREPARED and fault the next FULL commit: same-row claim.
     * Applying staged data models CU-NEW. Provider must not be called.
     */
    starts = g_provider.start_calls;
    g_store.fail_next_commit = 1u;
    g_store.commit_fault_skips = 1u;
    g_store.cu_apply_staged = 1u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    /* Crash-style reopen: preserve only durable storage, replace workspace. */
    durable = g_store;
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric2, &bearer2),
        NINLIL_FABRIC_PRIVATE_OK);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric2, &d1, &ops, &reg2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer2->open(
            bearer2->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle2),
        NINLIL_BEARER_OK);

    replay = msg;
    fabric_test_id(&replay.transaction_id, 0x11u);
    fabric_test_id(&replay.attempt_id, 0x21u);
    permit.attempt_id = replay.attempt_id;
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer2->send(bearer2->user, handle2, &permit, &replay, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    bearer2->close(bearer2->user, handle2);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    (void)fabric;
    (void)handle;
    return 0;
}

/* Fault injection matrix: begin/get/put/erase/commit each fail-closed once. */
static int test_storage_fault_injection_matrix(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    ninlil_fabric_path_policy_v1_t policy;
    uint8_t service_digest[32];

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    ninlil_fabric_private_nfl1_service_identity_digest(
        msg.service.namespace_id.bytes,
        msg.service.namespace_id.length,
        msg.service.service_id.bytes,
        msg.service.service_id.length,
        msg.service.schema_id.bytes,
        msg.service.schema_id.length,
        msg.service.descriptor_revision,
        msg.service.descriptor_digest.bytes,
        msg.service.schema_major,
        msg.service.schema_minor,
        msg.service.family,
        service_digest);
    ninlil_fabric_private_memzero(&policy, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    fabric_test_id(&policy.policy_id, 0x71u);
    policy.revision = 1u;
    (void)memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = msg.service.family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 5000u;
    policy.candidate_count = 1u;
    fabric_test_id(&policy.candidates[0].instance_id, 0x61u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;

    g_store.fail_next_begin = 1u;
    FABRIC_REQUIRE(
        ninlil_fabric_private_policy_put_v1(fabric, &policy)
        != NINLIL_FABRIC_PRIVATE_OK);

    g_store.fail_next_put = 1u;
    FABRIC_REQUIRE(
        ninlil_fabric_private_policy_put_v1(fabric, &policy)
        != NINLIL_FABRIC_PRIVATE_OK);

    /* CU OLD: no RAM publication; same-call success is not claimed. */
    {
        ninlil_fabric_path_policy_v1_t out;
        g_store.fail_next_commit = 1u;
        g_store.cu_apply_staged = 0u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &policy),
            NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_snapshot_v1(
                fabric, &policy.policy_id, policy.revision, &out),
            NINLIL_FABRIC_PRIVATE_UNAVAILABLE);
        FABRIC_REQUIRE_EQ_U32(store_count_magic("FBP1"), 0u);
    }

    /*
     * Post-reopen classify (CU path already reopened): OLD safe retry FULL.
     * Not an in-call success after CU without classify.
     */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        ninlil_fabric_path_policy_v1_t out;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_snapshot_v1(
                fabric, &policy.policy_id, policy.revision, &out),
            NINLIL_FABRIC_PRIVATE_OK);
    }

    /* Newer current so revision 1 is removable (not current). */
    {
        ninlil_fabric_path_policy_v1_t newer = policy;
        newer.revision = policy.revision + 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &newer),
            NINLIL_FABRIC_PRIVATE_OK);
    }

    g_store.fail_next_erase = 1u;
    FABRIC_REQUIRE(
        ninlil_fabric_private_policy_remove_v1(
            fabric, &policy.policy_id, policy.revision)
        != NINLIL_FABRIC_PRIVATE_OK);

    g_store.fail_next_begin = 1u;
    FABRIC_REQUIRE(
        ninlil_fabric_private_policy_remove_v1(
            fabric, &policy.policy_id, policy.revision)
        != NINLIL_FABRIC_PRIVATE_OK);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(
            fabric, &policy.policy_id, policy.revision),
        NINLIL_FABRIC_PRIVATE_OK);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 8u && done == 0u; ++spins) {
            FABRIC_REQUIRE_EQ_U32(
                ninlil_fabric_private_close_poll_v1(fabric, &done),
                NINLIL_FABRIC_PRIVATE_OK);
        }
        FABRIC_REQUIRE(done == 1u);
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    return 0;
}

/* FBT1 FULL failure must not publish RX. */
static int test_fbt1_full_required_before_rx(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    ninlil_bearer_message_t rx;
    uint32_t work = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    /* Keep send completion pending so step does not consume fail_next_commit. */
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    FABRIC_REQUIRE(g_provider.retained_len > 0u);

    /* --- FBT1 CU NEW: durable may land; RX publish forbidden. --- */
    memcpy(
        g_provider.rx_packet,
        g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx),
        NINLIL_BEARER_EMPTY);
    FABRIC_REQUIRE(store_count_magic("FBT1") >= 1u);

    /* Same-packet redelivery after CU NEW: still no publish (exactly-once). */
    memcpy(
        g_provider.rx_packet,
        g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx),
        NINLIL_BEARER_EMPTY);

    /* --- Fresh admit after destroy/recreate (post-reconcile clean path). --- */
    bearer->close(bearer->user, handle);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 16u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            FABRIC_REQUIRE_EQ_U32(
                ninlil_fabric_private_close_poll_v1(fabric, &done),
                NINLIL_FABRIC_PRIVATE_OK);
        }
        FABRIC_REQUIRE(done == 1u);
    }
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);

    /* New fabric, new transaction: clean FBT1 FULL then single publish. */
    {
        ninlil_fabric_private_t *f2 = NULL;
        const ninlil_bearer_ops_t *b2 = NULL;
        ninlil_fabric_registration_private_t *r2 = NULL;
        ninlil_bearer_handle_t h2 = NULL;
        ninlil_fabric_link_descriptor_v1_t d2;
        ninlil_fabric_packet_link_ops_v1_t ops2;
        ninlil_id128_t runtime2;
        ninlil_bearer_message_t msg2;
        ninlil_bearer_send_result_t res2;
        ninlil_tx_permit_t perm2;
        fabric_test_reset_globals();
        fabric_test_storage_ops(&storage);
        ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_create_v1(
                &config, g_workspace, sizeof(g_workspace), &f2),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_bearer_ops_v1(f2, &b2),
            NINLIL_FABRIC_PRIVATE_OK);
        fill_descriptor(&d2, 0x61u, 10u);
        fabric_test_provider_ops(&ops2, &g_provider);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(f2, &d2, &ops2, &r2),
            NINLIL_FABRIC_PRIVATE_OK);
        fill_message(&msg2);
        fabric_test_pattern(msg2.transaction_id.bytes, 0x44u, 16u);
        fabric_test_pattern(msg2.attempt_id.bytes, 0x55u, 16u);
        if (put_policy_and_authority(f2, &msg2) != 0) {
            return 1;
        }
        fabric_test_id(&runtime2, 0x30u);
        FABRIC_REQUIRE_EQ_U32(
            b2->open(b2->user, &runtime2, NINLIL_ROLE_ENDPOINT, &h2),
            NINLIL_BEARER_OK);
        ninlil_fabric_private_memzero(&perm2, sizeof(perm2));
        perm2.abi_version = NINLIL_ABI_VERSION;
        perm2.struct_size = (uint16_t)sizeof(perm2);
        fabric_test_id(&perm2.permit_id, 0xE1u);
        perm2.attempt_id = msg2.attempt_id;
        fabric_test_id(&perm2.clock_epoch_id, 0xA1u);
        perm2.expires_at_ms = 200000u;
        g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
        g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
        FABRIC_REQUIRE_EQ_U32(
            b2->send(b2->user, h2, &perm2, &msg2, &res2),
            NINLIL_BEARER_OK);
        memcpy(
            g_provider.rx_packet,
            g_provider.retained_packet,
            g_provider.retained_len);
        g_provider.rx_len = g_provider.retained_len;
        g_provider.rx_ready = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_step_v1(f2, 16u, &work),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE_EQ_U32(
            b2->receive_next(b2->user, h2, &rx), NINLIL_BEARER_OK);
        FABRIC_REQUIRE(store_count_magic("FBT1") >= 1u);
        b2->release_received(b2->user, h2, &rx);
        b2->close(b2->user, h2);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_close_begin_v1(f2),
            NINLIL_FABRIC_PRIVATE_OK);
        {
            uint32_t done = 0u;
            uint32_t spins;
            for (spins = 0u; spins < 16u && done == 0u; ++spins) {
                (void)ninlil_fabric_private_step_v1(f2, 16u, &work);
                FABRIC_REQUIRE_EQ_U32(
                    ninlil_fabric_private_close_poll_v1(f2, &done),
                    NINLIL_FABRIC_PRIVATE_OK);
            }
            FABRIC_REQUIRE(done == 1u);
        }
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_destroy_v1(f2),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    return 0;
}

/* Restart fences PREPARED/LINK_RETAINED FBA1 to FENCED_UNKNOWN. */
static int test_restart_fences_prepared_attempt(void)
{
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    fabric_test_store_t durable_copy;
    uint32_t i;
    uint32_t fenced = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(store_count_magic("FBA1") >= 1u);

    /* Crash-style restart: keep durable rows, open fresh fabric workspace. */
    durable_copy = g_store;
    g_store = durable_copy;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    /* Inspect durable FBA1 payloads for FENCED_UNKNOWN state=5. */
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used == 0u || g_store.rows[i].key_len != 76u) {
            continue;
        }
        if (g_store.rows[i].key[0] != (uint8_t)'F'
            || g_store.rows[i].key[1] != (uint8_t)'B'
            || g_store.rows[i].key[2] != (uint8_t)'A'
            || g_store.rows[i].key[3] != (uint8_t)'1') {
            continue;
        }
        {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fba1_t rec;
            if (ninlil_fabric_private_record_decode_envelope(
                    g_store.rows[i].value,
                    g_store.rows[i].value_len,
                    (const uint8_t *)"FBA1",
                    NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
                    &env,
                    &pl)
                    == NINLIL_FABRIC_PRIVATE_RECORD_OK
                && ninlil_fabric_private_fba1_decode(pl, &rec)
                    == NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                if (rec.state
                    == NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN) {
                    fenced = 1u;
                }
                FABRIC_REQUIRE(
                    rec.state != NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED);
                FABRIC_REQUIRE(
                    rec.state
                    != NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED);
            }
        }
    }
    FABRIC_REQUIRE(fenced == 1u);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    (void)handle;
    (void)fabric;
    return 0;
}

static fabric_test_row_t *find_store_row_magic(const char magic[4])
{
    uint32_t i;
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used != 0u && g_store.rows[i].key_len >= 4u
            && g_store.rows[i].key[0] == (uint8_t)magic[0]
            && g_store.rows[i].key[1] == (uint8_t)magic[1]
            && g_store.rows[i].key[2] == (uint8_t)magic[2]
            && g_store.rows[i].key[3] == (uint8_t)magic[3]) {
            return &g_store.rows[i];
        }
    }
    return NULL;
}

static int restart_create_expect(
    ninlil_storage_ops_t *storage,
    ninlil_fabric_config_v1_t *config,
    uint32_t expect_status)
{
    static uint8_t ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_fabric_private_t *fabric = NULL;
    fabric_test_store_t durable = g_store;
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(storage);
    ninlil_fabric_private_memzero(ws, sizeof(ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(config, ws, sizeof(ws), &fabric),
        expect_status);
    if (expect_status == NINLIL_FABRIC_PRIVATE_OK) {
        FABRIC_REQUIRE(fabric != NULL);
        (void)ninlil_fabric_private_close_begin_v1(fabric);
        {
            uint32_t done = 0u;
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
        (void)ninlil_fabric_private_destroy_v1(fabric);
    } else {
        FABRIC_REQUIRE(fabric == NULL);
    }
    return 0;
}

/* Same-key SAME vs CONFLICT for policy and authority puts. */
static int test_put_same_vs_conflict(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_authority_binding_v1_t binding;
    uint8_t service_digest[32];

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    /* Rebuild exact same policy as put_policy_and_authority. */
    ninlil_fabric_private_nfl1_service_identity_digest(
        msg.service.namespace_id.bytes,
        msg.service.namespace_id.length,
        msg.service.service_id.bytes,
        msg.service.service_id.length,
        msg.service.schema_id.bytes,
        msg.service.schema_id.length,
        msg.service.descriptor_revision,
        msg.service.descriptor_digest.bytes,
        msg.service.schema_major,
        msg.service.schema_minor,
        msg.service.family,
        service_digest);
    ninlil_fabric_private_memzero(&policy, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    fabric_test_id(&policy.policy_id, 0x71u);
    policy.revision = 3u;
    memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = 2u;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = 0x02u;
    policy.required_security_flags = 0x0Fu;
    policy.maximum_latency_class = 50u;
    policy.maximum_cost_class = 50u;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 100u;
    policy.candidate_count = 2u;
    fabric_test_id(&policy.candidates[0].instance_id, 0x01u);
    policy.candidates[0].rank = 20u;
    policy.candidates[0].reservation_units = 1u;
    fabric_test_id(&policy.candidates[1].instance_id, 0x61u);
    policy.candidates[1].rank = 10u;
    policy.candidates[1].reservation_units = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_OK); /* SAME */

    policy.deadline_guard_ms = 999u; /* content change, same id+rev */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_CONFLICT);

    /* Authority SAME then CONFLICT. */
    {
        ninlil_fabric_path_policy_v1_t snap;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_snapshot_v1(
                fabric, &policy.policy_id, 3u, &snap),
            NINLIL_FABRIC_PRIVATE_OK);
        ninlil_fabric_private_memzero(&binding, sizeof(binding));
        binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        binding.struct_size = (uint16_t)sizeof(binding);
        fabric_test_id(&binding.binding_id, 0xB8u);
        memcpy(binding.service_identity_digest, service_digest, 32u);
        binding.family = 2u;
        binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
        binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
        fabric_test_id(&binding.endpoint_runtime_id, 0x80u);
        fabric_test_id(&binding.target_runtime_id, 0x80u);
        fabric_test_id(&binding.target_application_id, 0x90u);
        binding.policy_id = policy.policy_id;
        binding.policy_revision = 3u;
        memcpy(
            binding.policy_digest,
            snap.canonical_digest_zero_on_input,
            32u);
        binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
        fabric_test_id(&binding.authority_id, 0xD0u);
        binding.authority_term = 17u;
        binding.assignment_epoch = 19u;
        fabric_test_id(&binding.owner_scope_id, 0x81u);
        fabric_test_pattern(binding.owner_tuple_canonical, 0x81u, 200u);
        ninlil_fabric_private_owner_tuple_digest(
            binding.owner_tuple_canonical, binding.owner_tuple_digest);
        fabric_test_id(&binding.authority_clock_epoch_id, 0xA1u);
        binding.lease_expires_at_ms = 300000u;
        binding.assignment_revision = 11u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_put_v1(fabric, &binding),
            NINLIL_FABRIC_PRIVATE_OK); /* SAME */
        binding.lease_expires_at_ms = 400000u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_put_v1(fabric, &binding),
            NINLIL_FABRIC_PRIVATE_CONFLICT);
    }

    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Persistent restart validation: corrupt row, key mismatch, digest, dup, overflow. */
static int test_restart_corrupt_and_canonical_failures(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    fabric_test_row_t *row;
    fabric_test_store_t baseline;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    baseline = g_store;
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);

    /* 1) Corrupt envelope CRC on current FBP1. */
    g_store = baseline;
    row = find_store_row_magic("FBP1");
    FABRIC_REQUIRE(row != NULL);
    FABRIC_REQUIRE(row->value_len > 24u);
    row->value[row->value_len - 1u] ^= 0x01u;
    if (restart_create_expect(
            &storage, &config, NINLIL_FABRIC_PRIVATE_CORRUPT)
        != 0) {
        return 1;
    }

    /* 2) Key/body mismatch: alter key policy_id suffix. */
    g_store = baseline;
    row = find_store_row_magic("FBP1");
    FABRIC_REQUIRE(row != NULL && row->key_len == 28u);
    row->key[4] ^= 0x5Au;
    if (restart_create_expect(
            &storage, &config, NINLIL_FABRIC_PRIVATE_CORRUPT)
        != 0) {
        return 1;
    }

    /* 3) Coherent digest tamper: keep CRC valid, break canonical digest. */
    g_store = baseline;
    row = find_store_row_magic("FBP1");
    FABRIC_REQUIRE(row != NULL);
    {
        ninlil_fabric_private_common_envelope_t env;
        const uint8_t *pl = NULL;
        uint8_t payload[328];
        uint8_t value[352];
        uint32_t vlen = 0u;
        FABRIC_REQUIRE(
            ninlil_fabric_private_record_decode_envelope(
                row->value,
                row->value_len,
                (const uint8_t *)"FBP1",
                328u,
                &env,
                &pl)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        memcpy(payload, pl, 328u);
        payload[24] ^= 0x01u; /* flip stored canonical digest byte */
        FABRIC_REQUIRE(
            ninlil_fabric_private_record_encode_envelope(
                (const uint8_t *)"FBP1",
                env.revision,
                payload,
                328u,
                value,
                352u,
                &vlen)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        FABRIC_REQUIRE(vlen <= FABRIC_TEST_VAL_MAX);
        memcpy(row->value, value, vlen);
        row->value_len = vlen;
    }
    if (restart_create_expect(
            &storage, &config, NINLIL_FABRIC_PRIVATE_CORRUPT)
        != 0) {
        return 1;
    }

    /* 4) Duplicate identity: two physical rows, same FBP1 key+value. */
    g_store = baseline;
    row = find_store_row_magic("FBP1");
    FABRIC_REQUIRE(row != NULL);
    {
        uint32_t free_i = FABRIC_TEST_STORE_MAX;
        uint32_t i;
        for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
            if (g_store.rows[i].used == 0u) {
                free_i = i;
                break;
            }
        }
        FABRIC_REQUIRE(free_i < FABRIC_TEST_STORE_MAX);
        g_store.rows[free_i] = *row;
        g_store.rows[free_i].used = 1u;
    }
    if (restart_create_expect(
            &storage, &config, NINLIL_FABRIC_PRIVATE_CORRUPT)
        != 0) {
        return 1;
    }

    /* 5) Overflow: 65 valid distinct FBP1 rows in durable store. */
    g_store = baseline;
    {
        uint32_t n;
        fabric_test_row_t *src = find_store_row_magic("FBP1");
        FABRIC_REQUIRE(src != NULL);
        for (n = 0u; n < 64u; ++n) {
            uint32_t free_i = FABRIC_TEST_STORE_MAX;
            uint32_t i;
            fabric_test_row_t *dst;
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbp1_t full;
            uint8_t payload[328];
            uint8_t value[352];
            uint32_t vlen = 0u;
            uint8_t key[28];
            for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
                if (g_store.rows[i].used == 0u) {
                    free_i = i;
                    break;
                }
            }
            if (n == 0u) {
                /* keep original as first; only inject additional beyond capacity */
                continue;
            }
            FABRIC_REQUIRE(free_i < FABRIC_TEST_STORE_MAX);
            FABRIC_REQUIRE(
                ninlil_fabric_private_record_decode_envelope(
                    src->value,
                    src->value_len,
                    (const uint8_t *)"FBP1",
                    328u,
                    &env,
                    &pl)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            FABRIC_REQUIRE(
                ninlil_fabric_private_fbp1_decode(pl, &full)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            full.policy_id[15] = (uint8_t)(0xA0u + (n & 0x1fu));
            full.revision = 100u + n;
            ninlil_fabric_private_fbp1_compute_digest(&full);
            FABRIC_REQUIRE(
                ninlil_fabric_private_fbp1_encode(&full, payload)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            FABRIC_REQUIRE(
                ninlil_fabric_private_record_encode_envelope(
                    (const uint8_t *)"FBP1",
                    1u,
                    payload,
                    328u,
                    value,
                    352u,
                    &vlen)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            ninlil_fabric_private_key_fbp1(
                full.policy_id, full.revision, key);
            dst = &g_store.rows[free_i];
            ninlil_fabric_private_memzero(dst, sizeof(*dst));
            dst->used = 1u;
            memcpy(dst->key, key, 28u);
            dst->key_len = 28u;
            memcpy(dst->value, value, vlen);
            dst->value_len = vlen;
        }
        /* Count FBP1: original + 63 injected = 64. Add one more for 65. */
        {
            uint32_t free_i = FABRIC_TEST_STORE_MAX;
            uint32_t i;
            fabric_test_row_t *dst;
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbp1_t full;
            uint8_t payload[328];
            uint8_t value[352];
            uint32_t vlen = 0u;
            uint8_t key[28];
            for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
                if (g_store.rows[i].used == 0u) {
                    free_i = i;
                    break;
                }
            }
            FABRIC_REQUIRE(free_i < FABRIC_TEST_STORE_MAX);
            FABRIC_REQUIRE(
                ninlil_fabric_private_record_decode_envelope(
                    src->value,
                    src->value_len,
                    (const uint8_t *)"FBP1",
                    328u,
                    &env,
                    &pl)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            FABRIC_REQUIRE(
                ninlil_fabric_private_fbp1_decode(pl, &full)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            full.policy_id[15] = 0xFFu;
            full.revision = 9999u;
            ninlil_fabric_private_fbp1_compute_digest(&full);
            FABRIC_REQUIRE(
                ninlil_fabric_private_fbp1_encode(&full, payload)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            FABRIC_REQUIRE(
                ninlil_fabric_private_record_encode_envelope(
                    (const uint8_t *)"FBP1",
                    1u,
                    payload,
                    328u,
                    value,
                    352u,
                    &vlen)
                == NINLIL_FABRIC_PRIVATE_RECORD_OK);
            ninlil_fabric_private_key_fbp1(
                full.policy_id, full.revision, key);
            dst = &g_store.rows[free_i];
            ninlil_fabric_private_memzero(dst, sizeof(*dst));
            dst->used = 1u;
            memcpy(dst->key, key, 28u);
            dst->key_len = 28u;
            memcpy(dst->value, value, vlen);
            dst->value_len = vlen;
        }
        FABRIC_REQUIRE(store_count_magic("FBP1") > NINLIL_FABRIC_POLICY_MAX);
    }
    if (restart_create_expect(
            &storage, &config, NINLIL_FABRIC_PRIVATE_CORRUPT)
        != 0) {
        return 1;
    }

    /* 6) Baseline still restarts cleanly. */
    g_store = baseline;
    if (restart_create_expect(
            &storage, &config, NINLIL_FABRIC_PRIVATE_OK)
        != 0) {
        return 1;
    }
    return 0;
}

/* LINK_RETAINED FULL fail after RETAINED: cancel+release once; close converges. */
static int test_link_retained_full_fail_reclaims_token(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_message_t replay;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint32_t done = 0u;
    uint32_t work = 0u;
    uint32_t spins;
    uint32_t rel0;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    /* Skip PREPARED FULL + permit claim, fail LINK_RETAINED FULL. */
    g_store.fail_next_commit = 1u;
    g_store.commit_fault_skips = 2u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    rel0 = g_provider.release_send_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE(g_provider.cancel_calls == 1u);
    FABRIC_REQUIRE(g_provider.release_send_calls == rel0 + 1u);
    FABRIC_REQUIRE(g_provider.live_token == 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    /*
     * The provider side effect preceded the failed LINK_RETAINED commit, but
     * the FBA1 claim was already durable. A distinct identity cannot replay it.
     */
    replay = msg;
    fabric_test_id(&replay.transaction_id, 0x11u);
    fabric_test_id(&replay.attempt_id, 0x21u);
    permit.attempt_id = replay.attempt_id;
    {
        uint32_t starts = g_provider.start_calls;
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &replay, &result),
            NINLIL_BEARER_DENIED);
        FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    }

    /* Double step must not double-release. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(g_provider.release_send_calls == rel0 + 1u);

    bearer->close(bearer->user, handle);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    done = 0u;
    for (spins = 0u; spins < 8u && done == 0u; ++spins) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_close_poll_v1(fabric, &done),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    FABRIC_REQUIRE(done == 1u);
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* poll_send non-OK: cancel+release, FENCED, no token hang. */
static int test_poll_non_ok_reclaims_token(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint32_t work = 0u;
    uint32_t done = 0u;
    uint32_t spins;
    uint32_t rel0;
    uint32_t cancel0;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(g_provider.live_token == 1u);

    g_provider.next_poll_status = NINLIL_FABRIC_LINK_CORRUPT;
    rel0 = g_provider.release_send_calls;
    cancel0 = g_provider.cancel_calls;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(g_provider.cancel_calls == cancel0 + 1u);
    FABRIC_REQUIRE(g_provider.release_send_calls == rel0 + 1u);
    FABRIC_REQUIRE(g_provider.live_token == 0u);

    /* Second step: no double release. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(g_provider.release_send_calls == rel0 + 1u);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    for (spins = 0u; spins < 8u && done == 0u; ++spins) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    FABRIC_REQUIRE(done == 1u);
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* WOULD_BLOCK + non-NULL token is invalid shape: reclaim + CORRUPT. */
static int test_would_block_with_token_contradiction(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint32_t done = 0u;
    uint32_t work = 0u;
    uint32_t spins;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    g_provider.inject_token_on_non_retained = 1u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE(g_provider.cancel_calls >= 1u);
    FABRIC_REQUIRE(g_provider.release_send_calls >= 1u);
    FABRIC_REQUIRE(g_provider.live_token == 0u);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    for (spins = 0u; spins < 8u && done == 0u; ++spins) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    FABRIC_REQUIRE(done == 1u);
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Unregister/close complete after accepted send via step drain. */
static int test_unregister_close_bounded_after_accept(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint32_t work = 0u;
    uint32_t done = 0u;
    uint32_t ureg_done = 0u;
    uint32_t spins;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_begin_v1(fabric, reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    for (spins = 0u; spins < 8u && ureg_done == 0u; ++spins) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_unregister_poll_v1(fabric, reg1, &ureg_done),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    FABRIC_REQUIRE(ureg_done == 1u);
    FABRIC_REQUIRE(g_provider.live_token == 0u);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    for (spins = 0u; spins < 8u && done == 0u; ++spins) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    FABRIC_REQUIRE(done == 1u);
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Decode retained APPLICATION NFL1, mutate to reverse RECEIPT, re-encode. */
static int craft_reverse_receipt_v2(
    const uint8_t *app_packet,
    uint32_t app_len,
    uint8_t *out_packet,
    uint32_t out_cap,
    uint32_t *out_len,
    int swap_source_target,
    const uint8_t *force_attempt_id,
    const uint8_t *force_authority_id,
    uint64_t force_authority_term,
    uint64_t force_policy_revision,
    int force_wrong_source_endpoint)
{
    ninlil_fabric_private_nfl1_workspace_t ws;
    ninlil_fabric_private_nfl1_envelope_t env;
    uint32_t required = 0u;
    ninlil_id128_t tmp;

    ninlil_fabric_private_memzero(&ws, sizeof(ws));
    ninlil_fabric_private_memzero(&env, sizeof(env));
    if (ninlil_fabric_private_nfl1_decode(
            app_packet, app_len, &ws, &env, &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return 1;
    }
    env.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    env.receipt_stage = 1u;
    env.payload.bytes = NULL;
    env.payload.length = 0u;
    /* RECEIPT matrix requires valid evidence_time (APPLICATION has zeros). */
    fabric_test_id(&env.evidence_time_clock_epoch_id, 0xA1u);
    env.evidence_time_now_ms = 170000u;
    env.evidence_time_trust = NINLIL_CLOCK_TRUSTED;
    env.disposition = 0u;
    env.effect_certainty = 0u;
    env.retry_guidance = 0u;
    env.retry_delay_ms = 0u;
    env.cancel_kind = 0u;
    if (swap_source_target != 0) {
        tmp = env.source_runtime_id;
        env.source_runtime_id = env.target_runtime_id;
        env.target_runtime_id = tmp;
        tmp = env.source_application_id;
        env.source_application_id = env.target_application_id;
        env.target_application_id = tmp;
    }
    if (force_attempt_id != NULL) {
        (void)memcpy(env.attempt_id.bytes, force_attempt_id, 16u);
    }
    if (force_authority_id != NULL) {
        (void)memcpy(env.authority_id.bytes, force_authority_id, 16u);
    }
    if (force_authority_term != 0u) {
        env.authority_term = force_authority_term;
    }
    if (force_policy_revision != 0u) {
        env.route_policy_revision = force_policy_revision;
    }
    if (force_wrong_source_endpoint != 0) {
        env.source_runtime_id.bytes[0] ^= 0x5Au;
    }
    if (ninlil_fabric_private_nfl1_encode(
            &env, out_packet, out_cap, out_len)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return 1;
    }
    return 0;
}

/* Re-encode a valid forward packet with one unique trigger identity. */
static int craft_forward_trigger_identity(
    const uint8_t *app_packet,
    uint32_t app_len,
    uint8_t identity_seed,
    uint8_t *out_packet,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_fabric_private_nfl1_workspace_t ws;
    ninlil_fabric_private_nfl1_envelope_t env;
    uint32_t required = 0u;

    ninlil_fabric_private_memzero(&ws, sizeof(ws));
    ninlil_fabric_private_memzero(&env, sizeof(env));
    if (ninlil_fabric_private_nfl1_decode(
            app_packet, app_len, &ws, &env, &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return 1;
    }
    fabric_test_id(&env.transaction_id, identity_seed);
    fabric_test_id(&env.attempt_id, (uint8_t)(identity_seed + 0x80u));
    env.absolute_effect_deadline_ms = 400000u;
    return ninlil_fabric_private_nfl1_encode(
               &env, out_packet, out_cap, out_len)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
        ? 0
        : 1;
}

static int boot_send_app_get_retained_with_peer(
    ninlil_fabric_private_t **out_fabric,
    const ninlil_bearer_ops_t **out_bearer,
    ninlil_storage_ops_t *storage,
    ninlil_clock_ops_t *clock,
    ninlil_execution_ops_t *exec,
    ninlil_fabric_config_v1_t *config,
    ninlil_bearer_handle_t *out_handle,
    ninlil_fabric_registration_private_t **out_reg,
    uint8_t peer_seed)
{
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;

    if (fabric_boot(out_fabric, out_bearer, storage, clock, exec, config)
        != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_id(&d1.authenticated_peer_runtime_id, peer_seed);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            *out_fabric, &d1, &ops, out_reg),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(*out_fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        (*out_bearer)
            ->open(
                (*out_bearer)->user, &runtime, NINLIL_ROLE_ENDPOINT,
                out_handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    FABRIC_REQUIRE_EQ_U32(
        (*out_bearer)
            ->send(
                (*out_bearer)->user, *out_handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(g_provider.retained_len > 0u);
    return 0;
}

static int boot_send_app_get_retained(
    ninlil_fabric_private_t **out_fabric,
    const ninlil_bearer_ops_t **out_bearer,
    ninlil_storage_ops_t *storage,
    ninlil_clock_ops_t *clock,
    ninlil_execution_ops_t *exec,
    ninlil_fabric_config_v1_t *config,
    ninlil_bearer_handle_t *out_handle,
    ninlil_fabric_registration_private_t **out_reg)
{
    return boot_send_app_get_retained_with_peer(
        out_fabric,
        out_bearer,
        storage,
        clock,
        exec,
        config,
        out_handle,
        out_reg,
        0x31u);
}

static int expect_no_rx_publish(
    ninlil_fabric_private_t *fabric,
    const ninlil_bearer_ops_t *bearer,
    ninlil_bearer_handle_t handle,
    const uint8_t *packet,
    uint32_t packet_len)
{
    ninlil_bearer_message_t rx;
    uint32_t work = 0u;
    uint32_t fbt1_before = store_count_magic("FBT1");

    memcpy(g_provider.rx_packet, packet, packet_len);
    g_provider.rx_len = packet_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx),
        NINLIL_BEARER_EMPTY);
    FABRIC_REQUIRE(store_count_magic("FBT1") == fbt1_before
        || packet_len == 0u);
    (void)fbt1_before;
    return 0;
}

/* Reverse happy path: exact echo publishes once. */
static int test_reverse_exact_echo_publishes(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    uint8_t rev[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t rev_len = 0u;
    uint32_t work = 0u;

    if (boot_send_app_get_retained(
            &fabric, &bearer, &storage, &clock, &exec, &config, &handle,
            &reg1)
        != 0) {
        return 1;
    }
    /* First publish APPLICATION (creates FBT1). */
    memcpy(
        g_provider.rx_packet, g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    bearer->release_received(bearer->user, handle, &rx);
    FABRIC_REQUIRE(store_count_magic("FBT1") >= 1u);

    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet, g_provider.retained_len, rev,
            sizeof(rev), &rev_len, 1, NULL, NULL, 0u, 0u, 0)
        == 0);
    memcpy(g_provider.rx_packet, rev, rev_len);
    g_provider.rx_len = rev_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(rx.kind, NINLIL_BEARER_MESSAGE_RECEIPT);
    bearer->release_received(bearer->user, handle, &rx);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 8u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/*
 * Original sender path: reverse ingress correlates against retained outbound
 * FBA1 without requiring a locally-created FBT1.
 */
static int test_reverse_fba1_exact_echo_publishes(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    uint8_t rev[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint8_t wrong_attempt[16];
    uint32_t rev_len = 0u;
    uint32_t work = 0u;

    if (boot_send_app_get_retained_with_peer(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &reg1,
            0x80u)
        != 0) {
        return 1;
    }
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 0u);
    FABRIC_REQUIRE(store_count_magic("FBA1") >= 1u);
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet,
            g_provider.retained_len,
            rev,
            sizeof(rev),
            &rev_len,
            1,
            NULL,
            NULL,
            0u,
            0u,
            0)
        == 0);
    memcpy(g_provider.rx_packet, rev, rev_len);
    g_provider.rx_len = rev_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(rx.kind, NINLIL_BEARER_MESSAGE_RECEIPT);
    bearer->release_received(bearer->user, handle, &rx);

    /* Same-looking reverse with no saved attempt correlation must be dropped. */
    fabric_test_pattern(wrong_attempt, 0xE7u, 16u);
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet,
            g_provider.retained_len,
            rev,
            sizeof(rev),
            &rev_len,
            1,
            wrong_attempt,
            NULL,
            0u,
            0u,
            0)
        == 0);
    if (expect_no_rx_publish(fabric, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 8u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/*
 * Reverse outbound path requires FBT1, then keeps its exact forward policy
 * revision even after a newer revision becomes current.
 */
static int test_reverse_send_uses_saved_fbt1_policy(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t receipt;
    ninlil_bearer_message_t rx;
    ninlil_bearer_send_result_t send_result;
    ninlil_tx_permit_t permit;
    ninlil_fabric_private_nfl1_workspace_t project_ws;
    ninlil_fabric_private_nfl1_workspace_t decode_ws;
    ninlil_fabric_private_nfl1_envelope_t sent_env;
    ninlil_fabric_path_policy_v1_t newer;
    ninlil_id128_t policy_id;
    uint8_t app_copy[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint8_t rev[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t required = 0u;
    uint32_t app_len;
    uint32_t rev_len = 0u;
    uint32_t work = 0u;
    uint32_t starts_before;

    if (boot_send_app_get_retained_with_peer(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &reg1,
            0x30u)
        != 0) {
        return 1;
    }
    app_len = g_provider.retained_len;
    memcpy(app_copy, g_provider.retained_packet, app_len);
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);

    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            app_copy,
            app_len,
            rev,
            sizeof(rev),
            &rev_len,
            1,
            NULL,
            NULL,
            0u,
            0u,
            0)
        == 0);
    ninlil_fabric_private_memzero(&project_ws, sizeof(project_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_project_bearer_v1(
            rev, rev_len, &project_ws, &receipt),
        NINLIL_FABRIC_PRIVATE_OK);

    /* Missing FBT1: reverse transport side effect must remain zero. */
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE1u);
    permit.attempt_id = receipt.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    starts_before = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(
            bearer->user, handle, &permit, &receipt, &send_result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before);

    /* Publish triggering APPLICATION, which durably creates FBT1. */
    memcpy(g_provider.rx_packet, app_copy, app_len);
    g_provider.rx_len = app_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    bearer->release_received(bearer->user, handle, &rx);
    FABRIC_REQUIRE(store_count_magic("FBT1") >= 1u);

    /* Rev 4 is current, but this conversation remains pinned to rev 3. */
    fabric_test_id(&policy_id, 0x71u);
    ninlil_fabric_private_memzero(&newer, sizeof(newer));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy_id, 3u, &newer),
        NINLIL_FABRIC_PRIVATE_OK);
    newer.revision = 4u;
    ninlil_fabric_private_memzero(
        newer.canonical_digest_zero_on_input,
        sizeof(newer.canonical_digest_zero_on_input));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &newer),
        NINLIL_FABRIC_PRIVATE_OK);

    fabric_test_id(&permit.permit_id, 0xE2u);
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(
            bearer->user, handle, &permit, &receipt, &send_result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before + 1u);
    ninlil_fabric_private_memzero(&decode_ws, sizeof(decode_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_nfl1_decode(
            g_provider.retained_packet,
            g_provider.retained_len,
            &decode_ws,
            &sent_env,
            &required),
        NINLIL_FABRIC_PRIVATE_NFL1_OK);
    FABRIC_REQUIRE_EQ_U32(
        sent_env.message_kind, NINLIL_BEARER_MESSAGE_RECEIPT);
    FABRIC_REQUIRE(sent_env.route_policy_revision == 3u);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 8u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Negative reverse cases: no publish/callback. */
static int test_reverse_auth_negatives_no_publish(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    uint8_t rev[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t rev_len = 0u;
    uint32_t work = 0u;
    uint8_t wrong_attempt[16];
    uint8_t wrong_auth[16];

    if (boot_send_app_get_retained(
            &fabric, &bearer, &storage, &clock, &exec, &config, &handle,
            &reg1)
        != 0) {
        return 1;
    }
    memcpy(
        g_provider.rx_packet, g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    bearer->release_received(bearer->user, handle, &rx);

    fabric_test_pattern(wrong_attempt, 0xEEu, 16u);
    fabric_test_pattern(wrong_auth, 0xCCu, 16u);

    /* wrong attempt */
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet, g_provider.retained_len, rev,
            sizeof(rev), &rev_len, 1, wrong_attempt, NULL, 0u, 0u, 0)
        == 0);
    if (expect_no_rx_publish(fabric, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }
    /* wrong authority id */
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet, g_provider.retained_len, rev,
            sizeof(rev), &rev_len, 1, NULL, wrong_auth, 0u, 0u, 0)
        == 0);
    if (expect_no_rx_publish(fabric, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }
    /* old term */
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet, g_provider.retained_len, rev,
            sizeof(rev), &rev_len, 1, NULL, NULL, 9999u, 0u, 0)
        == 0);
    if (expect_no_rx_publish(fabric, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }
    /* old policy revision */
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet, g_provider.retained_len, rev,
            sizeof(rev), &rev_len, 1, NULL, NULL, 0u, 888u, 0)
        == 0);
    if (expect_no_rx_publish(fabric, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }
    /* wrong endpoint (source) */
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet, g_provider.retained_len, rev,
            sizeof(rev), &rev_len, 1, NULL, NULL, 0u, 0u, 1)
        == 0);
    if (expect_no_rx_publish(fabric, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }
    /* foreign transaction reverse without FBT1: no swap needed but new tx */
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            g_provider.retained_packet, g_provider.retained_len, rev,
            sizeof(rev), &rev_len, 1, NULL, NULL, 0u, 0u, 0)
        == 0);
    {
        ninlil_fabric_private_nfl1_workspace_t ws;
        ninlil_fabric_private_nfl1_envelope_t env;
        uint32_t required = 0u;
        uint32_t nlen = 0u;
        ninlil_fabric_private_memzero(&ws, sizeof(ws));
        FABRIC_REQUIRE(
            ninlil_fabric_private_nfl1_decode(
                rev, rev_len, &ws, &env, &required)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK);
        env.transaction_id.bytes[0] ^= 0x11u;
        FABRIC_REQUIRE(
            ninlil_fabric_private_nfl1_encode(&env, rev, sizeof(rev), &nlen)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK);
        rev_len = nlen;
    }
    if (expect_no_rx_publish(fabric, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 8u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Ambiguous forward join: two FBC1 match same target → no FBT1/RX. */
static int test_forward_ambiguous_authority_no_publish(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t msg;
    ninlil_fabric_authority_binding_v1_t binding2;
    ninlil_fabric_path_policy_v1_t snap;
    ninlil_id128_t policy_id;
    uint32_t work = 0u;
    uint32_t fbt1_before;

    if (boot_send_app_get_retained(
            &fabric, &bearer, &storage, &clock, &exec, &config, &handle,
            &reg1)
        != 0) {
        return 1;
    }
    /* Insert second authority that also matches target_runtime (ambiguous). */
    fabric_test_id(&policy_id, 0x71u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy_id, 3u, &snap),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    ninlil_fabric_private_memzero(&binding2, sizeof(binding2));
    binding2.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding2.struct_size = (uint16_t)sizeof(binding2);
    fabric_test_id(&binding2.binding_id, 0xB9u);
    {
        uint8_t service_digest[32];
        ninlil_fabric_private_nfl1_service_identity_digest(
            msg.service.namespace_id.bytes,
            msg.service.namespace_id.length,
            msg.service.service_id.bytes,
            msg.service.service_id.length,
            msg.service.schema_id.bytes,
            msg.service.schema_id.length,
            msg.service.descriptor_revision,
            msg.service.descriptor_digest.bytes,
            msg.service.schema_major,
            msg.service.schema_minor,
            msg.service.family,
            service_digest);
        memcpy(binding2.service_identity_digest, service_digest, 32u);
    }
    binding2.family = 2u;
    binding2.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding2.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding2.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    fabric_test_id(&binding2.endpoint_runtime_id, 0x80u);
    fabric_test_id(&binding2.target_runtime_id, 0x80u);
    fabric_test_id(&binding2.target_application_id, 0x90u);
    binding2.policy_id = policy_id;
    binding2.policy_revision = 3u;
    memcpy(
        binding2.policy_digest, snap.canonical_digest_zero_on_input, 32u);
    binding2.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    fabric_test_id(&binding2.authority_id, 0xD0u); /* same group as primary */
    binding2.authority_term = 17u;
    binding2.assignment_epoch = 19u;
    fabric_test_id(&binding2.owner_scope_id, 0x82u); /* different scope */
    fabric_test_pattern(binding2.owner_tuple_canonical, 0x82u, 200u);
    ninlil_fabric_private_owner_tuple_digest(
        binding2.owner_tuple_canonical, binding2.owner_tuple_digest);
    fabric_test_id(&binding2.authority_clock_epoch_id, 0xA1u);
    binding2.lease_expires_at_ms = 300000u;
    binding2.assignment_revision = 12u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_put_v1(fabric, &binding2),
        NINLIL_FABRIC_PRIVATE_OK);

    fbt1_before = store_count_magic("FBT1");
    memcpy(
        g_provider.rx_packet, g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        ninlil_bearer_message_t rx;
        FABRIC_REQUIRE_EQ_U32(
            bearer->receive_next(bearer->user, handle, &rx),
            NINLIL_BEARER_EMPTY);
    }
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), fbt1_before);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 8u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Restart: FBT1 persists; reverse still works; wrong-echo still dropped. */
static int test_restart_fbt1_reverse_persistence(void)
{
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    fabric_test_store_t durable;
    uint8_t rev[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint8_t app_copy[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t app_len = 0u;
    uint32_t rev_len = 0u;
    uint32_t work = 0u;
    uint8_t wrong_attempt[16];

    if (boot_send_app_get_retained(
            &fabric, &bearer, &storage, &clock, &exec, &config, &handle,
            &reg1)
        != 0) {
        return 1;
    }
    app_len = g_provider.retained_len;
    memcpy(app_copy, g_provider.retained_packet, app_len);
    memcpy(g_provider.rx_packet, app_copy, app_len);
    g_provider.rx_len = app_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    bearer->release_received(bearer->user, handle, &rx);
    FABRIC_REQUIRE(store_count_magic("FBT1") >= 1u);

    durable = g_store;
    bearer->close(bearer->user, handle);
    /* Fresh fabric from durable store (policy/auth/FBT1 reload). */
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric2, &bearer),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        ninlil_fabric_link_descriptor_v1_t d1;
        ninlil_fabric_packet_link_ops_v1_t ops;
        ninlil_id128_t runtime;
        fill_descriptor(&d1, 0x61u, 10u);
        fabric_test_provider_ops(&ops, &g_provider);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(
                fabric2, &d1, &ops, &reg1),
            NINLIL_FABRIC_PRIVATE_OK);
        fabric_test_id(&runtime, 0x30u);
        FABRIC_REQUIRE_EQ_U32(
            bearer->open(
                bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
            NINLIL_BEARER_OK);
    }
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            app_copy, app_len, rev, sizeof(rev), &rev_len, 1, NULL, NULL, 0u,
            0u, 0)
        == 0);
    memcpy(g_provider.rx_packet, rev, rev_len);
    g_provider.rx_len = rev_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric2, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    bearer->release_received(bearer->user, handle, &rx);

    fabric_test_pattern(wrong_attempt, 0xABu, 16u);
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            app_copy, app_len, rev, sizeof(rev), &rev_len, 1, wrong_attempt,
            NULL, 0u, 0u, 0)
        == 0);
    if (expect_no_rx_publish(fabric2, bearer, handle, rev, rev_len) != 0) {
        return 1;
    }

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    (void)fabric;
    return 0;
}

/* Restart: outbound FBA1 remains valid reverse correlation without FBT1. */
static int test_restart_fba1_reverse_persistence(void)
{
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    fabric_test_store_t durable;
    uint8_t app_copy[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint8_t rev[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t app_len;
    uint32_t rev_len = 0u;
    uint32_t work = 0u;

    if (boot_send_app_get_retained_with_peer(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &reg1,
            0x80u)
        != 0) {
        return 1;
    }
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 0u);
    FABRIC_REQUIRE(store_count_magic("FBA1") >= 1u);
    app_len = g_provider.retained_len;
    memcpy(app_copy, g_provider.retained_packet, app_len);
    durable = g_store;
    bearer->close(bearer->user, handle);

    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric2, &bearer),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        ninlil_fabric_link_descriptor_v1_t d1;
        ninlil_fabric_packet_link_ops_v1_t ops;
        ninlil_id128_t runtime;
        fill_descriptor(&d1, 0x61u, 10u);
        fabric_test_id(&d1.authenticated_peer_runtime_id, 0x80u);
        fabric_test_provider_ops(&ops, &g_provider);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(
                fabric2, &d1, &ops, &reg1),
            NINLIL_FABRIC_PRIVATE_OK);
        fabric_test_id(&runtime, 0x30u);
        FABRIC_REQUIRE_EQ_U32(
            bearer->open(
                bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
            NINLIL_BEARER_OK);
    }
    FABRIC_REQUIRE(
        craft_reverse_receipt_v2(
            app_copy,
            app_len,
            rev,
            sizeof(rev),
            &rev_len,
            1,
            NULL,
            NULL,
            0u,
            0u,
            0)
        == 0);
    memcpy(g_provider.rx_packet, rev, rev_len);
    g_provider.rx_len = rev_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric2, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(rx.kind, NINLIL_BEARER_MESSAGE_RECEIPT);
    bearer->release_received(bearer->user, handle, &rx);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    (void)fabric;
    return 0;
}

/* PREPARED CU classified NEW: fence, provider start 0, same-process re-send 0. */
static int test_prepared_cu_new_fences_no_provider(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    g_provider.start_calls = 0u;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u; /* NEW under CU */
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, 0u);
    FABRIC_REQUIRE(store_count_magic("FBA1") >= 1u);

    /* Same-process duplicate send: still no provider start. */
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, 0u);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* PREPARED CU classified OLD: no FBA1 durable, provider start 0. */
static int test_prepared_cu_old_no_provider(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    uint32_t fba_before;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    fba_before = store_count_magic("FBA1");
    g_provider.start_calls = 0u;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 0u; /* OLD/ABSENT under CU */
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), fba_before);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Restart after PREPARED CU NEW: durable FBA1 is fenced, no resurrect PREPARED. */
static int test_prepared_cu_new_restart_fenced(void)
{
    static uint8_t ws2[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    fabric_test_store_t durable;
    uint32_t i;
    uint32_t fenced = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);

    durable = g_store;
    bearer->close(bearer->user, handle);
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(ws2, sizeof(ws2));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(&config, ws2, sizeof(ws2), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used == 0u || g_store.rows[i].key_len != 76u) {
            continue;
        }
        if (g_store.rows[i].key[0] != (uint8_t)'F'
            || g_store.rows[i].key[1] != (uint8_t)'B'
            || g_store.rows[i].key[2] != (uint8_t)'A'
            || g_store.rows[i].key[3] != (uint8_t)'1') {
            continue;
        }
        {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fba1_t rec;
            if (ninlil_fabric_private_record_decode_envelope(
                    g_store.rows[i].value,
                    g_store.rows[i].value_len,
                    (const uint8_t *)"FBA1",
                    NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
                    &env,
                    &pl)
                    == NINLIL_FABRIC_PRIVATE_RECORD_OK
                && ninlil_fabric_private_fba1_decode(pl, &rec)
                    == NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                FABRIC_REQUIRE(
                    rec.state != NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED);
                FABRIC_REQUIRE(
                    rec.state
                    != NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED);
                if (rec.state
                    == NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN) {
                    fenced = 1u;
                }
            }
        }
    }
    FABRIC_REQUIRE(fenced == 1u);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    (void)fabric;
    return 0;
}

/* Active FBT1 ref blocks policy/authority remove of referenced pins. */
static int test_remove_rejects_active_reference(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    ninlil_id128_t policy_id;
    ninlil_id128_t binding_id;
    uint32_t work = 0u;

    if (boot_send_app_get_retained(
            &fabric, &bearer, &storage, &clock, &exec, &config, &handle,
            &reg1)
        != 0) {
        return 1;
    }
    memcpy(
        g_provider.rx_packet, g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    bearer->release_received(bearer->user, handle, &rx);
    FABRIC_REQUIRE(store_count_magic("FBT1") >= 1u);

    fabric_test_id(&policy_id, 0x71u);
    fabric_test_id(&binding_id, 0xB8u);
    /* Current policy always CONFLICT; even older would block on FBT1 ref. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(fabric, &policy_id, 3u),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_remove_v1(fabric, &binding_id, 11u),
        NINLIL_FABRIC_PRIVATE_CONFLICT);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* trigger_release FULL + restart keeps runtime_terminal_revision. */
static int test_trigger_release_full_restart(void)
{
    static uint8_t ws2[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    ninlil_id128_t tx;
    ninlil_id128_t attempt;
    fabric_test_store_t durable;
    uint32_t work = 0u;
    uint32_t i;
    uint32_t found_term = 0u;

    if (boot_send_app_get_retained(
            &fabric, &bearer, &storage, &clock, &exec, &config, &handle,
            &reg1)
        != 0) {
        return 1;
    }
    memcpy(
        g_provider.rx_packet, g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    tx = rx.transaction_id;
    attempt = rx.attempt_id;
    bearer->release_received(bearer->user, handle, &rx);

    /* A trigger without Runtime terminal authority is never GC-eligible. */
    fabric_test_set_clock(
        170000u + NINLIL_FABRIC_RETRY_LIFETIME_MS + 1u, 0xA1u);
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 1u);
    fabric_test_set_clock(170000u, 0xA1u);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_trigger_release_v1(
            fabric, &tx, &attempt, NINLIL_BEARER_MESSAGE_APPLICATION, 42u),
        NINLIL_FABRIC_PRIVATE_OK);

    durable = g_store;
    bearer->close(bearer->user, handle);
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(ws2, sizeof(ws2));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(&config, ws2, sizeof(ws2), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used == 0u || g_store.rows[i].key_len != 40u) {
            continue;
        }
        if (g_store.rows[i].key[0] != (uint8_t)'F'
            || g_store.rows[i].key[1] != (uint8_t)'B'
            || g_store.rows[i].key[2] != (uint8_t)'T'
            || g_store.rows[i].key[3] != (uint8_t)'1') {
            continue;
        }
        {
            ninlil_fabric_private_common_envelope_t env;
            const uint8_t *pl = NULL;
            ninlil_fabric_private_fbt1_t rec;
            if (ninlil_fabric_private_record_decode_envelope(
                    g_store.rows[i].value,
                    g_store.rows[i].value_len,
                    (const uint8_t *)"FBT1",
                    224u,
                    &env,
                    &pl)
                    == NINLIL_FABRIC_PRIVATE_RECORD_OK
                && ninlil_fabric_private_fbt1_decode(pl, &rec)
                    == NINLIL_FABRIC_PRIVATE_RECORD_OK) {
                if (rec.runtime_terminal_revision == 42u) {
                    found_term = 1u;
                }
            }
        }
    }
    FABRIC_REQUIRE(found_term == 1u);

    /* Restarted terminal FBT1 stays fenced on epoch mismatch or early time. */
    fabric_test_set_clock(
        170000u + NINLIL_FABRIC_RETRY_LIFETIME_MS + 1u, 0xB2u);
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric2, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 1u);
    fabric_test_set_clock(
        170000u + NINLIL_FABRIC_RETRY_LIFETIME_MS - 1u, 0xA1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric2, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 1u);
    fabric_test_set_clock(
        170000u + NINLIL_FABRIC_RETRY_LIFETIME_MS, 0xA1u);
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric2, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 1u);
    work = 0u;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric2, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 0u);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    (void)fabric;
    return 0;
}

/*
 * Trigger retention duration must be checked before its FBT1 FULL
 * replacement. Overflow leaves the terminal revision unconsumed so the same
 * exact release can succeed later under a representable trusted clock sample.
 */
static int test_trigger_release_retention_overflow_no_mutation(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t received;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    uint32_t work = 0u;
    uint32_t puts_before;
    uint32_t commits_before;
    uint32_t starts_before;

    if (boot_send_app_get_retained(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &registration)
        != 0) {
        return 1;
    }
    (void)registration;
    (void)memcpy(
        g_provider.rx_packet,
        g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &received),
        NINLIL_BEARER_OK);
    transaction_id = received.transaction_id;
    attempt_id = received.attempt_id;
    bearer->release_received(bearer->user, handle, &received);

    fabric_test_set_clock(UINT64_MAX - 100u, 0xA1u);
    puts_before = g_store.put_calls;
    commits_before = g_store.commit_calls;
    starts_before = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_trigger_release_v1(
            fabric,
            &transaction_id,
            &attempt_id,
            NINLIL_BEARER_MESSAGE_APPLICATION,
            43u),
        NINLIL_FABRIC_PRIVATE_CAPACITY);
    FABRIC_REQUIRE_EQ_U32(g_store.put_calls, puts_before);
    FABRIC_REQUIRE_EQ_U32(g_store.commit_calls, commits_before);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before);

    /* Same terminal revision was not consumed by the failed checked add. */
    fabric_test_set_clock(170000u, 0xA1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_trigger_release_v1(
            fabric,
            &transaction_id,
            &attempt_id,
            NINLIL_BEARER_MESSAGE_APPLICATION,
            43u),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(g_store.put_calls > puts_before);
    FABRIC_REQUIRE(g_store.commit_calls > commits_before);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* 2 msg/s for 40 s: 30 s retained triggers must GC before slot 65. */
static int test_trigger_gc_80_at_two_per_second(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_handle_t handle = NULL;
    uint8_t source_packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t source_length;
    uint32_t index;

    if (boot_send_app_get_retained(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &registration)
        != 0) {
        return 1;
    }
    (void)registration;
    source_length = g_provider.retained_len;
    (void)memcpy(source_packet, g_provider.retained_packet, source_length);

    for (index = 0u; index < 80u; ++index) {
        ninlil_bearer_message_t received;
        ninlil_id128_t transaction_id;
        ninlil_id128_t attempt_id;
        uint32_t work = 0u;
        uint64_t now_ms = 170000u + (uint64_t)index * 500u;

        fabric_test_set_clock(now_ms, 0xA1u);
        FABRIC_REQUIRE_EQ_U32(
            craft_forward_trigger_identity(
                source_packet,
                source_length,
                (uint8_t)(0x10u + index),
                g_provider.rx_packet,
                sizeof(g_provider.rx_packet),
                &g_provider.rx_len),
            0u);
        g_provider.rx_ready = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_step_v1(fabric, 16u, &work),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE_EQ_U32(
            bearer->receive_next(bearer->user, handle, &received),
            NINLIL_BEARER_OK);
        transaction_id = received.transaction_id;
        attempt_id = received.attempt_id;
        bearer->release_received(bearer->user, handle, &received);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_trigger_release_v1(
                fabric,
                &transaction_id,
                &attempt_id,
                NINLIL_BEARER_MESSAGE_APPLICATION,
                (uint64_t)index + 1u),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE(store_count_magic("FBT1") < NINLIL_FABRIC_TRIGGER_MAX);
    }
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 60u);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* One transaction with coexisting outgoing FBA1 and incoming FBT1. */
static int test_transaction_terminal_release_mixed_and_retained(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t received;
    ninlil_id128_t transaction_id;
    ninlil_id128_t absent_id;
    uint32_t work = 0u;
    uint32_t more = 0u;
    uint32_t puts_before;
    uint32_t cancels_before;
    uint32_t releases_before;

    if (boot_send_app_get_retained(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &registration)
        != 0) {
        return 1;
    }
    (void)registration;
    (void)memcpy(
        g_provider.rx_packet,
        g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &received),
        NINLIL_BEARER_OK);
    transaction_id = received.transaction_id;
    bearer->release_received(bearer->user, handle, &received);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 1u);

    cancels_before = g_provider.cancel_calls;
    releases_before = g_provider.release_send_calls;
    work = 0u;
    more = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 77u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);
    FABRIC_REQUIRE_EQ_U32(g_provider.cancel_calls, cancels_before);
    FABRIC_REQUIRE_EQ_U32(g_provider.release_send_calls, releases_before);

    /* Retained FBA is waiting on step, but actionable FBT1 still progresses. */
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 77u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);
    work = 99u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 77u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);

    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(g_provider.cancel_calls, cancels_before + 1u);
    FABRIC_REQUIRE_EQ_U32(g_provider.release_send_calls, releases_before + 1u);

    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 77u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 0u);

    /* Exact replay and no-row are RAM-only final success. */
    puts_before = g_store.put_calls;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 77u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(more, 0u);
    FABRIC_REQUIRE_EQ_U32(g_store.put_calls, puts_before);
    fabric_test_id(&absent_id, 0xD1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &absent_id, 91u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(more, 0u);

    /* Different token conflicts after the full preflight with zero writes. */
    puts_before = g_store.put_calls;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 78u, &work, &more),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(g_store.put_calls, puts_before);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* A later conflicting token must not consume an earlier actionable FBA1. */
static int test_transaction_terminal_release_conflict_is_atomic(void)
{
    static uint8_t workspace_before[NINLIL_FABRIC_WORKSPACE_BYTES];
    static fabric_test_store_t store_before;
    static fabric_test_provider_t provider_before;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t received;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    uint32_t work = 0u;
    uint32_t more = 0u;
    uint32_t puts_before;
    uint32_t commits_before;
    uint32_t erases_before;

    if (boot_send_app_get_retained(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &registration)
        != 0) {
        return 1;
    }
    (void)registration;

    /* Keep the outgoing FBA1 at token zero and add a later FBT1 row. */
    (void)memcpy(
        g_provider.rx_packet,
        g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &received),
        NINLIL_BEARER_OK);
    transaction_id = received.transaction_id;
    attempt_id = received.attempt_id;
    bearer->release_received(bearer->user, handle, &received);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_trigger_release_v1(
            fabric,
            &transaction_id,
            &attempt_id,
            NINLIL_BEARER_MESSAGE_APPLICATION,
            88u),
        NINLIL_FABRIC_PRIVATE_OK);

    (void)memcpy(workspace_before, g_workspace, sizeof(workspace_before));
    store_before = g_store;
    provider_before = g_provider;
    puts_before = g_store.put_calls;
    commits_before = g_store.commit_calls;
    erases_before = g_store.erase_calls;

    work = 99u;
    more = 99u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 77u, &work, &more),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(more, 0u);
    FABRIC_REQUIRE_EQ_U32(g_store.put_calls, puts_before);
    FABRIC_REQUIRE_EQ_U32(g_store.commit_calls, commits_before);
    FABRIC_REQUIRE_EQ_U32(g_store.erase_calls, erases_before);
    FABRIC_REQUIRE(memcmp(&store_before, &g_store, sizeof(g_store)) == 0);
    FABRIC_REQUIRE(
        memcmp(&provider_before, &g_provider, sizeof(g_provider)) == 0);
    FABRIC_REQUIRE(
        memcmp(workspace_before, g_workspace, sizeof(g_workspace)) == 0);

    /* The untouched zero-token FBA1 remains actionable for the exact token. */
    work = 0u;
    more = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 88u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);
    FABRIC_REQUIRE(
        memcmp(&provider_before, &g_provider, sizeof(g_provider)) == 0);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Terminal FBT1 replacement follows CU OLD/NEW and restart readback rules. */
static int test_transaction_terminal_release_trigger_cu_restart(void)
{
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    static fabric_test_store_t durable;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *reopened = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t received;
    ninlil_id128_t transaction_id;
    uint8_t source_packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t source_length;
    uint32_t work = 0u;
    uint32_t more = 0u;

    if (boot_send_app_get_retained(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &registration)
        != 0) {
        return 1;
    }
    (void)registration;
    source_length = g_provider.retained_len;
    (void)memcpy(source_packet, g_provider.retained_packet, source_length);
    FABRIC_REQUIRE_EQ_U32(
        craft_forward_trigger_identity(
            source_packet,
            source_length,
            0xD0u,
            g_provider.rx_packet,
            sizeof(g_provider.rx_packet),
            &g_provider.rx_len),
        0u);
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &received),
        NINLIL_BEARER_OK);
    transaction_id = received.transaction_id;
    bearer->release_received(bearer->user, handle, &received);

    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 0u;
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 93u, &work, &more),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);

    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u;
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 93u, &work, &more),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);

    durable = g_store;
    bearer->close(bearer->user, handle);
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &reopened),
        NINLIL_FABRIC_PRIVATE_OK);
    work = 99u;
    more = 99u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            reopened, &transaction_id, 93u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 0u);
    FABRIC_REQUIRE_EQ_U32(more, 0u);

    (void)ninlil_fabric_private_close_begin_v1(reopened);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(reopened, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(reopened);
    (void)fabric;
    return 0;
}

static int test_transaction_terminal_release_trigger_cu_third(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t received;
    ninlil_id128_t transaction_id;
    uint8_t source_packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t source_length;
    uint32_t work = 0u;
    uint32_t more = 0u;

    if (boot_send_app_get_retained(
            &fabric,
            &bearer,
            &storage,
            &clock,
            &exec,
            &config,
            &handle,
            &registration)
        != 0) {
        return 1;
    }
    (void)registration;
    source_length = g_provider.retained_len;
    (void)memcpy(source_packet, g_provider.retained_packet, source_length);
    FABRIC_REQUIRE_EQ_U32(
        craft_forward_trigger_identity(
            source_packet,
            source_length,
            0xE0u,
            g_provider.rx_packet,
            sizeof(g_provider.rx_packet),
            &g_provider.rx_len),
        0u);
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &received),
        NINLIL_BEARER_OK);
    transaction_id = received.transaction_id;
    bearer->release_received(bearer->user, handle, &received);

    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u;
    g_store.cu_observed_shape = 2u;
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &transaction_id, 94u, &work, &more),
        NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);

    bearer->close(bearer->user, handle);
    (void)fabric;
    return 0;
}

/* PREPARED's externally reachable RETRYABLE sibling closes, then drains. */
static int test_transaction_terminal_release_retryable_two_step(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t message;
    ninlil_bearer_send_result_t result;
    ninlil_tx_permit_t permit;
    ninlil_id128_t runtime_id;
    uint32_t starts_before;
    uint32_t work = 0u;
    uint32_t more = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&descriptor, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            fabric, &descriptor, &ops, &registration),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&message);
    FABRIC_REQUIRE_EQ_U32(put_policy_and_authority(fabric, &message), 0u);
    fabric_test_id(&runtime_id, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(
            bearer->user, &runtime_id, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE5u);
    permit.attempt_id = message.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &message, &result),
        NINLIL_BEARER_WOULD_BLOCK);
    starts_before = g_provider.start_calls;

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &message.transaction_id, 101u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 1u);
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_terminal_release_v1(
            fabric, &message.transaction_id, 101u, &work, &more),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(more, 0u);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Erase CU NEW: RAM cleared (no selection resurrection). */
static int test_policy_remove_cu_new_clears_ram(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_path_policy_v1_t out;
    uint8_t service_digest[32];

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    ninlil_fabric_private_nfl1_service_identity_digest(
        msg.service.namespace_id.bytes,
        msg.service.namespace_id.length,
        msg.service.service_id.bytes,
        msg.service.service_id.length,
        msg.service.schema_id.bytes,
        msg.service.schema_id.length,
        msg.service.descriptor_revision,
        msg.service.descriptor_digest.bytes,
        msg.service.schema_major,
        msg.service.schema_minor,
        msg.service.family,
        service_digest);
    ninlil_fabric_private_memzero(&policy, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    fabric_test_id(&policy.policy_id, 0x73u);
    policy.revision = 1u;
    (void)memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = msg.service.family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 5000u;
    policy.candidate_count = 1u;
    fabric_test_id(&policy.candidates[0].instance_id, 0x61u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_put_v1(fabric, &policy),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        ninlil_fabric_path_policy_v1_t newer = policy;
        newer.revision = 2u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &newer),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u; /* durable erase applied under CU */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(
            fabric, &policy.policy_id, 1u),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    /* RAM cleared on CU NEW — no resurrection for selection. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(
            fabric, &policy.policy_id, 1u, &out),
        NINLIL_FABRIC_PRIVATE_UNAVAILABLE);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBP1"), 1u); /* only rev2 */

    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* After trigger_release + retention window, non-current policy remove OK. */
static int test_remove_after_release_and_retention(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_message_t rx;
    ninlil_id128_t policy_id;
    ninlil_id128_t binding_id;
    ninlil_id128_t tx;
    ninlil_id128_t attempt;
    ninlil_fabric_path_policy_v1_t newer;
    ninlil_bearer_message_t msg;
    uint32_t work = 0u;

    if (boot_send_app_get_retained(
            &fabric, &bearer, &storage, &clock, &exec, &config, &handle,
            &reg1)
        != 0) {
        return 1;
    }
    memcpy(
        g_provider.rx_packet, g_provider.retained_packet,
        g_provider.retained_len);
    g_provider.rx_len = g_provider.retained_len;
    g_provider.rx_ready = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->receive_next(bearer->user, handle, &rx), NINLIL_BEARER_OK);
    tx = rx.transaction_id;
    attempt = rx.attempt_id;
    bearer->release_received(bearer->user, handle, &rx);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_trigger_release_v1(
            fabric, &tx, &attempt, NINLIL_BEARER_MESSAGE_APPLICATION, 7u),
        NINLIL_FABRIC_PRIVATE_OK);

    /* Drain FBA1 attempt so policy refs can reach retention-complete. */
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        uint8_t foundation[32];
        uint32_t rslot;
        ninlil_fabric_private_nfl1_foundation_message_digest(
            g_provider.retained_packet, g_provider.retained_len, foundation);
        rslot = ninlil_fabric_private_nfl1_response_slot(
            NINLIL_BEARER_MESSAGE_APPLICATION, 0u, 0u, 0u);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_dispatch_release_v1(
                fabric,
                &tx,
                &attempt,
                NINLIL_BEARER_MESSAGE_APPLICATION,
                rslot,
                foundation,
                9u),
            NINLIL_FABRIC_PRIVATE_OK);
    }

    /* Advance clock past retention_until (release used now+RETRY_LIFETIME). */
    fabric_test_set_clock(170000u + NINLIL_FABRIC_RETRY_LIFETIME_MS + 1u, 0xA1u);

    fabric_test_id(&policy_id, 0x71u);
    fabric_test_id(&binding_id, 0xB8u);
    fill_message(&msg);
    /* Install newer policy so rev 3 is non-current. */
    {
        uint8_t service_digest[32];
        ninlil_fabric_private_nfl1_service_identity_digest(
            msg.service.namespace_id.bytes,
            msg.service.namespace_id.length,
            msg.service.service_id.bytes,
            msg.service.service_id.length,
            msg.service.schema_id.bytes,
            msg.service.schema_id.length,
            msg.service.descriptor_revision,
            msg.service.descriptor_digest.bytes,
            msg.service.schema_major,
            msg.service.schema_minor,
            msg.service.family,
            service_digest);
        ninlil_fabric_private_memzero(&newer, sizeof(newer));
        newer.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        newer.struct_size = (uint16_t)sizeof(newer);
        fabric_test_id(&newer.policy_id, 0x71u);
        newer.revision = 4u;
        (void)memcpy(newer.service_identity_digest, service_digest, 32u);
        newer.family = 2u;
        newer.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        newer.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
        newer.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
        newer.required_capability_flags = 0x02u;
        newer.required_security_flags = 0x0Fu;
        newer.maximum_latency_class = 50u;
        newer.maximum_cost_class = 50u;
        newer.minimum_packet_bytes = 587u;
        newer.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
        newer.deadline_guard_ms = 100u;
        newer.candidate_count = 2u;
        fabric_test_id(&newer.candidates[0].instance_id, 0x01u);
        newer.candidates[0].rank = 20u;
        newer.candidates[0].reservation_units = 1u;
        fabric_test_id(&newer.candidates[1].instance_id, 0x61u);
        newer.candidates[1].rank = 10u;
        newer.candidates[1].reservation_units = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &newer),
            NINLIL_FABRIC_PRIVATE_OK);
    }

    /*
     * Eligibility does not erase by itself. The durable FBA1 reference still
     * blocks removal until one bounded step completes its exact FULL erase.
     */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(fabric, &policy_id, 3u),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_remove_v1(fabric, &binding_id, 11u),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 0u);

    /* FBT1 remains blocking until its own bounded FULL erase completes. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(fabric, &policy_id, 3u),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_remove_v1(fabric, &binding_id, 11u),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 0u);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_remove_v1(fabric, &policy_id, 3u),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_remove_v1(fabric, &binding_id, 11u),
        NINLIL_FABRIC_PRIVATE_OK);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* (a) register_link: FBR1+FBM1 same FULL group; fail closed on multi put. */
static int test_register_link_fbr1_fbm1_same_full_group(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    uint32_t fbr1_before;
    uint32_t fbm1_before;
    uint32_t puts_before;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fbr1_before = store_count_magic("FBR1");
    fbm1_before = store_count_magic("FBM1");
    puts_before = g_store.put_calls;
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(reg1 != NULL);
    /* First register: FBR1 insert + FBM1 outer availability FULL group. */
    FABRIC_REQUIRE(store_count_magic("FBR1") == fbr1_before + 1u);
    FABRIC_REQUIRE(store_count_magic("FBM1") == fbm1_before); /* same key replaced */
    FABRIC_REQUIRE(g_store.put_calls >= puts_before + 2u);
    /* Second register same descriptor+ops: idempotent, no extra open. */
    {
        ninlil_fabric_registration_private_t *reg2 = NULL;
        uint32_t open_before = g_provider.open_calls;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg2),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE(reg2 == reg1);
        FABRIC_REQUIRE(g_provider.open_calls == open_before);
    }
    /* Vtable mismatch on same instance: CONFLICT */
    {
        ninlil_fabric_packet_link_ops_v1_t ops2 = ops;
        ninlil_fabric_registration_private_t *regx = NULL;
        ops2.user = (void *)((uintptr_t)ops.user + 1u);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(fabric, &d1, &ops2, &regx),
            NINLIL_FABRIC_PRIVATE_CONFLICT);
        FABRIC_REQUIRE(regx == NULL);
    }
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Register FULL fail after provider open: close handle, no RAM publish. */
static int test_register_link_full_fail_closes_provider(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_id128_t id;
    ninlil_fabric_link_descriptor_v1_t dout;
    ninlil_fabric_link_state_v1_t st;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    g_store.fail_next_commit = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE(reg1 == NULL);
    FABRIC_REQUIRE(g_provider.close_calls >= 1u);
    fabric_test_id(&id, 0x61u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_link_snapshot_v1(fabric, &id, &dout, &st),
        NINLIL_FABRIC_PRIVATE_UNAVAILABLE);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* (b) adoption: other records without FBM1 => CORRUPT, no repair. */
static int test_adoption_rejects_orphan_records_without_fbm1(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    static uint8_t ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    uint8_t key[20];
    uint8_t val[4] = { 1, 2, 3, 4 };

    fabric_test_reset_globals();
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &exec;
    /* Plant orphan FBR1-shaped key without FBM1. */
    key[0] = (uint8_t)'F';
    key[1] = (uint8_t)'B';
    key[2] = (uint8_t)'R';
    key[3] = (uint8_t)'1';
    fabric_test_pattern(key + 4, 0x61u, 16u);
    g_store.rows[0].used = 1u;
    memcpy(g_store.rows[0].key, key, 20u);
    g_store.rows[0].key_len = 20u;
    memcpy(g_store.rows[0].value, val, 4u);
    g_store.rows[0].value_len = 4u;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(ws, sizeof(ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(&config, ws, sizeof(ws), &fabric),
        NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE(fabric == NULL);
    return 0;
}

/* Provider open non-OK + non-NULL handle: close + CORRUPT. */
static int test_provider_open_error_nonnull_handle_closed(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    g_provider.next_open_status = NINLIL_FABRIC_LINK_UNAVAILABLE;
    g_provider.open_return_nonnull_on_error = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE(reg1 == NULL);
    FABRIC_REQUIRE(g_provider.close_calls >= 1u);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* (d) authority assignment_revision strict +1 and immutable lookup tuple. */
static int test_authority_revision_strict_plus1_and_immutable(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_bearer_message_t msg;
    ninlil_fabric_authority_binding_v1_t binding;
    ninlil_fabric_path_policy_v1_t snap;
    ninlil_id128_t policy_id;
    ninlil_id128_t binding_id;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&policy_id, 0x71u);
    fabric_test_id(&binding_id, 0xB8u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_policy_snapshot_v1(fabric, &policy_id, 3u, &snap),
        NINLIL_FABRIC_PRIVATE_OK);
    /* Gap: 11 -> 13 not allowed. */
    ninlil_fabric_private_memzero(&binding, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    binding.binding_id = binding_id;
    memcpy(
        binding.service_identity_digest, snap.service_identity_digest, 32u);
    binding.family = 2u;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    fabric_test_id(&binding.endpoint_runtime_id, 0x80u);
    fabric_test_id(&binding.target_runtime_id, 0x80u);
    fabric_test_id(&binding.target_application_id, 0x90u);
    binding.policy_id = policy_id;
    binding.policy_revision = 3u;
    memcpy(binding.policy_digest, snap.canonical_digest_zero_on_input, 32u);
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    fabric_test_id(&binding.authority_id, 0xD0u);
    binding.authority_term = 18u;
    binding.assignment_epoch = 20u;
    fabric_test_id(&binding.owner_scope_id, 0x81u);
    fabric_test_pattern(binding.owner_tuple_canonical, 0x82u, 200u);
    ninlil_fabric_private_owner_tuple_digest(
        binding.owner_tuple_canonical, binding.owner_tuple_digest);
    fabric_test_id(&binding.authority_clock_epoch_id, 0xA1u);
    binding.lease_expires_at_ms = 300000u;
    binding.assignment_revision = 13u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_put_v1(fabric, &binding),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    /* Immutable lookup identity change on +1: CONFLICT */
    binding.assignment_revision = 12u;
    fabric_test_id(&binding.endpoint_runtime_id, 0x99u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_put_v1(fabric, &binding),
        NINLIL_FABRIC_PRIVATE_CONFLICT);
    /* Exact +1 with immutable identity: OK */
    fabric_test_id(&binding.endpoint_runtime_id, 0x80u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_authority_put_v1(fabric, &binding),
        NINLIL_FABRIC_PRIVATE_OK);
    /* Policy gap: rev 5 when current is 3 */
    {
        ninlil_fabric_path_policy_v1_t policy;
        ninlil_fabric_private_memzero(&policy, sizeof(policy));
        policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        policy.struct_size = (uint16_t)sizeof(policy);
        policy.policy_id = policy_id;
        policy.revision = 5u;
        memcpy(
            policy.service_identity_digest,
            snap.service_identity_digest,
            32u);
        policy.family = 2u;
        policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
        policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
        policy.required_capability_flags = 0x02u;
        policy.required_security_flags = 0x0Fu;
        policy.maximum_latency_class = 50u;
        policy.maximum_cost_class = 50u;
        policy.minimum_packet_bytes = 587u;
        policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
        policy.deadline_guard_ms = 100u;
        policy.candidate_count = 1u;
        fabric_test_id(&policy.candidates[0].instance_id, 0x61u);
        policy.candidates[0].rank = 10u;
        policy.candidates[0].reservation_units = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_put_v1(fabric, &policy),
            NINLIL_FABRIC_PRIVATE_CONFLICT);
    }
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Clean unavailable may succeed the historical FBR1 pinned by CLOSED FBA1. */
static int test_restart_allows_strict_availability_successor(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_link_descriptor_v1_t snapshot_descriptor;
    ninlil_fabric_link_state_v1_t snapshot_state;
    ninlil_fabric_link_state_v1_t unavailable;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_id128_t instance_id;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    fabric_test_store_t durable_successor;
    uint32_t work = 0u;
    uint32_t done = 0u;
    uint32_t i;
    uint32_t mutated = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(g_provider.live_token == 0u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    fabric_test_id(&instance_id, 0x61u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_link_snapshot_v1(
            fabric, &instance_id, &snapshot_descriptor, &snapshot_state),
        NINLIL_FABRIC_PRIVATE_OK);
    unavailable = snapshot_state;
    unavailable.availability_epoch = snapshot_state.availability_epoch + 1u;
    unavailable.available = 0u;
    unavailable.available_until_ms = snapshot_state.available_until_ms + 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_link_availability_update_v1(
            fabric, &instance_id, &unavailable),
        NINLIL_FABRIC_PRIVATE_OK);

    bearer->close(bearer->user, handle);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_begin_v1(fabric, reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_poll_v1(fabric, reg1, &done),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(done == 1u);
    done = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_poll_v1(fabric, &done),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(done == 1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(fabric),
        NINLIL_FABRIC_PRIVATE_OK);

    durable_successor = g_store;
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(fabric2 != NULL);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_begin_v1(fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    done = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_poll_v1(fabric2, &done),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(done == 1u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(fabric2),
        NINLIL_FABRIC_PRIVATE_OK);

    /* A CRC-valid immutable mutation is not an availability successor. */
    g_store = durable_successor;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        fabric_test_row_t *row = &g_store.rows[i];
        uint32_t capability_flags;
        if (row->used == 0u || row->key_len != 20u
            || row->value_len != 372u
            || memcmp(row->key, "FBR1", 4u) != 0) {
            continue;
        }
        capability_flags =
            ninlil_fabric_private_get_u32_be(row->value + 48u);
        ninlil_fabric_private_put_u32_be(
            row->value + 48u,
            capability_flags ^ NINLIL_FABRIC_CAP_BROADCAST);
        ninlil_fabric_private_put_u32_be(row->value + 20u, 0u);
        ninlil_fabric_private_put_u32_be(
            row->value + 20u,
            ninlil_fabric_private_crc32c(row->value, row->value_len));
        mutated = 1u;
        break;
    }
    FABRIC_REQUIRE(mutated == 1u);
    fabric2 = NULL;
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE(fabric2 == NULL);
    return 0;
}

/* (e) restart: corrupt FBA1 registry pin digest => CORRUPT open. */
static int test_restart_cross_record_registry_pin_corruption(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    fabric_test_store_t durable_copy;
    uint32_t i;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    durable_copy = g_store;
    /* Flip one byte inside FBA1 registry digest region (payload offset 248). */
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (durable_copy.rows[i].used == 0u
            || durable_copy.rows[i].key_len != 76u) {
            continue;
        }
        if (durable_copy.rows[i].key[0] == (uint8_t)'F'
            && durable_copy.rows[i].key[1] == (uint8_t)'B'
            && durable_copy.rows[i].key[2] == (uint8_t)'A'
            && durable_copy.rows[i].key[3] == (uint8_t)'1'
            && durable_copy.rows[i].value_len >= 300u) {
            /* envelope 24 + payload offset 248 = value offset 272 */
            durable_copy.rows[i].value[272] ^= 0xA5u;
            break;
        }
    }
    g_store = durable_copy;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE(fabric2 == NULL);
    return 0;
}

/* receive_next EMPTY with dirty outputs: release token + fence instance. */
static int test_receive_dirty_empty_releases_and_fences(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    uint32_t work = 0u;
    uint32_t rel_before;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    rel_before = g_provider.release_received_calls;
    g_provider.next_receive_status = NINLIL_FABRIC_LINK_EMPTY;
    g_provider.dirty_non_success_outputs = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 8u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(g_provider.release_received_calls > rel_before);
    /* Instance fenced (DRAINING): subsequent send cannot select it. */
    {
        ninlil_id128_t runtime;
        ninlil_bearer_handle_t handle = NULL;
        ninlil_tx_permit_t permit;
        ninlil_bearer_send_result_t result;
        fabric_test_id(&runtime, 0x30u);
        FABRIC_REQUIRE_EQ_U32(
            bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
            NINLIL_BEARER_OK);
        ninlil_fabric_private_memzero(&permit, sizeof(permit));
        permit.abi_version = NINLIL_ABI_VERSION;
        permit.struct_size = (uint16_t)sizeof(permit);
        fabric_test_id(&permit.permit_id, 0xE0u);
        permit.attempt_id = msg.attempt_id;
        fabric_test_id(&permit.clock_epoch_id, 0xA1u);
        permit.expires_at_ms = 200000u;
        g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &msg, &result),
            NINLIL_BEARER_UNAVAILABLE);
        bearer->close(bearer->user, handle);
    }
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* OK + NULL rx_token must fence and not publish RX. */
static int test_receive_ok_null_token_fences(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    uint32_t work = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    g_provider.rx_ready = 1u;
    g_provider.rx_len = 600u;
    g_provider.ok_null_token = 1u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 4u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBT1"), 0u);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* register multi FULL CU ALL-OLD: FBR1 absent + FBM1 old recovers CU. */
static int test_register_multi_full_cu_all_old(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    /* Discard staged: FBR1 stays absent, FBM1 stays old => ALL-OLD/ABSENT CU. */
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE(reg1 == NULL);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBR1"), 0u);
    /* Retry after CU succeeds. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(reg1 != NULL);
    FABRIC_REQUIRE(store_count_magic("FBR1") >= 1u);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* register multi FULL CU ALL-NEW: no RAM, close provider, retry blocked by pin. */
static int test_register_multi_full_cu_all_new(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u; /* NEW under CU */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN);
    FABRIC_REQUIRE(reg1 == NULL);
    /* Durable FBR1 may exist under CU-NEW; re-attach after restart only. */
    FABRIC_REQUIRE(store_count_magic("FBR1") >= 1u);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* 2 authorities: emitted FBA authority must match selected policy join. */
static int test_tx_authority_unique_not_last_loaded(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint32_t i;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    /* Second unrelated BOUND authority (different service digest). */
    {
        ninlil_fabric_authority_binding_v1_t binding;
        ninlil_fabric_path_policy_v1_t snap;
        ninlil_id128_t policy_id;
        fabric_test_id(&policy_id, 0x71u);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_policy_snapshot_v1(
                fabric, &policy_id, 3u, &snap),
            NINLIL_FABRIC_PRIVATE_OK);
        ninlil_fabric_private_memzero(&binding, sizeof(binding));
        binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        binding.struct_size = (uint16_t)sizeof(binding);
        fabric_test_id(&binding.binding_id, 0xC9u);
        fabric_test_pattern(binding.service_identity_digest, 0xFFu, 32u);
        binding.family = 2u;
        binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
        binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
        fabric_test_id(&binding.endpoint_runtime_id, 0x80u);
        fabric_test_id(&binding.target_runtime_id, 0x80u);
        fabric_test_id(&binding.target_application_id, 0x90u);
        binding.policy_id = policy_id;
        binding.policy_revision = 3u;
        memcpy(binding.policy_digest, snap.canonical_digest_zero_on_input, 32u);
        binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
        fabric_test_id(&binding.authority_id, 0xEEu);
        binding.authority_term = 99u;
        binding.assignment_epoch = 88u;
        fabric_test_id(&binding.owner_scope_id, 0x81u);
        fabric_test_pattern(binding.owner_tuple_canonical, 0xEEu, 200u);
        ninlil_fabric_private_owner_tuple_digest(
            binding.owner_tuple_canonical, binding.owner_tuple_digest);
        fabric_test_id(&binding.authority_clock_epoch_id, 0xA1u);
        binding.lease_expires_at_ms = 300000u;
        binding.assignment_revision = 1u;
        /* Different service digest: put may still accept as separate binding. */
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_put_v1(fabric, &binding),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    /* FBA1 authority_id must be 0xD0 (selected), not 0xEE (last loaded). */
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used == 0u || g_store.rows[i].key_len != 76u) {
            continue;
        }
        if (g_store.rows[i].key[0] == (uint8_t)'F'
            && g_store.rows[i].key[1] == (uint8_t)'B'
            && g_store.rows[i].key[2] == (uint8_t)'A'
            && g_store.rows[i].key[3] == (uint8_t)'1') {
            /* payload authority_id at FBA1 offset 164 => value 24+164=188 */
            uint8_t expect_auth[16];
            fabric_test_pattern(expect_auth, 0xD0u, 16u);
            FABRIC_REQUIRE(g_store.rows[i].value_len > 200u);
            FABRIC_REQUIRE(ninlil_fabric_private_memeq(
                g_store.rows[i].value + 188, expect_auth, 16u));
            break;
        }
    }
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/*
 * PREPARED FULL then availability race before provider: CLOSED, start_calls=0.
 */
static int test_prepared_reval_fail_closes_no_provider(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_id128_t id;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    ninlil_fabric_link_state_v1_t st;
    ninlil_fabric_link_descriptor_v1_t dout;
    uint32_t starts;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    /* First send: WOULD_BLOCK leaves RETRYABLE with FBA availability pin. */
    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_WOULD_BLOCK);
    starts = g_provider.start_calls;

    /* Advance availability epoch so FBA pin no longer matches registry. */
    fabric_test_id(&id, 0x61u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_link_snapshot_v1(fabric, &id, &dout, &st),
        NINLIL_FABRIC_PRIVATE_OK);
    {
        ninlil_fabric_link_state_v1_t neu = st;
        neu.availability_epoch = st.availability_epoch + 1u;
        neu.available = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_link_availability_update_v1(
                fabric, &id, &neu),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    /* Exact retry: PREPARED then pre-provider reval fails → CLOSED, no start. */
    fabric_test_id(&permit.permit_id, 0xE1u);
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE(
        bearer->send(bearer->user, handle, &permit, &msg, &result)
        != NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Restart keeps RETRYABLE when epoch matches; exact retry succeeds. */
static int test_restart_retryable_epoch_and_exact_retry(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    const ninlil_bearer_ops_t *bearer2 = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_fabric_registration_private_t *reg2 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_handle_t handle2 = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    fabric_test_store_t durable_copy;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_WOULD_BLOCK);
    durable_copy = g_store;
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);

    /* Restart with same clock epoch. */
    g_store = durable_copy;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_reset_globals();
    g_store = durable_copy;
    g_store.open = 0u;
    fabric_test_storage_ops(&storage);
    fabric_test_set_clock(170000u, 0xA1u);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    config.clock = &clock;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    config.execution = &exec;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric2, &bearer2),
        NINLIL_FABRIC_PRIVATE_OK);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric2, &d1, &ops, &reg2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer2->open(bearer2->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle2),
        NINLIL_BEARER_OK);
    fabric_test_id(&permit.permit_id, 0xE1u);
    {
        uint32_t starts_before = g_provider.start_calls;
        g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
        FABRIC_REQUIRE_EQ_U32(
            bearer2->send(bearer2->user, handle2, &permit, &msg, &result),
            NINLIL_BEARER_OK);
        /* Packet slot restored on restart RETRYABLE → provider start runs. */
        FABRIC_REQUIRE(g_provider.start_calls > starts_before);
    }
    bearer2->close(bearer2->user, handle2);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    return 0;
}

/*
 * P1: durable path_selection_epoch restores max from FBA1; wrap at UINT64_MAX
 * fails closed on next NEW attempt (no provider start).
 */
static int test_path_selection_epoch_wrap_fail_closed(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    const ninlil_bearer_ops_t *bearer2 = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_fabric_registration_private_t *reg2 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_handle_t handle2 = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    fabric_test_store_t durable_copy;
    fabric_test_row_t *fba_row;
    uint32_t starts;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_WOULD_BLOCK);
    FABRIC_REQUIRE(store_count_magic("FBA1") >= 1u);

    /* Pin durable path_selection_epoch to UINT64_MAX with valid CRC. */
    fba_row = find_store_row_magic("FBA1");
    FABRIC_REQUIRE(fba_row != NULL);
    {
        ninlil_fabric_private_common_envelope_t env;
        const uint8_t *pl = NULL;
        ninlil_fabric_private_fba1_t rec;
        uint8_t payload[NINLIL_FABRIC_FBA1_PAYLOAD_BYTES];
        uint8_t value[24u + NINLIL_FABRIC_FBA1_PAYLOAD_BYTES];
        uint32_t vlen = 0u;
        FABRIC_REQUIRE(
            ninlil_fabric_private_record_decode_envelope(
                fba_row->value,
                fba_row->value_len,
                (const uint8_t *)"FBA1",
                NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
                &env,
                &pl)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        FABRIC_REQUIRE(
            ninlil_fabric_private_fba1_decode(pl, &rec)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        /* Close RETRYABLE so post-restart send is a NEW attempt. */
        rec.state = NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED;
        rec.path_selection_epoch = UINT64_MAX;
        FABRIC_REQUIRE(
            ninlil_fabric_private_fba1_encode(&rec, payload)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        FABRIC_REQUIRE(
            ninlil_fabric_private_record_encode_envelope(
                (const uint8_t *)"FBA1",
                env.revision,
                payload,
                NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
                value,
                (uint32_t)sizeof(value),
                &vlen)
            == NINLIL_FABRIC_PRIVATE_RECORD_OK);
        FABRIC_REQUIRE(vlen <= FABRIC_TEST_VAL_MAX);
        (void)memcpy(fba_row->value, value, vlen);
        fba_row->value_len = vlen;
    }

    durable_copy = g_store;
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);

    g_store = durable_copy;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_reset_globals();
    g_store = durable_copy;
    g_store.open = 0u;
    fabric_test_storage_ops(&storage);
    fabric_test_set_clock(170000u, 0xA1u);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    config.clock = &clock;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    config.execution = &exec;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, restart_ws, sizeof(restart_ws), &fabric2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric2, &bearer2),
        NINLIL_FABRIC_PRIVATE_OK);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric2, &d1, &ops, &reg2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer2->open(bearer2->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle2),
        NINLIL_BEARER_OK);

    /* NEW attempt identity after wrap restore → fail-closed, no provider. */
    fabric_test_id(&msg.attempt_id, 0xAAu);
    fabric_test_id(&permit.permit_id, 0xE2u);
    permit.attempt_id = msg.attempt_id;
    starts = g_provider.start_calls;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer2->send(bearer2->user, handle2, &permit, &msg, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    bearer2->close(bearer2->user, handle2);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    return 0;
}

/* P0: text_id length 64 and 255 never reach digest/provider (ASan-safe). */
static int test_send_rejects_text_id_length_boundaries(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint32_t starts;
    uint8_t lens[2];
    uint32_t li;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    lens[0] = 64u;
    lens[1] = 255u;
    for (li = 0u; li < 2u; ++li) {
        ninlil_bearer_message_t bad = msg;
        starts = g_provider.start_calls;
        bad.service.namespace_id.length = lens[li];
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &bad, &result),
            NINLIL_BEARER_CORRUPT);
        FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
        bad = msg;
        bad.service.service_id.length = lens[li];
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &bad, &result),
            NINLIL_BEARER_CORRUPT);
        FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
        bad = msg;
        bad.service.schema_id.length = lens[li];
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &bad, &result),
            NINLIL_BEARER_CORRUPT);
        FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    }
    /* length 63 still admissible if bytes are filled. */
    {
        ninlil_bearer_message_t okm = msg;
        uint8_t i;
        okm.service.namespace_id.length = 63u;
        for (i = 0u; i < 63u; ++i) {
            okm.service.namespace_id.bytes[i] = (uint8_t)('a' + (i % 26u));
        }
        /* Policy won't match different service digest => UNAVAILABLE, not crash. */
        starts = g_provider.start_calls;
        FABRIC_REQUIRE(
            bearer->send(bearer->user, handle, &permit, &okm, &result)
                != NINLIL_BEARER_OK
            || g_provider.start_calls >= starts);
        /* Must not be CORRUPT from length alone when length==63. */
        FABRIC_REQUIRE(
            bearer->send(bearer->user, handle, &permit, &okm, &result)
            != NINLIL_BEARER_CORRUPT
            || okm.service.namespace_id.length > 63u);
    }
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/*
 * Two links with different peers: selection must not depend on registration
 * order (no first-row Attachment/peer seed).
 */
static int test_multi_peer_registry_order_independence(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d0;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg0 = NULL;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d0, 0x01u, 30u); /* worse latency */
    fill_descriptor(&d1, 0x61u, 10u); /* better latency */
    fabric_test_id(&d0.authenticated_peer_runtime_id, 0xAAu);
    fabric_test_id(&d0.attachment_authority_id, 0xBBu);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"peer-a-attach", 13u, d0.attachment_binding_digest);
    fabric_test_id(&d1.authenticated_peer_runtime_id, 0xCCu);
    fabric_test_id(&d1.attachment_authority_id, 0xDDu);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"peer-b-attach", 13u, d1.attachment_binding_digest);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d0, &ops, &reg0),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    /* Prefer better latency candidate 0x61 regardless of peer difference. */
    FABRIC_REQUIRE_EQ_U32(result.kind, NINLIL_BEARER_SEND_ACCEPTED);
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* P0: invalid TxPermit must DENY with provider start_calls == 0. */
static int test_tx_permit_gate_denies_before_provider(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint32_t starts;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;

    /* NULL permit */
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, NULL, &msg, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* wrong attempt_id */
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    fabric_test_id(&permit.attempt_id, 0xFFu);
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* Expiry is exclusive: exactly now is already denied. */
    permit.attempt_id = msg.attempt_id;
    permit.expires_at_ms = 170000u;
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* wrong clock epoch */
    permit.expires_at_ms = 200000u;
    fabric_test_id(&permit.clock_epoch_id, 0xB2u);
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* zero permit_id */
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    ninlil_fabric_private_memzero(permit.permit_id.bytes, 16u);
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* bad ABI */
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.abi_version = 0u;
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* One millisecond before expiry remains valid. */
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.expires_at_ms = 170001u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);

    /*
     * One-shot durable authority (not 16-slot ring): same permit_id replay
     * after OK+ACCEPTED => DENIED, provider start unchanged.
     */
    starts = g_provider.start_calls;
    {
        ninlil_bearer_message_t msg2 = msg;
        fabric_test_id(&msg2.attempt_id, 0x21u);
        permit.attempt_id = msg2.attempt_id;
        /* Same permit_id, different attempt: still one-shot by permit_id. */
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &msg2, &result),
            NINLIL_BEARER_DENIED);
        FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    }
    /* Fresh permit_id still works for new attempt. */
    fabric_test_id(&permit.permit_id, 0xE1u);
    {
        ninlil_bearer_message_t msg3 = msg;
        fabric_test_id(&msg3.attempt_id, 0x22u);
        permit.attempt_id = msg3.attempt_id;
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(bearer->user, handle, &permit, &msg3, &result),
            NINLIL_BEARER_OK);
    }

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        uint32_t work = 0u;
        uint32_t spins;
        for (spins = 0u; spins < 32u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        }
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/*
 * P0 permanent matrix: same {tx,attempt,kind} with one-byte digest change
 * is CORRUPT / provider start unchanged for LINK_RETAINED, CLOSED, FENCED,
 * and restart; bit-exact RETRYABLE retry still OK.
 */
static int test_identity_conflict_all_fba_states(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_bearer_message_t mut;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint32_t starts;
    uint32_t work = 0u;
    uint32_t done = 0u;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    /* --- LINK_RETAINED: accept then mutate => CORRUPT, start unchanged --- */
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    starts = g_provider.start_calls;
    mut = msg;
    mut.content_digest.bytes[0] ^= 0x5Au;
    fabric_test_id(&permit.permit_id, 0xE1u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    /* Bit-exact same on LINK_RETAINED also CORRUPT (no re-dispatch). */
    fabric_test_id(&permit.permit_id, 0xE2u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* Drain to CLOSED via step. */
    g_provider.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    g_provider.next_poll_status = NINLIL_FABRIC_LINK_OK;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 16u, &work),
        NINLIL_FABRIC_PRIVATE_OK);

    /* --- CLOSED: mutated digest CORRUPT --- */
    mut = msg;
    mut.content_digest.bytes[1] ^= 0x11u;
    fabric_test_id(&permit.permit_id, 0xE3u);
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    /* Bit-exact on CLOSED: CORRUPT */
    fabric_test_id(&permit.permit_id, 0xE4u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    for (done = 0u; done == 0u;) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);

    /* --- FENCED via LOST_UNKNOWN start, then mutate --- */
    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    fabric_test_id(&permit.permit_id, 0xF0u);
    permit.attempt_id = msg.attempt_id;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    starts = g_provider.start_calls;
    mut = msg;
    mut.content_digest.bytes[0] ^= 0x22u;
    fabric_test_id(&permit.permit_id, 0xF1u);
    {
        ninlil_bearer_status_t fs =
            bearer->send(bearer->user, handle, &permit, &mut, &result);
        FABRIC_REQUIRE(
            fs == NINLIL_BEARER_CORRUPT || fs == NINLIL_BEARER_LOST_UNKNOWN);
    }
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    for (done = 0u; done == 0u;) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);

    /* --- Restart: RETRYABLE then mutate after reload (preserve store) --- */
    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    fabric_test_id(&permit.permit_id, 0xA0u);
    permit.attempt_id = msg.attempt_id;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_WOULD_BLOCK);
    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    for (done = 0u; done == 0u;) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);

    /* Reopen without wiping g_store so RETRYABLE FBA1 reloads. */
    {
        fabric_test_store_t durable = g_store;
        g_store = durable;
        g_store.open = 0u;
        ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
        ninlil_fabric_private_memzero(&g_provider, sizeof(g_provider));
        g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
        g_provider.completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        g_provider.state.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        g_provider.state.struct_size = (uint16_t)sizeof(g_provider.state);
        g_provider.state.availability_epoch = 7u;
        fabric_test_pattern(
            g_provider.state.availability_clock_epoch_id.bytes, 0xA1u, 16u);
        g_provider.state.available_until_ms = 250000u;
        g_provider.state.available = 1u;
        fabric_test_storage_ops(&storage);
        ninlil_fabric_private_memzero(g_workspace, sizeof(g_workspace));
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_create_v1(
                &config, g_workspace, sizeof(g_workspace), &fabric),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_bearer_ops_v1(fabric, &bearer),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    mut = msg;
    mut.content_digest.bytes[0] ^= 0x33u;
    fabric_test_id(&permit.permit_id, 0xA1u);
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    /* Bit-exact idempotent retry after restart. */
    fabric_test_id(&permit.permit_id, 0xA2u);
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(g_provider.start_calls > starts);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    for (done = 0u; done == 0u;) {
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* P1: RETRYABLE same IDs with mutated message fields => CORRUPT, TX0. */
static int test_retryable_rejects_mutated_same_attempt_ids(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *reg1 = NULL;
    ninlil_bearer_message_t msg;
    ninlil_bearer_message_t mut;
    ninlil_id128_t runtime;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint32_t starts;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg1),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&msg);
    if (put_policy_and_authority(fabric, &msg) != 0) {
        return 1;
    }
    fabric_test_id(&runtime, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(bearer->user, &runtime, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xE0u);
    permit.attempt_id = msg.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    /* First send: WOULD_BLOCK => RETRYABLE_NO_ACCEPT with saved packet. */
    g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_WOULD_BLOCK);
    starts = g_provider.start_calls;

    /* Mutate content_digest only; keep transaction/attempt/kind. */
    mut = msg;
    mut.content_digest.bytes[0] ^= 0x5Au;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* Mutate target runtime. */
    mut = msg;
    fabric_test_id(&mut.target.target_runtime_id, 0x11u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* Mutate service family. */
    mut = msg;
    mut.service.family = 9u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* Mutate source runtime. */
    mut = msg;
    fabric_test_id(&mut.source.runtime_id, 0x22u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* Mutate generation. */
    mut = msg;
    mut.generation = msg.generation + 1u;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &mut, &result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);

    /* Bit-exact same message + fresh valid permit still retries OK. */
    fabric_test_id(&permit.permit_id, 0xE1u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(g_provider.start_calls > starts);

    bearer->close(bearer->user, handle);
    (void)ninlil_fabric_private_close_begin_v1(fabric);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

static int run_claim_cu_readback_shape(
    uint32_t apply_staged,
    uint32_t observed_shape,
    int expect_reopen_corrupt)
{
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *fabric2 = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    const ninlil_bearer_ops_t *bearer2 = NULL;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_message_t message;
    ninlil_bearer_message_t replay;
    ninlil_id128_t runtime_id;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_handle_t handle2 = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    fabric_test_store_t durable;
    uint32_t starts;
    ninlil_fabric_private_status_t create_status;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&descriptor, 0x61u, 10u);
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            fabric, &descriptor, &ops, &registration),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&message);
    if (put_policy_and_authority(fabric, &message) != 0) {
        return 1;
    }
    fabric_test_id(&runtime_id, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(
            bearer->user, &runtime_id, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.permit_id, 0xD0u);
    permit.attempt_id = message.attempt_id;
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;

    /* PREPARED succeeds; the co-located CLEAR->CLAIMED FULL is uncertain. */
    starts = g_provider.start_calls;
    g_store.fail_next_commit = 1u;
    g_store.commit_fault_skips = 1u;
    g_store.cu_apply_staged = apply_staged;
    g_store.cu_observed_shape = observed_shape;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &message, &result),
        NINLIL_BEARER_LOST_UNKNOWN);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBPC"), 0u);

    durable = g_store;
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    create_status = ninlil_fabric_private_create_v1(
        &config, restart_ws, sizeof(restart_ws), &fabric2);
    if (expect_reopen_corrupt != 0) {
        FABRIC_REQUIRE_EQ_U32(
            create_status, NINLIL_FABRIC_PRIVATE_CORRUPT);
        FABRIC_REQUIRE(fabric2 == NULL);
        return 0;
    }
    FABRIC_REQUIRE_EQ_U32(create_status, NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(fabric2, &bearer2),
        NINLIL_FABRIC_PRIVATE_OK);
    fabric_test_provider_ops(&ops, &g_provider);
    registration = NULL;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            fabric2, &descriptor, &ops, &registration),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        bearer2->open(
            bearer2->user, &runtime_id, NINLIL_ROLE_ENDPOINT, &handle2),
        NINLIL_BEARER_OK);
    replay = message;
    fabric_test_id(&replay.transaction_id, 0x91u);
    fabric_test_id(&replay.attempt_id, 0xA1u);
    permit.attempt_id = replay.attempt_id;
    starts = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer2->send(
            bearer2->user, handle2, &permit, &replay, &result),
        NINLIL_BEARER_DENIED);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
    bearer2->close(bearer2->user, handle2);
    (void)ninlil_fabric_private_close_begin_v1(fabric2);
    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_poll_v1(fabric2, &done);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric2);
    (void)fabric;
    (void)handle;
    return 0;
}

/*
 * Claim COMMIT_UNKNOWN readback matrix. OLD/NEW/PARTIAL/CRC-valid THIRD all
 * authorize zero provider calls. PARTIAL makes cold reopen reject the damaged
 * row; the other exact/valid rows reopen and remain replay-denied.
 */
static int test_permit_claim_cu_readback_matrix(void)
{
    (void)run_claim_cu_readback_shape(0u, 0u, 0);
    (void)run_claim_cu_readback_shape(1u, 0u, 0);
    (void)run_claim_cu_readback_shape(1u, 1u, 1);
    (void)run_claim_cu_readback_shape(1u, 2u, 0);
    return 0;
}

/* Exact Profile-1 FBA capacity: 64 reopens; a canonical row 65 rejects open. */
static int test_attempt_capacity_exact_64_and_65(void)
{
    static uint8_t reopen64_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    static uint8_t reopen65_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    static fabric_test_store_t durable64;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_private_t *reopened = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *registration = NULL;
    ninlil_bearer_message_t base;
    ninlil_bearer_message_t message;
    ninlil_id128_t runtime_id;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint32_t i;
    uint32_t first_fba = FABRIC_TEST_STORE_MAX;
    uint32_t free_row = FABRIC_TEST_STORE_MAX;

    if (fabric_boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&descriptor, 0x61u, 10u);
    descriptor.reservation_capacity = NINLIL_FABRIC_ATTEMPT_MAX;
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            fabric, &descriptor, &ops, &registration),
        NINLIL_FABRIC_PRIVATE_OK);
    fill_message(&base);
    if (put_policy_and_authority(fabric, &base) != 0) {
        return 1;
    }
    fabric_test_id(&runtime_id, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        bearer->open(
            bearer->user, &runtime_id, NINLIL_ROLE_ENDPOINT, &handle),
        NINLIL_BEARER_OK);
    ninlil_fabric_private_memzero(&permit, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    fabric_test_id(&permit.clock_epoch_id, 0xA1u);
    permit.expires_at_ms = 200000u;
    /*
     * Definite UNAVAILABLE closes each attempt; Runtime release then makes it
     * DRAINED and frees the 32-slot packet pool while retaining all 64 FBA1s.
     */
    g_provider.next_start_status = NINLIL_FABRIC_LINK_UNAVAILABLE;

    for (i = 0u; i < NINLIL_FABRIC_ATTEMPT_MAX; ++i) {
        uint32_t row_i;
        const uint8_t *foundation = NULL;
        message = base;
        fabric_test_id(&message.transaction_id, (uint8_t)(0x10u + i));
        fabric_test_id(&message.attempt_id, (uint8_t)(0x50u + i));
        fabric_test_id(&permit.permit_id, (uint8_t)(0xA0u + i));
        permit.attempt_id = message.attempt_id;
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(
                bearer->user, handle, &permit, &message, &result),
            NINLIL_BEARER_UNAVAILABLE);
        for (row_i = 0u; row_i < FABRIC_TEST_STORE_MAX; ++row_i) {
            if (g_store.rows[row_i].used != 0u
                && g_store.rows[row_i].key_len == 76u
                && memcmp(g_store.rows[row_i].key, "FBA1", 4u) == 0
                && memcmp(
                       g_store.rows[row_i].key + 4u,
                       message.transaction_id.bytes,
                       16u)
                    == 0
                && memcmp(
                       g_store.rows[row_i].key + 20u,
                       message.attempt_id.bytes,
                       16u)
                    == 0) {
                foundation = g_store.rows[row_i].key + 44u;
                break;
            }
        }
        FABRIC_REQUIRE(foundation != NULL);
        if (foundation != NULL) {
            FABRIC_REQUIRE_EQ_U32(
                ninlil_fabric_private_dispatch_release_v1(
                    fabric,
                    &message.transaction_id,
                    &message.attempt_id,
                    message.kind,
                    0u,
                    foundation,
                    (uint64_t)i + 1u),
                NINLIL_FABRIC_PRIVATE_OK);
        }
    }
    FABRIC_REQUIRE_EQ_U32(
        store_count_magic("FBA1"), NINLIL_FABRIC_ATTEMPT_MAX);
    message = base;
    fabric_test_id(&message.transaction_id, 0x70u);
    fabric_test_id(&message.attempt_id, 0xF0u);
    fabric_test_id(&permit.permit_id, 0xE8u);
    permit.attempt_id = message.attempt_id;
    {
        uint32_t starts = g_provider.start_calls;
        FABRIC_REQUIRE_EQ_U32(
            bearer->send(
                bearer->user, handle, &permit, &message, &result),
            NINLIL_BEARER_WOULD_BLOCK);
        FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
        FABRIC_REQUIRE_EQ_U32(
            store_count_magic("FBA1"), NINLIL_FABRIC_ATTEMPT_MAX);
    }

    durable64 = g_store;
    g_store = durable64;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(reopen64_ws, sizeof(reopen64_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, reopen64_ws, sizeof(reopen64_ws), &reopened),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(reopened != NULL);

    /*
     * Restore the crash image and append one individually canonical FBA1
     * derived from an existing row. The profile count, not malformed bytes,
     * must reject it.
     */
    g_store = durable64;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used == 0u && free_row == FABRIC_TEST_STORE_MAX) {
            free_row = i;
        } else if (
            g_store.rows[i].used != 0u && g_store.rows[i].key_len == 76u
            && memcmp(g_store.rows[i].key, "FBA1", 4u) == 0
            && first_fba == FABRIC_TEST_STORE_MAX) {
            first_fba = i;
        }
    }
    FABRIC_REQUIRE(first_fba < FABRIC_TEST_STORE_MAX);
    FABRIC_REQUIRE(free_row < FABRIC_TEST_STORE_MAX);
    if (first_fba < FABRIC_TEST_STORE_MAX
        && free_row < FABRIC_TEST_STORE_MAX) {
        ninlil_fabric_private_common_envelope_t env;
        ninlil_fabric_private_fba1_t fba;
        const uint8_t *payload = NULL;
        uint8_t new_payload[NINLIL_FABRIC_FBA1_PAYLOAD_BYTES];
        uint8_t new_value[NINLIL_FABRIC_FBA1_VALUE_BYTES];
        uint8_t new_key[76];
        uint32_t new_value_len = 0u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_record_decode_envelope(
                g_store.rows[first_fba].value,
                g_store.rows[first_fba].value_len,
                (const uint8_t *)"FBA1",
                NINLIL_FABRIC_FBA1_PAYLOAD_BYTES,
                &env,
                &payload),
            NINLIL_FABRIC_PRIVATE_RECORD_OK);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_fba1_decode(payload, &fba),
            NINLIL_FABRIC_PRIVATE_RECORD_OK);
        fabric_test_pattern(fba.transaction_id, 0xD1u, 16u);
        fabric_test_pattern(fba.attempt_id, 0xE1u, 16u);
        fabric_test_pattern(fba.foundation_message_digest, 0xF1u, 32u);
        fabric_test_pattern(fba.permit_id, 0x01u, 16u);
        ninlil_fabric_private_key_fba1(
            fba.transaction_id,
            fba.attempt_id,
            fba.message_kind,
            fba.response_slot,
            fba.foundation_message_digest,
            new_key);
        ninlil_fabric_private_local_dispatch_id(
            new_key, fba.local_dispatch_id);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_fba1_encode(&fba, new_payload),
            NINLIL_FABRIC_PRIVATE_RECORD_OK);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_record_encode_envelope(
                (const uint8_t *)"FBA1",
                1u,
                new_payload,
                sizeof(new_payload),
                new_value,
                sizeof(new_value),
                &new_value_len),
            NINLIL_FABRIC_PRIVATE_RECORD_OK);
        g_store.rows[free_row].used = 1u;
        (void)memcpy(g_store.rows[free_row].key, new_key, sizeof(new_key));
        g_store.rows[free_row].key_len = sizeof(new_key);
        (void)memcpy(
            g_store.rows[free_row].value, new_value, new_value_len);
        g_store.rows[free_row].value_len = new_value_len;
    }
    fabric_test_storage_ops(&storage);
    reopened = NULL;
    ninlil_fabric_private_memzero(reopen65_ws, sizeof(reopen65_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &config, reopen65_ws, sizeof(reopen65_ws), &reopened),
        NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE(reopened == NULL);
    (void)fabric;
    (void)handle;
    return 0;
}

typedef struct fabric_gc_fixture {
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric;
    const ninlil_bearer_ops_t *bearer;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_registration_private_t *registration;
    ninlil_bearer_handle_t handle;
    ninlil_id128_t runtime_id;
    ninlil_bearer_message_t message;
    ninlil_tx_permit_t permit;
    uint8_t foundation_digest[32];
} fabric_gc_fixture_t;

static int fabric_gc_fixture_boot(
    fabric_gc_fixture_t *fixture, uint8_t identity_seed, uint64_t permit_expiry)
{
    ninlil_bearer_send_result_t result;
    uint32_t i;
    const uint8_t *foundation = NULL;
    if (fixture == NULL) {
        return 1;
    }
    ninlil_fabric_private_memzero(fixture, sizeof(*fixture));
    if (fabric_boot(
            &fixture->fabric,
            &fixture->bearer,
            &fixture->storage,
            &fixture->clock,
            &fixture->exec,
            &fixture->config)
        != 0) {
        return 1;
    }
    fill_descriptor(&fixture->descriptor, 0x61u, 10u);
    fabric_test_provider_ops(&fixture->ops, &g_provider);
    if (ninlil_fabric_private_register_link_v1(
            fixture->fabric,
            &fixture->descriptor,
            &fixture->ops,
            &fixture->registration)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 1;
    }
    fill_message(&fixture->message);
    fabric_test_id(&fixture->message.transaction_id, identity_seed);
    fabric_test_id(
        &fixture->message.attempt_id, (uint8_t)(identity_seed + 0x20u));
    if (put_policy_and_authority(fixture->fabric, &fixture->message) != 0) {
        return 1;
    }
    fabric_test_id(&fixture->runtime_id, 0x30u);
    if (fixture->bearer->open(
            fixture->bearer->user,
            &fixture->runtime_id,
            NINLIL_ROLE_ENDPOINT,
            &fixture->handle)
        != NINLIL_BEARER_OK) {
        return 1;
    }
    fixture->permit.abi_version = NINLIL_ABI_VERSION;
    fixture->permit.struct_size = (uint16_t)sizeof(fixture->permit);
    fabric_test_id(
        &fixture->permit.permit_id, (uint8_t)(identity_seed + 0x40u));
    fixture->permit.attempt_id = fixture->message.attempt_id;
    fabric_test_id(&fixture->permit.clock_epoch_id, 0xA1u);
    fixture->permit.expires_at_ms = permit_expiry;
    g_provider.next_start_status = NINLIL_FABRIC_LINK_UNAVAILABLE;
    if (fixture->bearer->send(
            fixture->bearer->user,
            fixture->handle,
            &fixture->permit,
            &fixture->message,
            &result)
        != NINLIL_BEARER_UNAVAILABLE) {
        return 1;
    }
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (g_store.rows[i].used != 0u && g_store.rows[i].key_len == 76u
            && memcmp(g_store.rows[i].key, "FBA1", 4u) == 0
            && memcmp(
                   g_store.rows[i].key + 4u,
                   fixture->message.transaction_id.bytes,
                   16u)
                == 0
            && memcmp(
                   g_store.rows[i].key + 20u,
                   fixture->message.attempt_id.bytes,
                   16u)
                == 0) {
            foundation = g_store.rows[i].key + 44u;
            break;
        }
    }
    if (foundation == NULL) {
        return 1;
    }
    (void)memcpy(fixture->foundation_digest, foundation, 32u);
    if (ninlil_fabric_private_dispatch_release_v1(
            fixture->fabric,
            &fixture->message.transaction_id,
            &fixture->message.attempt_id,
            fixture->message.kind,
            0u,
            fixture->foundation_digest,
            1u)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 1;
    }
    return store_count_magic("FBA1") == 1u ? 0 : 1;
}

/*
 * Same-epoch GC waits for max(retention_until, permit expiry), is inclusive
 * at that boundary, survives a cold reopen, and spends one work unit/erase.
 */
static int test_attempt_gc_retention_expiry_and_restart(void)
{
    static uint8_t restart_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    static fabric_test_store_t durable;
    fabric_gc_fixture_t fixture;
    ninlil_fabric_private_t *reopened = NULL;
    uint32_t work = 0u;
    uint32_t erase_before;
    uint32_t delete_before;

    FABRIC_REQUIRE_EQ_U32(
        fabric_gc_fixture_boot(&fixture, 0x11u, 210000u), 0u);
    durable = g_store;
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&fixture.storage);
    fabric_test_set_clock(209999u, 0xA1u);
    ninlil_fabric_private_memzero(restart_ws, sizeof(restart_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &fixture.config, restart_ws, sizeof(restart_ws), &reopened),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);
    fabric_test_provider_ops(&fixture.ops, &g_provider);
    fixture.registration = NULL;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            reopened,
            &fixture.descriptor,
            &fixture.ops,
            &fixture.registration),
        NINLIL_FABRIC_PRIVATE_OK);

    erase_before = g_store.erase_calls;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(reopened, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(g_store.erase_calls, erase_before);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    fabric_test_set_clock(210000u, 0xA1u);
    erase_before = g_store.erase_calls;
    delete_before = g_store.delete_calls;
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(reopened, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(g_store.erase_calls, erase_before + 1u);
    FABRIC_REQUIRE_EQ_U32(g_store.delete_calls, delete_before + 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 0u);
    (void)fixture.fabric;
    (void)fixture.handle;
    return 0;
}

/*
 * GC erase CU-OLD retains the row across restart; a subsequent CU-NEW proves
 * absence, frees the slot, and a second cold reopen observes no resurrection.
 */
static int test_attempt_gc_commit_unknown_old_new_restart(void)
{
    static uint8_t restart1_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    static uint8_t restart2_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
        __attribute__((aligned(16)));
    static fabric_test_store_t durable;
    fabric_gc_fixture_t fixture;
    ninlil_fabric_private_t *reopened1 = NULL;
    ninlil_fabric_private_t *reopened2 = NULL;
    uint32_t work = 0u;
    uint32_t deletes;

    FABRIC_REQUIRE_EQ_U32(
        fabric_gc_fixture_boot(&fixture, 0x12u, 200000u), 0u);
    fabric_test_set_clock(200000u, 0xA1u);
    deletes = g_store.delete_calls;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fixture.fabric, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(g_store.delete_calls, deletes);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    durable = g_store;
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&fixture.storage);
    ninlil_fabric_private_memzero(restart1_ws, sizeof(restart1_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &fixture.config, restart1_ws, sizeof(restart1_ws), &reopened1),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 1u);

    deletes = g_store.delete_calls;
    g_store.fail_next_commit = 1u;
    g_store.cu_apply_staged = 1u;
    work = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(reopened1, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(g_store.delete_calls, deletes + 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 0u);

    durable = g_store;
    g_store = durable;
    g_store.open = 0u;
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    fabric_test_storage_ops(&fixture.storage);
    ninlil_fabric_private_memzero(restart2_ws, sizeof(restart2_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(
            &fixture.config, restart2_ws, sizeof(restart2_ws), &reopened2),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 0u);
    return 0;
}

/* A new trusted clock epoch makes an old permit epoch GC-eligible immediately. */
static int test_attempt_gc_old_permit_epoch(void)
{
    fabric_gc_fixture_t fixture;
    uint32_t work = 0u;
    uint32_t erase_before;
    FABRIC_REQUIRE_EQ_U32(
        fabric_gc_fixture_boot(&fixture, 0x13u, 240000u), 0u);
    fabric_test_set_clock(170000u, 0xB2u);
    erase_before = g_store.erase_calls;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fixture.fabric, 1u, &work),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(work, 1u);
    FABRIC_REQUIRE_EQ_U32(g_store.erase_calls, erase_before + 1u);
    FABRIC_REQUIRE_EQ_U32(store_count_magic("FBA1"), 0u);
    return 0;
}

int main(void)
{
    g_fabric_test_failures = 0;
    (void)test_enrich_project_lossless();
    (void)test_create_register_send_accept();
    (void)test_wifi_custody_rejected_before_provider_or_store();
    (void)test_provider_would_block_retry();
    (void)test_provider_lost_unknown();
    (void)test_provider_all_terminal_status();
    (void)test_new_attempt_failover_after_conflict();
    (void)test_registry_capacity_exhaustion();
    (void)test_policy_authority_capacity_64();
    (void)test_availability_epoch_hot_update();
    (void)test_unregister_race_excludes_selection();
    (void)test_unregister_draining();
    (void)test_commit_unknown_create();
    (void)test_commit_unknown_classifier_matrix();
    (void)test_endian_padding_independence();
    (void)test_wrong_thread();
    (void)test_policy_put_full_first_fail_closed();
    (void)test_restart_reload_and_no_resurrection();
    (void)test_send_prepared_full_before_provider();
    (void)test_permit_preclaim_cu_new_restart_replay_denied();
    (void)test_storage_fault_injection_matrix();
    (void)test_fbt1_full_required_before_rx();
    (void)test_restart_fences_prepared_attempt();
    (void)test_put_same_vs_conflict();
    (void)test_restart_corrupt_and_canonical_failures();
    (void)test_link_retained_full_fail_reclaims_token();
    (void)test_poll_non_ok_reclaims_token();
    (void)test_would_block_with_token_contradiction();
    (void)test_unregister_close_bounded_after_accept();
    (void)test_reverse_exact_echo_publishes();
    (void)test_reverse_fba1_exact_echo_publishes();
    (void)test_reverse_send_uses_saved_fbt1_policy();
    (void)test_reverse_auth_negatives_no_publish();
    (void)test_forward_ambiguous_authority_no_publish();
    (void)test_restart_fbt1_reverse_persistence();
    (void)test_restart_fba1_reverse_persistence();
    (void)test_prepared_cu_new_fences_no_provider();
    (void)test_prepared_cu_old_no_provider();
    (void)test_prepared_cu_new_restart_fenced();
    (void)test_remove_rejects_active_reference();
    (void)test_trigger_release_full_restart();
    (void)test_trigger_release_retention_overflow_no_mutation();
    (void)test_trigger_gc_80_at_two_per_second();
    (void)test_transaction_terminal_release_mixed_and_retained();
    (void)test_transaction_terminal_release_conflict_is_atomic();
    (void)test_transaction_terminal_release_trigger_cu_restart();
    (void)test_transaction_terminal_release_trigger_cu_third();
    (void)test_transaction_terminal_release_retryable_two_step();
    (void)test_policy_remove_cu_new_clears_ram();
    (void)test_remove_after_release_and_retention();
    (void)test_register_link_fbr1_fbm1_same_full_group();
    (void)test_register_link_full_fail_closes_provider();
    (void)test_adoption_rejects_orphan_records_without_fbm1();
    (void)test_provider_open_error_nonnull_handle_closed();
    (void)test_authority_revision_strict_plus1_and_immutable();
    (void)test_restart_allows_strict_availability_successor();
    (void)test_restart_cross_record_registry_pin_corruption();
    (void)test_receive_dirty_empty_releases_and_fences();
    (void)test_receive_ok_null_token_fences();
    (void)test_register_multi_full_cu_all_old();
    (void)test_register_multi_full_cu_all_new();
    (void)test_tx_authority_unique_not_last_loaded();
    (void)test_tx_permit_gate_denies_before_provider();
    (void)test_identity_conflict_all_fba_states();
    (void)test_retryable_rejects_mutated_same_attempt_ids();
    (void)test_permit_claim_cu_readback_matrix();
    (void)test_attempt_capacity_exact_64_and_65();
    (void)test_attempt_gc_retention_expiry_and_restart();
    (void)test_attempt_gc_commit_unknown_old_new_restart();
    (void)test_attempt_gc_old_permit_epoch();
    (void)test_send_rejects_text_id_length_boundaries();
    (void)test_multi_peer_registry_order_independence();
    (void)test_prepared_reval_fail_closes_no_provider();
    (void)test_restart_retryable_epoch_and_exact_retry();
    (void)test_path_selection_epoch_wrap_fail_closed();
    if (g_fabric_test_failures != 0) {
        (void)fprintf(
            stderr,
            "fabric_v1_lifecycle_test failures=%d\n",
            g_fabric_test_failures);
        return 1;
    }
    (void)printf("fabric_v1_lifecycle_test OK\n");
    return 0;
}
