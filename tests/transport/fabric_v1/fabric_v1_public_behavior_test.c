/* Public-wrapper ownership, re-entry and close observability. */
#include <ninlil/fabric_v1.h>

#include "fabric_v1_test_storage.h"

static _Alignas(16)
    uint8_t g_public_workspace[NINLIL_FABRIC_WORKSPACE_BYTES];
static ninlil_fabric_v1_t *g_reentry_fabric;
static ninlil_fabric_status_t g_reentry_status;
static uint32_t g_reentry_no_effect;

static ninlil_fabric_link_status_t reentry_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    const uint32_t begin_before = g_store.begin_calls;
    const uint32_t put_before = g_store.put_calls;
    const uint32_t commit_before = g_store.commit_calls;
    const uint32_t start_before = g_provider.start_calls;
    const uint32_t receive_before = g_provider.receive_calls;
    uint32_t work = UINT32_MAX;

    g_reentry_status = ninlil_fabric_v1_step(g_reentry_fabric, 1u, &work);
    g_reentry_no_effect =
        work == 0u && g_store.begin_calls == begin_before
        && g_store.put_calls == put_before
        && g_store.commit_calls == commit_before
        && g_provider.start_calls == start_before
        && g_provider.receive_calls == receive_before;
    return test_link_open(user, out_handle);
}

static void fill_descriptor(ninlil_fabric_link_descriptor_v1_t *descriptor)
{
    ninlil_fabric_private_memzero(descriptor, sizeof(*descriptor));
    descriptor->api_version = NINLIL_FABRIC_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    fabric_test_id(&descriptor->instance_id, 0x61u);
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_LOOPBACK;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_UNICAST
        | NINLIL_FABRIC_CAP_RESERVATION | NINLIL_FABRIC_CAP_CUSTODY
        | NINLIL_FABRIC_CAP_EVIDENCE;
    descriptor->descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"public-behavior-descriptor",
        sizeof("public-behavior-descriptor") - 1u,
        descriptor->descriptor_digest);
    fabric_test_id(&descriptor->security_profile_id, 0x31u);
    descriptor->security_capability_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"public-behavior-security",
        sizeof("public-behavior-security") - 1u,
        descriptor->security_binding_digest);
    descriptor->attestation_epoch = 1u;
    fabric_test_id(&descriptor->attestation_clock_epoch_id, 0xA1u);
    descriptor->attestation_expires_at_ms = 250000u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"public-behavior-attestation",
        sizeof("public-behavior-attestation") - 1u,
        descriptor->attestation_digest);
    fabric_test_id(&descriptor->authenticated_peer_runtime_id, 0x41u);
    fabric_test_id(&descriptor->attachment_authority_id, 0x51u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"public-behavior-attachment",
        sizeof("public-behavior-attachment") - 1u,
        descriptor->attachment_binding_digest);
    descriptor->maximum_packet_bytes = 1925u;
    descriptor->maximum_transfer_bytes = 1925u;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->reservation_capacity = 8u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"public-behavior-configuration",
        sizeof("public-behavior-configuration") - 1u,
        descriptor->configuration_digest);
}

static int test_public_ownership_reentry_close(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_fabric_link_registration_v1_t *registration = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    uint32_t done = 0u;
    uint32_t work = 0u;
    uint32_t spins;
    uint32_t begin_before;
    uint32_t put_before;
    uint32_t commit_before;
    uint32_t open_before;
    uint32_t close_after;
    uint32_t state_after;

    fabric_test_reset_globals();
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&execution, sizeof(execution));
    execution.abi_version = NINLIL_ABI_VERSION;
    execution.struct_size = (uint16_t)sizeof(execution);
    execution.current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &execution;
    ninlil_fabric_private_memzero(
        g_public_workspace, sizeof(g_public_workspace));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_v1_create(
            &config,
            g_public_workspace,
            sizeof(g_public_workspace),
            &g_reentry_fabric),
        NINLIL_FABRIC_OK);

    begin_before = g_store.begin_calls;
    put_before = g_store.put_calls;
    commit_before = g_store.commit_calls;
    open_before = g_provider.open_calls;
    g_exec_context = 2u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_v1_bearer_ops(g_reentry_fabric, &bearer),
        NINLIL_FABRIC_WRONG_THREAD);
    FABRIC_REQUIRE(bearer == NULL);
    FABRIC_REQUIRE(g_store.begin_calls == begin_before);
    FABRIC_REQUIRE(g_store.put_calls == put_before);
    FABRIC_REQUIRE(g_store.commit_calls == commit_before);
    FABRIC_REQUIRE(g_provider.open_calls == open_before);

    g_exec_context = 1u;
    fill_descriptor(&descriptor);
    descriptor.link_kind = NINLIL_FABRIC_LINK_KIND_RF;
    descriptor.capability_flags |= NINLIL_FABRIC_CAP_REGULATED_RF;
    fabric_test_provider_ops(&link_ops, &g_provider);
    link_ops.open = reentry_open;
    g_reentry_status = NINLIL_FABRIC_OK;
    g_reentry_no_effect = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_v1_register_link(
            g_reentry_fabric, &descriptor, &link_ops, &registration),
        NINLIL_FABRIC_OK);
    FABRIC_REQUIRE(registration != NULL);
    FABRIC_REQUIRE_EQ_U32(g_reentry_status, NINLIL_FABRIC_REENTRANT);
    FABRIC_REQUIRE(g_reentry_no_effect == 1u);

    /* Public RF registration alone never enables provider receive I/O. */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_v1_step(g_reentry_fabric, 8u, &work),
        NINLIL_FABRIC_OK);
    FABRIC_REQUIRE(work == 0u);
    FABRIC_REQUIRE(g_provider.receive_calls == 0u);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_v1_close_begin(g_reentry_fabric),
        NINLIL_FABRIC_OK);
    for (spins = 0u; spins < 32u && done == 0u; ++spins) {
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_v1_step(g_reentry_fabric, 8u, &work),
            NINLIL_FABRIC_OK);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_v1_close_poll(g_reentry_fabric, &done),
            NINLIL_FABRIC_OK);
    }
    FABRIC_REQUIRE(done == 1u);
    FABRIC_REQUIRE(spins <= 32u);
    close_after = g_provider.close_calls;
    state_after = g_provider.receive_calls;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_v1_step(g_reentry_fabric, 8u, &work),
        NINLIL_FABRIC_OK);
    FABRIC_REQUIRE(work == 0u);
    FABRIC_REQUIRE(g_provider.close_calls == close_after);
    FABRIC_REQUIRE(g_provider.receive_calls == state_after);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_v1_destroy(g_reentry_fabric), NINLIL_FABRIC_OK);
    g_reentry_fabric = NULL;
    return 0;
}

int main(void)
{
    const int result = test_public_ownership_reentry_close();
    if (result == 0) {
        (void)printf("fabric_v1_public_behavior_test: PASS\n");
    }
    return result;
}
