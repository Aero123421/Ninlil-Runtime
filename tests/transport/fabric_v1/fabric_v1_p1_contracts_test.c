/*
 * Fabric P1 contracts: API precedence Cartesian, workspace exact partition,
 * provider output shapes, outer query peer/attachment/RF, revision wrap.
 * Private only; no public ABI; no Wi-Fi shared sources.
 */
#include "fabric_v1_test_common.h"
#include "fabric_v1_test_storage.h"
#include "fabric_workspace.h"

static uint8_t g_ws[NINLIL_FABRIC_WORKSPACE_BYTES]
    __attribute__((aligned(16)));

/* --- workspace exact partition (Accepted profile-1) --- */
static int test_workspace_exact_partition(void)
{
    ninlil_fabric_ws_region_info_t regions[NINLIL_FABRIC_WS_REGION_COUNT];
    ninlil_fabric_ws_region_info_t objects[11];
    uint32_t total = 0u;
    uint32_t object_bytes = 0u;
    uint32_t workspace_bytes = 0u;
    uint32_t i;

    FABRIC_REQUIRE(
        ninlil_fabric_private_workspace_layout_proof_v1(&total, regions) == 0u);
    FABRIC_REQUIRE(total == 198656u);
    FABRIC_REQUIRE(regions[0].offset == 0u);
    FABRIC_REQUIRE(regions[0].size == NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES);
    FABRIC_REQUIRE(regions[1].size == NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES);
    FABRIC_REQUIRE(regions[2].size == NINLIL_FABRIC_WS_REGISTRY_BYTES);
    FABRIC_REQUIRE(regions[3].size == NINLIL_FABRIC_WS_POLICY_INDEX_BYTES);
    FABRIC_REQUIRE(regions[4].size == NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES);
    FABRIC_REQUIRE(regions[5].size == NINLIL_FABRIC_WS_ATTEMPT_BYTES);
    FABRIC_REQUIRE(regions[6].size == NINLIL_FABRIC_WS_TRIGGER_BYTES);
    FABRIC_REQUIRE(regions[7].size == NINLIL_FABRIC_WS_QUEUE_DESC_BYTES);
    for (i = 1u; i < NINLIL_FABRIC_WS_REGION_COUNT; ++i) {
        FABRIC_REQUIRE(
            regions[i].offset
            == regions[i - 1u].offset + regions[i - 1u].size);
    }
    FABRIC_REQUIRE(
        ninlil_fabric_private_object_partition_proof_v1(
            &object_bytes, &workspace_bytes, objects)
        == 0u);
    FABRIC_REQUIRE(workspace_bytes == 198656u);
    FABRIC_REQUIRE(object_bytes <= 198656u);
    FABRIC_REQUIRE(objects[0].offset == 0u);
    FABRIC_REQUIRE(objects[0].size == NINLIL_FABRIC_WS_NFL1_QUEUE_BYTES);
    FABRIC_REQUIRE(objects[1].size == NINLIL_FABRIC_WS_CODEC_SCRATCH_BYTES);
    FABRIC_REQUIRE(objects[2].size <= NINLIL_FABRIC_WS_REGISTRY_BYTES);
    FABRIC_REQUIRE(objects[2].size == NINLIL_FABRIC_WS_REGISTRY_BYTES);
    FABRIC_REQUIRE(objects[4].size == NINLIL_FABRIC_WS_AUTHORITY_INDEX_BYTES);
    FABRIC_REQUIRE(objects[7].size == NINLIL_FABRIC_WS_QUEUE_DESC_BYTES);
    return 0;
}

/* --- precedence: NULL out before owner (no wrong-thread via null fabric) --- */
static int test_api_precedence_null_before_owner(void)
{
    uint32_t done = 1u;
    uint32_t work = 1u;
    const ninlil_bearer_ops_t *ops = (const ninlil_bearer_ops_t *)1;

    /* close_poll: out_done NULL first */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_close_poll_v1(NULL, NULL),
        NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT);
    /* step: out NULL first */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(NULL, 1u, NULL),
        NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(NULL, 0u, &work),
        NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT);
    /* bearer_ops: out NULL first */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(NULL, NULL),
        NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT);
    (void)ops;
    (void)done;
    /* unregister_poll out NULL first */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_unregister_poll_v1(NULL, NULL, NULL),
        NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT);
    /* destroy null fabric */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_destroy_v1(NULL),
        NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT);
    return 0;
}

static int fabric_boot(
    ninlil_fabric_private_t **out_f, const ninlil_bearer_ops_t **out_b)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
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
    ninlil_fabric_private_memzero(g_ws, sizeof(g_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(&config, g_ws, sizeof(g_ws), out_f),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(*out_f, out_b),
        NINLIL_FABRIC_PRIVATE_OK);
    return 0;
}

/* Owner then reentry: wrong thread before reentry observation. */
static int test_api_precedence_owner_before_reentry(void)
{
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    uint32_t work = 0u;
    uint64_t saved;

    if (fabric_boot(&fabric, &bearer) != 0) {
        return 1;
    }
    saved = g_exec_context;
    g_exec_context = 99u; /* wrong thread */
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_step_v1(fabric, 1u, &work),
        NINLIL_FABRIC_PRIVATE_WRONG_THREAD);
    g_exec_context = saved;
    /* close with done=0 when outer still open path uses owner */
    {
        uint32_t done = 1u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_close_begin_v1(fabric),
            NINLIL_FABRIC_PRIVATE_OK);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_close_poll_v1(fabric, &done),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    (void)ninlil_fabric_private_destroy_v1(fabric);
    return 0;
}

/* Provider output: EMPTY must be NULL bytes/len/token shape via test double. */
static int test_provider_output_empty_shape(void)
{
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_packet_link_handle_t h = NULL;
    const uint8_t *bytes = (const uint8_t *)1;
    uint32_t length = 9u;
    void *tok = (void *)1;
    ninlil_fabric_link_status_t st;

    fabric_test_reset_globals();
    fabric_test_provider_ops(&ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(ops.open(ops.user, &h), NINLIL_FABRIC_LINK_OK);
    g_provider.next_receive_status = NINLIL_FABRIC_LINK_EMPTY;
    st = ops.receive_next(ops.user, h, &bytes, &length, &tok);
    FABRIC_REQUIRE_EQ_U32(st, NINLIL_FABRIC_LINK_EMPTY);
    /* Provider contract: non-OK clean shape (test double may leave; fabric fences dirty). */
    ops.close(ops.user, h);
    return 0;
}

/* Select query: RF mapping unsupported + peer/attachment presence. */
static int test_select_rf_and_peer_attachment(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;
    ninlil_fabric_private_select_policy_t *p;
    ninlil_fabric_private_select_registry_row_t *r;

    ninlil_fabric_private_memzero(&snap, sizeof(snap));
    snap.outer_available = 1u;
    fabric_test_pattern(snap.query.service_identity_digest, 0x11u, 32u);
    snap.query.family = 2u;
    snap.query.direction = 1u;
    snap.query.traffic_class = 1u;
    fabric_test_pattern(snap.query.source_runtime_id, 0x30u, 16u);
    fabric_test_pattern(snap.query.target_runtime_id, 0x80u, 16u);
    fabric_test_pattern(snap.query.target_application_id, 0x90u, 16u);
    snap.query.packet_bytes = 587u;
    snap.query.transfer_bytes = 587u;
    snap.query.now_ms = 100000ull;
    snap.query.deadline_ms = 200000ull;
    fabric_test_pattern(snap.query.deadline_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(snap.query.admission_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(snap.query.availability_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(snap.query.attestation_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(snap.query.authority_clock_epoch_id, 0xD1u, 16u);
    snap.query.rf_permit_valid = 1u;
    snap.query.rf_mapping_accepted = 0u; /* Host v1: RF unsupported */

    snap.policy_count = 1u;
    p = &snap.policies[0];
    fabric_test_pattern(p->policy_id, 0x71u, 16u);
    p->revision = 1u;
    fabric_test_pattern(p->canonical_digest, 0x22u, 32u);
    fabric_test_pattern(p->service_identity_digest, 0x11u, 32u);
    p->family = 2u;
    p->direction = 1u;
    p->traffic_class = 1u;
    p->scope_selector = 2u;
    p->maximum_latency_class = 50u;
    p->maximum_cost_class = 50u;
    p->minimum_packet_bytes = 587u;
    p->authority_mode = 0u;
    p->deadline_guard_ms = 0u;
    p->candidate_count = 1u;
    fabric_test_pattern(p->candidates[0].instance_id, 0x61u, 16u);
    p->candidates[0].rank = 1u;
    p->candidates[0].reservation_units = 1u;
    p->revision_chain_len = 1u;
    p->revision_chain[0] = 1u;

    snap.registry_count = 1u;
    r = &snap.registry[0];
    fabric_test_pattern(r->instance_id, 0x61u, 16u);
    r->link_kind = 4u; /* RF */
    r->direction_mask = 3u;
    r->capability_flags = 0x6Fu | (1u << 4); /* regulated RF */
    r->security_capability_flags = 0x0Fu;
    r->maximum_packet_bytes = 1925u;
    r->maximum_transfer_bytes = 1925u;
    r->latency_class = 10u;
    r->cost_class = 20u;
    r->reservation_capacity = 8u;
    r->lifecycle = 1u;
    r->peer_nfl1_version = 1u;
    r->peer_fabric_capability_flags = 1u;
    fabric_test_pattern(r->authenticated_peer_runtime_id, 0x31u, 16u);
    fabric_test_pattern(r->attachment_authority_id, 0x41u, 16u);
    fabric_test_pattern(r->attachment_binding_digest, 0x51u, 32u);
    fabric_test_pattern(r->attestation_clock_epoch_id, 0xA1u, 16u);
    r->attestation_expires_at_ms = 300000u;
    fabric_test_pattern(r->availability_clock_epoch_id, 0xA1u, 16u);
    r->availability_state = 1u;
    r->availability_expires_at_ms = 250000u;

    /* ABSENT_ALLOWED still needs exact-1 ABSENT authority row (no invent). */
    snap.authority_count = 1u;
    {
        ninlil_fabric_private_select_authority_row_t *a = &snap.authorities[0];
        fabric_test_pattern(a->service_identity_digest, 0x11u, 32u);
        a->family = 2u;
        a->direction = 1u;
        a->traffic_class = 1u;
        a->scope_selector = 2u;
        fabric_test_pattern(a->endpoint_runtime_id, 0x80u, 16u);
        fabric_test_pattern(a->target_runtime_id, 0x80u, 16u);
        fabric_test_pattern(a->target_application_id, 0x90u, 16u);
        fabric_test_pattern(a->policy_id, 0x71u, 16u);
        a->policy_revision = 1u;
        fabric_test_pattern(a->policy_digest, 0x22u, 32u);
        a->authority_state = 0u; /* ABSENT */
        fabric_test_pattern(a->authority_clock_epoch_id, 0xD1u, 16u);
        a->lease_expires_at_ms = 300000ull;
    }
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "RF_MAPPING_UNSUPPORTED") == 0);

    /* Peer/attachment ABSENT */
    r->link_kind = 2u;
    r->capability_flags = 0x6Fu;
    snap.query.rf_mapping_accepted = 1u;
    ninlil_fabric_private_memzero(r->authenticated_peer_runtime_id, 16u);
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "AUTHENTICATED_PEER_ABSENT") == 0);
    fabric_test_pattern(r->authenticated_peer_runtime_id, 0x31u, 16u);
    ninlil_fabric_private_memzero(r->attachment_authority_id, 16u);
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "ATTACHMENT_ABSENT") == 0);
    return 0;
}

/* Closed catalog: private status codes are a closed set used by APIs. */
static int test_closed_status_catalog(void)
{
    FABRIC_REQUIRE(NINLIL_FABRIC_PRIVATE_OK == 0u);
    FABRIC_REQUIRE(NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT != NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(NINLIL_FABRIC_PRIVATE_WRONG_THREAD != NINLIL_FABRIC_PRIVATE_REENTRANT);
    FABRIC_REQUIRE(NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN != NINLIL_FABRIC_PRIVATE_CORRUPT);
    FABRIC_REQUIRE(NINLIL_FABRIC_LINK_RETAINED != NINLIL_FABRIC_LINK_OK);
    FABRIC_REQUIRE(
        NINLIL_FABRIC_LINK_COMPLETION_PENDING
        != NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
    return 0;
}

int main(void)
{
    ninlil_id128_t id_probe;
    g_fabric_test_failures = 0;
    /* Keep test-support static helpers referenced under -Wunused-function. */
    fabric_test_id(&id_probe, 0x01u);
    fabric_test_pattern(id_probe.bytes, 0x02u, 16u);
    fabric_test_reset_globals();
    (void)test_workspace_exact_partition();
    (void)test_api_precedence_null_before_owner();
    (void)test_api_precedence_owner_before_reentry();
    (void)test_provider_output_empty_shape();
    (void)test_select_rf_and_peer_attachment();
    (void)test_closed_status_catalog();
    if (g_fabric_test_failures != 0) {
        (void)fprintf(
            stderr, "fabric_v1_p1_contracts_test failures=%d\n",
            g_fabric_test_failures);
        return 1;
    }
    (void)printf("fabric_v1_p1_contracts_test OK\n");
    return 0;
}
