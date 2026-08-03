#include "deterministic_entropy.h"
#include "fake_byte_stream.h"
#include "in_memory_storage.h"
#include "n6_context_store.h"
#include "n6_crypto_provider.h"
#include "nfl1_codec.h"
#include "pcp_authority.h"
#include "platform_basic_fixtures.h"
#include "r7_crypto_openssl3.h"
#include "r7_frag_issue_coordinator.h"
#include "radio_hal.h"
#include "sx1262_bus_spy.h"
#include "sx1262_r9_edge.h"
#include "v1_lab_binding.h"
#include "v1_lab_board_owner.h"
#include "v1_lab_n6_owner.h"
#include "v1_lab_peer_runtime.h"
#include "v1_lab_provisioner.h"
#include "v1_lab_radio_packet_link.h"
#include "v1_usb_bridge.h"

#include "ninlil/fabric_v1.h"
#include "ninlil/version.h"
#include "ninlil_sx1262_backend.h"
#include "ninlil_sx1262_phy.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                   \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "vertical failure %s:%d: %s\n",         \
                __FILE__, __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

#define TEST_CONTEXT_SLOTS ((uint32_t)8u)
#define TEST_N6_POOL_BYTES ((size_t)4096u)
#define TEST_POLL_LIMIT ((uint32_t)12u)

#if !defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    || (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING == 0)
#define TEST_PEER_RUNTIME_ENABLED 1
#else
#define TEST_PEER_RUNTIME_ENABLED 0
#endif

typedef struct test_pcp {
    ninlil_pcp_object_t object;
    ninlil_pcp_t *pcp;
    ninlil_test_storage_t *storage;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_pcp_live_profile_t live;
} test_pcp_t;

typedef struct test_node {
    _Alignas(NINLIL_N6_OBJECT_ALIGN) uint8_t
        n6_object[NINLIL_N6_OBJECT_BYTES];
    uint8_t n6_pool[TEST_N6_POOL_BYTES];
    ninlil_n6_t *n6;
    ninlil_test_storage_t *n6_storage;
    ninlil_v1_lab_n6_owner_t n6_owner;
    ninlil_v1_lab_n6_handles_t n6_handles;

    ninlil_sx1262_bus_spy_t bus;
    ninlil_sx1262_backend_object_t backend_object;
    ninlil_sx1262_backend_t *backend;
    ninlil_sx1262_phy_object_t phy_object;
    ninlil_sx1262_phy_t *phy;
    ninlil_sx1262_rf_profile_t rf_profile;
    ninlil_sx1262_r9_edge_object_t edge_object;
    ninlil_sx1262_r9_edge_t *edge;
    const ninlil_radio_hal_edge_ops_t *edge_ops;
    void *edge_context;
    ninlil_radio_hal_object_t hal_object;
    ninlil_radio_hal_t *hal;

    ninlil_r7_frag_prod_bind_t a_to_b;
    ninlil_r7_frag_prod_bind_t b_to_a;
    ninlil_v1_lab_radio_packet_link_t packet_link;
    uint8_t pair_slot;
} test_node_t;

#if TEST_PEER_RUNTIME_ENABLED
typedef struct test_peer_runtime {
    ninlil_v1_lab_peer_runtime_t runtime;
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage;
    ninlil_platform_ops_t platform;
    ninlil_service_callbacks_t callbacks;
    void *workspace;
    uint32_t workspace_bytes;
    uint32_t workspace_alignment;
    uint32_t prepared;
    uint32_t delivery_count;
} test_peer_runtime_t;
#endif

static test_node_t g_node_a;
static test_node_t g_node_b;
static ninlil_v1_lab_board_owner_t g_board_owner;
static ninlil_v1_lab_provisioner_t g_board_provisioner;
static const ninlil_r7_crypto_provider *g_crypto;

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

#if TEST_PEER_RUNTIME_ENABLED
static ninlil_callback_action_t peer_runtime_delivery(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    test_peer_runtime_t *fixture = (test_peer_runtime_t *)user;

    (void)token;
    if (fixture == NULL || delivery == NULL || out_result == NULL
        || delivery->payload.data == NULL || delivery->payload.length == 0u) {
        return NINLIL_CALLBACK_FATAL;
    }
    fixture->delivery_count += 1u;
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->abi_version = NINLIL_ABI_VERSION;
    out_result->struct_size = (uint16_t)sizeof(*out_result);
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t peer_runtime_reconcile(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    if (delivery == NULL || out_result == NULL) {
        return NINLIL_RECONCILE_OUTCOME_UNKNOWN;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->abi_version = NINLIL_ABI_VERSION;
    out_result->struct_size = (uint16_t)sizeof(*out_result);
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    return NINLIL_RECONCILE_KNOWN_RESULT;
}

static int setup_peer_runtime(
    test_peer_runtime_t *fixture,
    test_pcp_t *pcp)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_v1_lab_peer_runtime_config_t runtime_config;
    ninlil_tx_gate_ops_t unexpected_tx_gate;
    const ninlil_allocator_ops_t *allocator_ops;

    (void)memset(fixture, 0, sizeof(*fixture));
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 8u;
    storage_config.max_entries_per_namespace = 256u;
    storage_config.max_bytes_per_namespace = UINT64_C(1048576);
    fixture->allocator = ninlil_test_allocator_create();
    fixture->execution = ninlil_test_execution_create(1u);
    fixture->entropy = ninlil_test_entropy_create(0x726f6c65u, 3u);
    fixture->storage = ninlil_test_storage_create(&storage_config);
    if (fixture->allocator == NULL || fixture->execution == NULL
        || fixture->entropy == NULL || fixture->storage == NULL
        || ninlil_composition_v1_workspace_required(
               NINLIL_COMPOSITION_PROFILE_1,
               &fixture->workspace_bytes,
               &fixture->workspace_alignment)
            != NINLIL_OK) {
        return 1;
    }
    allocator_ops = ninlil_test_allocator_ops(fixture->allocator);
    fixture->workspace = allocator_ops->allocate(allocator_ops->user,
        fixture->workspace_bytes, fixture->workspace_alignment);
    if (fixture->workspace == NULL) {
        return 1;
    }
    fixture->platform.abi_version = NINLIL_ABI_VERSION;
    fixture->platform.struct_size = (uint16_t)sizeof(fixture->platform);
    fixture->platform.allocator = allocator_ops;
    fixture->platform.execution =
        ninlil_test_execution_ops(fixture->execution);
    fixture->platform.clock = ninlil_test_clock_ops(pcp->clock);
    fixture->platform.entropy = ninlil_test_entropy_ops(fixture->entropy);
    fixture->platform.storage = ninlil_test_storage_ops(fixture->storage);
    fixture->callbacks.abi_version = NINLIL_ABI_VERSION;
    fixture->callbacks.struct_size = (uint16_t)sizeof(fixture->callbacks);
    fixture->callbacks.user = fixture;
    fixture->callbacks.on_delivery = peer_runtime_delivery;
    fixture->callbacks.on_reconcile = peer_runtime_reconcile;
    (void)memset(&runtime_config, 0, sizeof(runtime_config));
    runtime_config.crypto = g_crypto;
    runtime_config.platform_template = &fixture->platform;
    runtime_config.composition_workspace = fixture->workspace;
    runtime_config.composition_workspace_bytes = fixture->workspace_bytes;
    runtime_config.desired_callbacks = &fixture->callbacks;
    (void)memset(&unexpected_tx_gate, 0, sizeof(unexpected_tx_gate));
    fixture->platform.tx_gate = &unexpected_tx_gate;
    if (ninlil_v1_lab_peer_runtime_prepare(
            &fixture->runtime, &runtime_config)
        != NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT) {
        return 1;
    }
    fixture->platform.tx_gate = NULL;
    if (ninlil_v1_lab_peer_runtime_prepare(
            &fixture->runtime, &runtime_config)
        != NINLIL_V1_LAB_PEER_RUNTIME_OK) {
        return 1;
    }
    fixture->prepared = 1u;
    return 0;
}

static int teardown_peer_runtime(test_peer_runtime_t *fixture)
{
    const ninlil_allocator_ops_t *allocator_ops = NULL;

    if (fixture->prepared != 0u
        && ninlil_v1_lab_peer_runtime_clear(&fixture->runtime)
            != NINLIL_V1_LAB_PEER_RUNTIME_OK) {
        return 1;
    }
    if (fixture->allocator != NULL) {
        allocator_ops = ninlil_test_allocator_ops(fixture->allocator);
    }
    if (allocator_ops != NULL && fixture->workspace != NULL) {
        allocator_ops->deallocate(allocator_ops->user, fixture->workspace,
            fixture->workspace_bytes, fixture->workspace_alignment);
    }
    if (fixture->storage != NULL) {
        ninlil_test_storage_destroy(fixture->storage);
    }
    if (fixture->entropy != NULL) {
        ninlil_test_entropy_destroy(fixture->entropy);
    }
    if (fixture->execution != NULL) {
        ninlil_test_execution_destroy(fixture->execution);
    }
    if (fixture->allocator != NULL
        && ninlil_test_allocator_destroy(fixture->allocator) != 0u) {
        return 1;
    }
    (void)memset(fixture, 0, sizeof(*fixture));
    return 0;
}
#endif

static void fill_epoch(uint8_t out[16])
{
    (void)memset(out, 0, 16u);
    out[0] = 0xa0u;
    out[15] = 0x01u;
}

static void fill_endpoint(ninlil_v1_lab_endpoint_t *endpoint, uint8_t seed)
{
    (void)memset(endpoint, 0, sizeof(*endpoint));
    fill_bytes(endpoint->runtime_id, 16u, seed);
    fill_bytes(endpoint->application_id, 16u, (uint8_t)(seed + 0x10u));
    fill_bytes(endpoint->device_id, 16u, (uint8_t)(seed + 0x20u));
    fill_bytes(endpoint->installation_id, 16u, (uint8_t)(seed + 0x30u));
    fill_bytes(endpoint->site_id, 16u, (uint8_t)(seed + 0x40u));
    endpoint->binding_epoch = 4u;
    endpoint->membership_epoch = 9u;
    endpoint->identity_flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    fill_epoch(endpoint->clock_epoch_id);
    endpoint->clock_trust = NINLIL_CLOCK_TRUSTED;
}

static void fill_service(
    ninlil_v1_lab_service_row_t *row,
    uint8_t slot,
    uint8_t flow,
    uint32_t family,
    uint8_t seed)
{
    (void)memset(row, 0, sizeof(*row));
    row->slot = slot;
    row->flow = flow;
    row->namespace_length = 3u;
    row->service_length = 4u;
    row->schema_length = 2u;
    row->descriptor_revision = (uint64_t)(20u + slot);
    fill_bytes(row->descriptor_digest, 32u, seed);
    row->schema_major = 1u;
    row->family = family;
    row->direction = family == NINLIL_FAMILY_DESIRED_STATE
        ? NINLIL_DIRECTION_DOWNLINK
        : NINLIL_DIRECTION_UPLINK;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    row->evidence_grace_ms = family == NINLIL_FAMILY_DESIRED_STATE ? 500u : 0u;
    (void)memcpy(row->namespace_id, "lab", 3u);
    (void)memcpy(row->service_id, "svc0", 4u);
    row->service_id[3] = (uint8_t)('0' + slot);
    (void)memcpy(row->schema_id, "v1", 2u);
}

static int make_binding(
    const ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *binding,
    uint8_t encoded[NINLIL_V1_LAB_BINDING_MAX_BYTES],
    size_t *encoded_length)
{
    (void)memset(binding, 0, sizeof(*binding));
    binding->service_count = 3u;
    binding->pair_generation = 7u;
    fill_endpoint(&binding->endpoint_a, 0x10u);
    fill_endpoint(&binding->endpoint_b, 0x30u);
    fill_bytes(binding->radio_site_domain_id, 16u, 0x90u);
    binding->radio_membership_epoch = 11u;
    /* Fresh N6 receiver namespaces each start at context ID one. */
    binding->a_to_b_hop_context_id = 1u;
    binding->a_to_b_e2e_context_id = 1u;
    binding->b_to_a_hop_context_id = 1u;
    binding->b_to_a_e2e_context_id = 1u;
    fill_bytes(binding->a_to_b_hop_secret, 32u, 0xa0u);
    fill_bytes(binding->a_to_b_e2e_secret, 32u, 0xb0u);
    fill_bytes(binding->b_to_a_hop_secret, 32u, 0xc0u);
    fill_bytes(binding->b_to_a_e2e_secret, 32u, 0xd0u);
    fill_service(&binding->services[0], 1u, NINLIL_V1_LAB_FLOW_A_TO_B,
        NINLIL_FAMILY_DESIRED_STATE, 0x70u);
    fill_service(&binding->services[1], 2u, NINLIL_V1_LAB_FLOW_B_TO_A,
        NINLIL_FAMILY_EVENT_FACT, 0x80u);
    fill_service(&binding->services[2], 3u, NINLIL_V1_LAB_FLOW_A_TO_B,
        NINLIL_FAMILY_DESIRED_STATE, 0x90u);
    return ninlil_v1_lab_binding_finalize(crypto, binding)
                == NINLIL_V1_LAB_BINDING_OK
            && ninlil_v1_lab_binding_encode(crypto, binding, encoded,
                   NINLIL_V1_LAB_BINDING_MAX_BYTES, encoded_length)
                == NINLIL_V1_LAB_BINDING_OK
        ? 0
        : 1;
}

static void set_source(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->source_runtime_id.bytes, endpoint->runtime_id, 16u);
    (void)memcpy(envelope->source_application_id.bytes,
        endpoint->application_id, 16u);
    (void)memcpy(envelope->source_device_id.bytes, endpoint->device_id, 16u);
    (void)memcpy(envelope->source_installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(envelope->source_site_id.bytes, endpoint->site_id, 16u);
    envelope->source_binding_epoch = endpoint->binding_epoch;
    envelope->source_membership_epoch = endpoint->membership_epoch;
    envelope->source_flags = endpoint->identity_flags;
}

static void set_target(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->target_runtime_id.bytes, endpoint->runtime_id, 16u);
    (void)memcpy(envelope->target_application_id.bytes,
        endpoint->application_id, 16u);
    (void)memcpy(envelope->target_device_id.bytes, endpoint->device_id, 16u);
    (void)memcpy(envelope->target_installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(envelope->target_site_id.bytes, endpoint->site_id, 16u);
    envelope->target_binding_epoch = endpoint->binding_epoch;
    envelope->target_membership_epoch = endpoint->membership_epoch;
    envelope->target_flags = endpoint->identity_flags;
}

static int make_application(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t *out,
    uint32_t *out_length)
{
    const ninlil_v1_lab_service_row_t *row = &binding->services[0];
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint8_t payload[32];
    uint8_t digest[32];

    fill_bytes(payload, sizeof(payload), 0x41u);
    (void)memset(&envelope, 0, sizeof(envelope));
    envelope.api_version = NINLIL_ABI_VERSION;
    envelope.struct_size = (uint16_t)sizeof(envelope);
    envelope.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    fill_bytes(envelope.transaction_id.bytes, 16u, 0x01u);
    fill_bytes(envelope.attempt_id.bytes, 16u, 0x21u);
    set_source(&envelope, &binding->endpoint_a);
    set_target(&envelope, &binding->endpoint_b);
    (void)memcpy(
        envelope.authority_id.bytes, binding->endpoint_a.runtime_id, 16u);
    envelope.authority_term = binding->pair_generation;
    envelope.assignment_epoch = (uint32_t)binding->pair_generation;
    envelope.descriptor_revision = row->descriptor_revision;
    envelope.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(
        envelope.descriptor_digest.bytes, row->descriptor_digest, 32u);
    envelope.schema_major = row->schema_major;
    envelope.schema_minor = row->schema_minor;
    envelope.family = row->family;
    envelope.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    if (ninlil_r7_crypto_sha256(
            crypto, payload, sizeof(payload), digest)
        != NINLIL_R7_CRYPTO_OK) {
        return 1;
    }
    (void)memcpy(envelope.content_digest.bytes, digest, 32u);
    envelope.generation = 42u;
    (void)memcpy(envelope.deadline_clock_epoch_id.bytes,
        binding->endpoint_a.clock_epoch_id, 16u);
    envelope.absolute_effect_deadline_ms = 10000u;
    envelope.evidence_grace_ms = row->evidence_grace_ms;
    envelope.required_evidence = NINLIL_EVIDENCE_APPLIED;
    (void)memcpy(envelope.route_policy_id.bytes, row->policy_id, 16u);
    envelope.route_policy_revision = binding->pair_generation;
    envelope.route_policy_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(envelope.route_policy_digest.bytes,
        row->path_policy_digest, 32u);
    (void)memcpy(
        envelope.selected_path_id.bytes, row->selected_path_id, 16u);
    envelope.path_selection_epoch = 77u;
    envelope.namespace_id.bytes = row->namespace_id;
    envelope.namespace_id.length = row->namespace_length;
    envelope.service_id.bytes = row->service_id;
    envelope.service_id.length = row->service_length;
    envelope.schema_id.bytes = row->schema_id;
    envelope.schema_id.length = row->schema_length;
    envelope.payload.bytes = payload;
    envelope.payload.length = (uint32_t)sizeof(payload);
    return ninlil_fabric_private_nfl1_encode(&envelope, out,
               NINLIL_V1_LAB_RADIO_NFL1_MAX, out_length)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
        ? 0
        : 1;
}

static int make_receipt(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *application,
    uint32_t application_length,
    uint8_t *out,
    uint32_t *out_length)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    if (ninlil_fabric_private_nfl1_decode(application, application_length,
            &workspace, &envelope, &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return 1;
    }
    envelope.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    set_source(&envelope, &binding->endpoint_b);
    set_target(&envelope, &binding->endpoint_a);
    envelope.receipt_stage = NINLIL_EVIDENCE_APPLIED;
    envelope.payload.bytes = NULL;
    envelope.payload.length = 0u;
    (void)memcpy(envelope.evidence_time_clock_epoch_id.bytes,
        binding->endpoint_b.clock_epoch_id, 16u);
    envelope.evidence_time_now_ms = 1600u;
    envelope.evidence_time_trust = NINLIL_CLOCK_TRUSTED;
    envelope.path_selection_epoch = 91u;
    return ninlil_fabric_private_nfl1_encode(&envelope, out,
               NINLIL_V1_LAB_RADIO_NFL1_MAX, out_length)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
        ? 0
        : 1;
}

static void fill_radio_id(ninlil_radio_hal_id_t *id, uint8_t seed)
{
    fill_bytes(id->bytes, sizeof(id->bytes), seed);
}

static void fill_live(ninlil_pcp_live_profile_t *live)
{
    (void)memset(live, 0, sizeof(*live));
    fill_radio_id(&live->hardware_profile_id, 0x10u);
    live->hardware_profile_rev = 1u;
    fill_radio_id(&live->regulatory_profile_id, 0x20u);
    live->regulatory_profile_rev = 1u;
    fill_radio_id(&live->site_assignment_id, 0x30u);
    live->site_assignment_rev = 1u;
    live->site_assignment_epoch = 7u;
    fill_radio_id(&live->transmitter_id, 0x40u);
    live->channel_id = 2u;
    live->phy.bandwidth_hz = 125000u;
    live->phy.spreading_factor = 7u;
    live->phy.coding_rate_denom = 5u;
    live->phy.preamble_symbols = 8u;
    live->phy.tx_power_mdb = 10000;
    live->max_airtime_us = 2000000u;
}

static int setup_pcp(test_pcp_t *pcp)
{
    ninlil_test_storage_config_t config;
    ninlil_pcp_instance_seed_t seed;
    ninlil_pcp_error_t error;

    (void)memset(pcp, 0, sizeof(*pcp));
    pcp->object = (ninlil_pcp_object_t)NINLIL_PCP_OBJECT_INIT;
    REQUIRE(ninlil_pcp_init_object(&pcp->object, &pcp->pcp)
        == NINLIL_PCP_OK);
    (void)memset(&config, 0, sizeof(config));
    config.max_namespaces = 8u;
    config.max_entries_per_namespace = 128u;
    config.max_bytes_per_namespace = 131072u;
    pcp->storage = ninlil_test_storage_create(&config);
    pcp->clock = ninlil_test_clock_create();
    pcp->entropy = ninlil_test_entropy_create(0xc0ffeeu, 1u);
    REQUIRE(pcp->storage != NULL && pcp->clock != NULL
        && pcp->entropy != NULL);
    REQUIRE(ninlil_test_clock_advance(pcp->clock, 1000u) == 1);
    REQUIRE(ninlil_pcp_bind_storage(pcp->pcp,
                ninlil_test_storage_ops(pcp->storage), &error)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_pcp_bind_clock(
                pcp->pcp, ninlil_test_clock_ops(pcp->clock), &error)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_pcp_bind_entropy(pcp->pcp,
                ninlil_test_entropy_ops(pcp->entropy), &error)
        == NINLIL_PCP_OK);
    fill_live(&pcp->live);
    REQUIRE(ninlil_pcp_bind_live_profile(pcp->pcp, &pcp->live, &error)
        == NINLIL_PCP_OK);
    fill_bytes(seed.bytes, sizeof(seed.bytes), 0x50u);
    REQUIRE(ninlil_pcp_publish_initial_meta(pcp->pcp, &seed, &error)
        == NINLIL_PCP_OK);
    return 0;
}

static ninlil_radio_hal_status_t verify_digest(
    void *user,
    const ninlil_radio_hal_frame_view_t *frame,
    const uint8_t digest[NINLIL_RADIO_HAL_DIGEST_BYTES],
    uint32_t digest_algorithm,
    ninlil_radio_hal_error_t *out_error)
{
    uint8_t computed[32];
    (void)user;
    if (frame == NULL || frame->bytes == NULL || frame->length == 0u
        || digest == NULL || digest_algorithm != NINLIL_DIGEST_SHA256
        || g_crypto == NULL
        || ninlil_r7_crypto_sha256(
               g_crypto, frame->bytes, frame->length, computed)
            != NINLIL_R7_CRYPTO_OK
        || memcmp(computed, digest, sizeof(computed)) != 0) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH;
        }
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_RADIO_HAL_OK;
}

static const ninlil_radio_hal_digest_ops_t g_digest_ops = {
    verify_digest,
};

static void fill_board(ninlil_sx1262_board_config_t *board)
{
    (void)memset(board, 0, sizeof(*board));
    board->abi_version = NINLIL_SX1262_ABI_VERSION;
    board->struct_size = (uint16_t)sizeof(*board);
    board->pin_nss = 1001u;
    board->pin_sck = 1002u;
    board->pin_mosi = 1003u;
    board->pin_miso = 1004u;
    board->pin_reset = 1005u;
    board->pin_busy = 1006u;
    board->pin_dio1 = 1007u;
    board->pin_ant_sw = NINLIL_SX1262_PIN_UNSET;
    board->reset_pulse_us = 1000u;
    board->busy_timeout_ms = 50u;
    board->spi_busy_timeout_ms = 50u;
    board->post_spi_busy_guard_us = 1u;
    board->busy_poll_interval_us = 100u;
    board->busy_poll_slack = 2u;
    board->regulator_mode = NINLIL_SX1262_REG_MODE_LDO;
}

static int setup_radio(test_node_t *node, test_pcp_t *pcp)
{
    ninlil_sx1262_board_config_t board;
    ninlil_sx1262_bus_ops_t bus_ops;
    ninlil_sx1262_error_t sx_error;
    ninlil_radio_hal_error_t hal_error;
    ninlil_radio_hal_permit_ops_t permit_ops;

    ninlil_sx1262_bus_spy_init(&node->bus);
    node->bus.now_ms = 1000u;
    fill_board(&board);
    bus_ops = *ninlil_sx1262_bus_spy_ops();
    node->backend_object =
        (ninlil_sx1262_backend_object_t)NINLIL_SX1262_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_init(&node->backend_object, &board, &bus_ops,
                &node->bus, &node->backend, &sx_error)
        == NINLIL_SX1262_OK);
    ninlil_sx1262_rf_profile_lab_default(&node->rf_profile);
    node->phy_object =
        (ninlil_sx1262_phy_object_t)NINLIL_SX1262_PHY_OBJECT_INIT;
    REQUIRE(ninlil_sx1262_phy_init(&node->phy_object, node->backend,
                &node->rf_profile, NULL, NULL, &node->phy, &sx_error)
        == NINLIL_SX1262_OK);
    node->edge_object = (ninlil_sx1262_r9_edge_object_t){0};
    REQUIRE(ninlil_sx1262_r9_edge_init(&node->edge_object, node->phy,
                &node->rf_profile, &node->edge, &node->edge_ops,
                &node->edge_context, &hal_error)
        == NINLIL_RADIO_HAL_OK);
    node->hal_object = (ninlil_radio_hal_object_t)NINLIL_RADIO_HAL_OBJECT_INIT;
    REQUIRE(ninlil_radio_hal_init_object(&node->hal_object, &node->hal)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_radio_hal_bind_edge(
                node->hal, node->edge_ops, node->edge_context, &hal_error)
        == NINLIL_RADIO_HAL_OK);
    ninlil_pcp_permit_ops(&permit_ops);
    REQUIRE(ninlil_radio_hal_bind_permit_ops(
                node->hal, &permit_ops, pcp->pcp, &hal_error)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_radio_hal_bind_digest_ops(
                node->hal, &g_digest_ops, NULL, &hal_error)
        == NINLIL_RADIO_HAL_OK);
    REQUIRE(ninlil_radio_hal_set_live_binding(
                node->hal, &pcp->live, &hal_error)
        == NINLIL_RADIO_HAL_OK);
    return 0;
}

static void fill_class_d(
    ninlil_r2_authority_clock_result_t *sample,
    const uint8_t epoch[16])
{
    (void)memset(sample, 0, sizeof(*sample));
    sample->typed_class = NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH;
    (void)memcpy(sample->sample_epoch_id, epoch, 16u);
    sample->sample_now_ms = 1000u;
    sample->sample_trust = NINLIL_CLOCK_TRUSTED;
    sample->sample_fields_valid = 1u;
    sample->result_catalog = NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP;
    sample->exact_status = NINLIL_PCP_OK;
}

static void bind_r7(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_n6_t *n6,
    ninlil_n6_handle_t hop_handle,
    ninlil_n6_handle_t e2e_handle,
    test_node_t *node,
    test_pcp_t *pcp,
    int outbound)
{
    ninlil_r7_frag_prod_bind_reset(bind);
    bind->n6 = n6;
    bind->hop_data_handle = hop_handle;
    bind->e2e_handle = e2e_handle;
    bind->hop_data_context_id = 1u;
    bind->e2e_context_id_pin = 1u;
    bind->crypto = g_crypto;
    bind->epoch_id_lo = 1u;
    if (outbound != 0) {
        bind->pcp = pcp->pcp;
        bind->hal = node->hal;
        (void)ninlil_r7_frag_prod_set_live(bind, &pcp->live);
    }
}

static int setup_node(
    test_node_t *node,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    uint8_t local_side,
    test_pcp_t *pcp)
{
    ninlil_test_storage_config_t config;
    ninlil_n6_context_pool_t pool;
    ninlil_r2_authority_clock_result_t sample;
    const ninlil_v1_lab_endpoint_t *local = local_side == NINLIL_V1_LAB_SIDE_A
        ? &binding->endpoint_a
        : &binding->endpoint_b;
    int a_to_b_outbound = local_side == NINLIL_V1_LAB_SIDE_A;

    (void)memset(node, 0, sizeof(*node));
    (void)memset(&config, 0, sizeof(config));
    config.max_namespaces = 8u;
    config.max_entries_per_namespace = 128u;
    config.max_bytes_per_namespace = 262144u;
    node->n6_storage = ninlil_test_storage_create(&config);
    REQUIRE(node->n6_storage != NULL);
    (void)memset(&pool, 0, sizeof(pool));
    pool.max_slots = TEST_CONTEXT_SLOTS;
    pool.bytes = node->n6_pool;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    REQUIRE(pool.bytes_size <= sizeof(node->n6_pool));
    REQUIRE(ninlil_n6_init(node->n6_object, sizeof(node->n6_object), &pool,
                &node->n6)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_v1_lab_n6_owner_init(&node->n6_owner, node->n6,
                ninlil_test_storage_ops(node->n6_storage),
                ninlil_n6_crypto_host_ops(), g_crypto, local->runtime_id)
        == NINLIL_N6_OK);
    fill_class_d(&sample, local->clock_epoch_id);
    REQUIRE(ninlil_v1_lab_n6_owner_boot_from_class_d(
                &node->n6_owner, &sample)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_v1_lab_n6_owner_install_pair(&node->n6_owner,
                encoded_binding, encoded_length, &node->n6_handles)
        == NINLIL_N6_OK);
    REQUIRE(setup_radio(node, pcp) == 0);
    bind_r7(&node->a_to_b, node->n6, node->n6_handles.a_to_b_hop,
        node->n6_handles.a_to_b_e2e, node, pcp, a_to_b_outbound);
    bind_r7(&node->b_to_a, node->n6, node->n6_handles.b_to_a_hop,
        node->n6_handles.b_to_a_e2e, node, pcp, !a_to_b_outbound);
    if (a_to_b_outbound != 0) {
        REQUIRE(ninlil_r7_frag_prod_time_authority_mint(
                    &node->a_to_b, NULL)
            == NINLIL_R7_FRAG_PROD_OK);
    } else {
        REQUIRE(ninlil_r7_frag_prod_time_authority_mint(
                    &node->b_to_a, NULL)
            == NINLIL_R7_FRAG_PROD_OK);
    }
    REQUIRE(ninlil_v1_lab_radio_packet_link_init(&node->packet_link,
                g_crypto, local->runtime_id,
                ninlil_test_clock_ops(pcp->clock), node->phy)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(ninlil_v1_lab_radio_packet_link_install_pair(&node->packet_link,
                encoded_binding, encoded_length, &node->a_to_b,
                &node->b_to_a, &node->pair_slot)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(node->pair_slot == 0u);
    return 0;
}

static void make_packet_view(
    const uint8_t *bytes,
    uint32_t length,
    const uint8_t path_id[16],
    uint64_t path_epoch,
    uint8_t permit_seed,
    ninlil_tx_permit_t *permit,
    ninlil_fabric_packet_view_v1_t *view)
{
    (void)memset(permit, 0, sizeof(*permit));
    permit->abi_version = NINLIL_ABI_VERSION;
    permit->struct_size = (uint16_t)sizeof(*permit);
    fill_bytes(permit->permit_id.bytes, 16u, permit_seed);
    fill_bytes(permit->attempt_id.bytes, 16u, 0x21u);
    fill_epoch(permit->clock_epoch_id.bytes);
    permit->expires_at_ms = 60000u;

    (void)memset(view, 0, sizeof(*view));
    view->api_version = NINLIL_FABRIC_API_VERSION;
    view->struct_size = (uint16_t)sizeof(*view);
    view->bytes = bytes;
    view->length = length;
    fill_bytes(view->transaction_id.bytes, 16u, 0x01u);
    fill_bytes(view->attempt_id.bytes, 16u, 0x21u);
    (void)memcpy(view->selected_path_id.bytes, path_id, 16u);
    view->path_selection_epoch = path_epoch;
    view->permit = permit;
}

static int send_frame(
    test_node_t *node,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t *bytes,
    uint32_t length,
    const uint8_t path_id[16],
    uint64_t path_epoch,
    uint8_t permit_seed,
    uint64_t release_authority,
    uint64_t release_sequence,
    uint8_t out_frame[255],
    uint8_t *out_length)
{
    ninlil_tx_permit_t permit;
    ninlil_fabric_packet_view_v1_t view;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_completion_v1_t completion;
    uint32_t i;

    node->bus.irq_status = 0u;
    node->bus.last_tx_payload_len = 0u;
    make_packet_view(bytes, length, path_id, path_epoch, permit_seed,
        &permit, &view);
    REQUIRE(ops->start_send(ops->user, handle, &view, &token)
        == NINLIL_FABRIC_LINK_RETAINED);
    REQUIRE(token != NULL);
    if (release_sequence != 0u) {
        REQUIRE(node->packet_link.tx.r7_held != 0u);
        REQUIRE(ninlil_r7_frag_issue_coordinator_complete(
                    release_authority, release_sequence, NULL)
            == NINLIL_R7_COORD_OK);
    }
    for (i = 0u; i < TEST_POLL_LIMIT; ++i) {
        (void)memset(&completion, 0, sizeof(completion));
        REQUIRE(ops->poll_send(ops->user, handle, token, &completion)
            == NINLIL_FABRIC_LINK_OK);
        if (completion.kind != NINLIL_FABRIC_LINK_COMPLETION_PENDING) {
            break;
        }
    }
    REQUIRE(completion.kind
        == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
    REQUIRE(node->bus.last_tx_payload_len > 0u);
    *out_length = node->bus.last_tx_payload_len;
    (void)memcpy(out_frame, node->bus.last_tx_payload, *out_length);
    ops->release_send(ops->user, handle, token);
    return 0;
}

static int receive_frame(
    test_node_t *node,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t *frame,
    uint8_t frame_length,
    uint8_t *out,
    uint32_t *out_length)
{
    const uint8_t *borrowed = NULL;
    void *receive_token = NULL;
    ninlil_fabric_link_status_t status;

    REQUIRE(ninlil_v1_lab_radio_packet_link_step(&node->packet_link)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(ninlil_sx1262_phy_state(node->phy)
        == NINLIL_SX1262_PHY_STATE_RX_ACTIVE);
    node->bus.rx_payload_len = frame_length;
    (void)memcpy(node->bus.rx_payload, frame, frame_length);
    node->bus.irq_status = 0x0002u;
    status = ops->receive_next(ops->user, handle, &borrowed, out_length,
        &receive_token);
    REQUIRE(status == NINLIL_FABRIC_LINK_OK);
    REQUIRE(borrowed != NULL && receive_token != NULL
        && *out_length <= NINLIL_V1_LAB_RADIO_NFL1_MAX);
    (void)memcpy(out, borrowed, *out_length);
    ops->release_received(ops->user, handle, receive_token);
    return 0;
}

static int duplicate_is_rejected(
    test_node_t *node,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t *frame,
    uint8_t frame_length)
{
    const uint8_t *borrowed = NULL;
    uint32_t length = 0u;
    void *receive_token = NULL;

    REQUIRE(ninlil_v1_lab_radio_packet_link_step(&node->packet_link)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    node->bus.rx_payload_len = frame_length;
    (void)memcpy(node->bus.rx_payload, frame, frame_length);
    node->bus.irq_status = 0x0002u;
    REQUIRE(ops->receive_next(ops->user, handle, &borrowed, &length,
                &receive_token)
        != NINLIL_FABRIC_LINK_OK);
    REQUIRE(borrowed == NULL && length == 0u && receive_token == NULL);
    return 0;
}

static int verify_application(
    const uint8_t *packet, uint32_t packet_length, uint64_t expected_epoch)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint8_t expected_payload[32];
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    REQUIRE(ninlil_fabric_private_nfl1_decode(packet, packet_length,
                &workspace, &envelope, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    fill_bytes(expected_payload, sizeof(expected_payload), 0x41u);
    REQUIRE(envelope.message_kind == NINLIL_BEARER_MESSAGE_APPLICATION);
    REQUIRE(envelope.path_selection_epoch == expected_epoch);
    REQUIRE(envelope.payload.length == sizeof(expected_payload));
    REQUIRE(memcmp(
                envelope.payload.bytes, expected_payload, sizeof(expected_payload))
        == 0);
    return 0;
}

static int verify_receipt(
    const uint8_t *packet, uint32_t packet_length, uint64_t expected_epoch)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    REQUIRE(ninlil_fabric_private_nfl1_decode(packet, packet_length,
                &workspace, &envelope, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    REQUIRE(envelope.message_kind == NINLIL_BEARER_MESSAGE_RECEIPT);
    REQUIRE(envelope.receipt_stage == NINLIL_EVIDENCE_APPLIED);
    REQUIRE(envelope.path_selection_epoch == expected_epoch);
    return 0;
}

#if TEST_PEER_RUNTIME_ENABLED
static int verify_runtime_receipt(
    const uint8_t *packet,
    uint32_t packet_length)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint8_t expected_transaction_id[16];
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    fill_bytes(expected_transaction_id, sizeof(expected_transaction_id), 0x01u);
    REQUIRE(ninlil_fabric_private_nfl1_decode(packet, packet_length,
                &workspace, &envelope, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    REQUIRE(envelope.message_kind == NINLIL_BEARER_MESSAGE_RECEIPT);
    REQUIRE(envelope.receipt_stage == NINLIL_EVIDENCE_VERIFIED);
    REQUIRE(memcmp(envelope.transaction_id.bytes,
                expected_transaction_id, 16u)
        == 0);
    return 0;
}

static int submit_peer_event(
    ninlil_service_t *service,
    const ninlil_v1_lab_binding_t *binding,
    ninlil_submission_result_t *out_result)
{
    static const uint8_t idempotency_key[] = "peer-event-1";
    uint8_t payload[8];
    ninlil_concrete_target_t target;
    ninlil_submission_t submission;

    fill_bytes(payload, sizeof(payload), 0xe0u);
    (void)memset(&target, 0, sizeof(target));
    target.abi_version = NINLIL_ABI_VERSION;
    target.struct_size = (uint16_t)sizeof(target);
    (void)memcpy(target.target_runtime_id.bytes,
        binding->endpoint_a.runtime_id, 16u);
    (void)memcpy(target.target_application_instance_id.bytes,
        binding->endpoint_a.application_id, 16u);
    (void)memcpy(target.device_id.bytes,
        binding->endpoint_a.device_id, 16u);
    (void)memcpy(target.installation_id.bytes,
        binding->endpoint_a.installation_id, 16u);
    (void)memcpy(target.site_domain_id.bytes,
        binding->endpoint_a.site_id, 16u);
    target.binding_epoch = binding->endpoint_a.binding_epoch;
    target.membership_epoch = binding->endpoint_a.membership_epoch;
    target.flags = binding->endpoint_a.identity_flags;

    (void)memset(&submission, 0, sizeof(submission));
    submission.abi_version = NINLIL_ABI_VERSION;
    submission.struct_size = (uint16_t)sizeof(submission);
    submission.schema_major = binding->services[1].schema_major;
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = NINLIL_NO_DEADLINE;
    submission.evidence_grace_ms = 0u;
    fill_bytes(submission.event_id.bytes, 16u, 0xc0u);
    submission.generation = 0u;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length =
        (uint32_t)(sizeof(idempotency_key) - 1u);
    submission.payload.data = payload;
    submission.payload.length = (uint32_t)sizeof(payload);
    submission.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    REQUIRE(ninlil_r7_crypto_sha256(g_crypto, payload, sizeof(payload),
                submission.content_digest.bytes)
        == NINLIL_R7_CRYPTO_OK);

    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->abi_version = NINLIL_ABI_VERSION;
    out_result->struct_size = (uint16_t)sizeof(*out_result);
    REQUIRE(ninlil_submit(service, &submission, out_result) == NINLIL_OK);
    REQUIRE(out_result->kind == NINLIL_SUBMISSION_ADMITTED_READY);
    return 0;
}

static int verify_peer_event(
    const uint8_t *packet,
    uint32_t packet_length,
    const ninlil_v1_lab_binding_t *binding)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint8_t expected_payload[8];
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    REQUIRE(ninlil_fabric_private_nfl1_decode(packet, packet_length,
                &workspace, &envelope, &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    fill_bytes(expected_payload, sizeof(expected_payload), 0xe0u);
    REQUIRE(envelope.message_kind == NINLIL_BEARER_MESSAGE_APPLICATION);
    REQUIRE(envelope.family == NINLIL_FAMILY_EVENT_FACT);
    REQUIRE(memcmp(envelope.source_runtime_id.bytes,
                binding->endpoint_b.runtime_id, 16u)
        == 0);
    REQUIRE(memcmp(envelope.target_runtime_id.bytes,
                binding->endpoint_a.runtime_id, 16u)
        == 0);
    REQUIRE(envelope.payload.length == sizeof(expected_payload));
    REQUIRE(memcmp(envelope.payload.bytes, expected_payload,
                sizeof(expected_payload))
        == 0);
    return 0;
}
#endif

typedef struct host_capture {
    uint32_t count;
    uint32_t board_info_count;
    uint32_t length;
    uint32_t response_code;
    uint8_t packet[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    ninlil_nvb1_board_info_t board_info;
} host_capture_t;

static void teardown_node(test_node_t *node);

static uint32_t capture_host_packet(
    void *user, const uint8_t *packet, size_t packet_length)
{
    host_capture_t *capture = (host_capture_t *)user;

    if (capture == NULL || packet == NULL || packet_length == 0u
        || packet_length > sizeof(capture->packet)
        || capture->count == UINT32_MAX) {
        return NINLIL_NVB1_STATUS_REJECTED;
    }
    (void)memcpy(capture->packet, packet, packet_length);
    capture->length = (uint32_t)packet_length;
    capture->count += 1u;
    return capture->response_code == 0u
        ? NINLIL_NVB1_STATUS_ACCEPTED_LOCAL
        : capture->response_code;
}

static ninlil_v1_usb_bridge_status_t capture_board_info(
    void *user, const ninlil_nvb1_board_info_t *info)
{
    host_capture_t *capture = (host_capture_t *)user;

    capture->board_info = *info;
    capture->board_info_count += 1u;
    return NINLIL_V1_USB_BRIDGE_OK;
}

static int transfer_fake_stream(
    ninlil_fake_byte_stream_t *from, ninlil_fake_byte_stream_t *to)
{
    uint8_t bytes[NINLIL_FAKE_BS_RING_BYTES];
    uint32_t length = ninlil_fake_byte_stream_take_tx(
        from, bytes, sizeof(bytes));

    if (length == 0u) {
        return 0;
    }
    return ninlil_fake_byte_stream_inject_rx(to, bytes, length) != 0
        ? 0
        : 1;
}

static int setup_board_owner(
    test_node_t *node,
    const ninlil_v1_lab_binding_t *binding,
    test_pcp_t *pcp,
    ninlil_fake_byte_stream_t *stream,
    uint8_t runtime_adopt_mode,
    uint8_t data_consumer,
    ninlil_v1_lab_board_owner_pair_ready_fn pair_ready,
    void *pair_ready_user)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_n6_context_pool_t pool;
    ninlil_r2_authority_clock_result_t sample;
    ninlil_v1_lab_board_owner_config_t owner_config;
    ninlil_clock_ops_t invalid_clock;
    const ninlil_v1_lab_endpoint_t *local_endpoint;
    uint8_t local_side;

    (void)memset(node, 0, sizeof(*node));
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 8u;
    storage_config.max_entries_per_namespace = 128u;
    storage_config.max_bytes_per_namespace = 262144u;
    node->n6_storage = ninlil_test_storage_create(&storage_config);
    REQUIRE(node->n6_storage != NULL);
    (void)memset(&pool, 0, sizeof(pool));
    pool.max_slots = TEST_CONTEXT_SLOTS;
    pool.bytes = node->n6_pool;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    REQUIRE(pool.bytes_size <= sizeof(node->n6_pool));
    REQUIRE(ninlil_n6_init(node->n6_object, sizeof(node->n6_object), &pool,
                &node->n6)
        == NINLIL_N6_OK);
    REQUIRE(runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_CONTROLLER
        || runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_PEER);
    local_side = runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_CONTROLLER
        ? binding->controller_side
        : (binding->controller_side == NINLIL_V1_LAB_SIDE_A
                ? NINLIL_V1_LAB_SIDE_B
                : NINLIL_V1_LAB_SIDE_A);
    local_endpoint = local_side == NINLIL_V1_LAB_SIDE_A
        ? &binding->endpoint_a
        : &binding->endpoint_b;
    fill_class_d(&sample, local_endpoint->clock_epoch_id);
    if (runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_CONTROLLER) {
        REQUIRE(ninlil_v1_lab_provisioner_init_controller(
                    &g_board_provisioner, node->n6,
                    ninlil_test_storage_ops(node->n6_storage),
                    ninlil_n6_crypto_host_ops(), g_crypto, &sample)
            == NINLIL_V1_LAB_PROVISION_OK);
    } else {
        REQUIRE(ninlil_v1_lab_provisioner_init_peer(&g_board_provisioner,
                    node->n6, ninlil_test_storage_ops(node->n6_storage),
                    ninlil_n6_crypto_host_ops(), g_crypto, &sample)
            == NINLIL_V1_LAB_PROVISION_OK);
    }
    REQUIRE(setup_radio(node, pcp) == 0);
    (void)memset(&owner_config, 0, sizeof(owner_config));
    owner_config.usb_stream = &stream->view;
    owner_config.provisioner = &g_board_provisioner;
    owner_config.crypto = g_crypto;
    owner_config.local_runtime_id = NULL;
    owner_config.clock = ninlil_test_clock_ops(pcp->clock);
    owner_config.phy = node->phy;
    owner_config.pcp = pcp->pcp;
    owner_config.hal = node->hal;
    owner_config.live = &pcp->live;
    owner_config.data_consumer = data_consumer;
    owner_config.pair_ready = pair_ready;
    owner_config.pair_ready_user = pair_ready_user;
    invalid_clock = *owner_config.clock;
    invalid_clock.now = NULL;
    owner_config.clock = &invalid_clock;
    REQUIRE(ninlil_v1_lab_board_owner_init(&g_board_owner, &owner_config)
        == NINLIL_V1_LAB_BOARD_OWNER_INVALID_ARGUMENT);
    owner_config.clock = ninlil_test_clock_ops(pcp->clock);
    REQUIRE(ninlil_v1_lab_board_owner_init(&g_board_owner, &owner_config)
        == NINLIL_V1_LAB_BOARD_OWNER_OK);
    return 0;
}

static int teardown_board_owner(test_node_t *node)
{
    ninlil_sx1262_error_t sx_error;
    ninlil_radio_hal_error_t hal_error;

    REQUIRE(ninlil_v1_lab_board_owner_clear(&g_board_owner)
        == NINLIL_V1_LAB_BOARD_OWNER_OK);
    ninlil_v1_lab_provisioner_clear(&g_board_provisioner);
    if (node->hal != NULL) {
        (void)ninlil_radio_hal_shutdown(node->hal, &hal_error);
    }
    if (node->phy != NULL) {
        (void)ninlil_sx1262_phy_shutdown(node->phy, &sx_error);
    }
    if (node->backend != NULL) {
        (void)ninlil_sx1262_shutdown(node->backend, &sx_error);
    }
    if (node->n6_storage != NULL) {
        ninlil_test_storage_destroy(node->n6_storage);
    }
    (void)memset(node, 0, sizeof(*node));
    return 0;
}

static int run_board_owner_vertical(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    test_pcp_t *pcp)
{
    ninlil_fake_byte_stream_t host_stream;
    ninlil_fake_byte_stream_t board_stream;
    ninlil_v1_usb_bridge_t host_bridge;
    ninlil_v1_usb_bridge_config_t host_config;
    ninlil_v1_usb_bridge_handle_t usb_handle;
    ninlil_v1_usb_bridge_completion_t usb_completion;
    host_capture_t capture;
    uint8_t application[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t peer_application[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t receipt[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t radio_frame[255];
    uint8_t receipt_frame[255];
    uint32_t application_length = 0u;
    uint32_t peer_application_length = 0u;
    uint32_t receipt_length = 0u;
    uint8_t radio_frame_length = 0u;
    uint8_t receipt_frame_length = 0u;
    const uint8_t *peer_path = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *peer_ops = NULL;
    ninlil_fabric_packet_link_handle_t peer_handle = NULL;
    uint64_t now = 1u;
    uint32_t i;
    int binding_done = 0;
    int application_done = 0;

    (void)memset(&capture, 0, sizeof(capture));
    ninlil_fake_byte_stream_init(&host_stream);
    ninlil_fake_byte_stream_init(&board_stream);
    ninlil_fake_byte_stream_open_up(&host_stream, 1u);
    ninlil_fake_byte_stream_open_up(&board_stream, 1u);
    REQUIRE(setup_board_owner(&g_node_a, binding, pcp, &board_stream,
                NINLIL_V1_LAB_ADOPT_CONTROLLER,
                NINLIL_V1_LAB_BOARD_OWNER_DATA_USB, NULL, NULL)
        == 0);
    REQUIRE(setup_node(&g_node_b, binding, encoded_binding, encoded_length,
                NINLIL_V1_LAB_SIDE_B, pcp)
        == 0);
    REQUIRE(ninlil_v1_lab_radio_packet_link_path(&g_node_b.packet_link, 0u,
                NINLIL_V1_LAB_FLOW_A_TO_B, &peer_path, &peer_ops)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(peer_ops->open(peer_ops->user, &peer_handle)
        == NINLIL_FABRIC_LINK_OK);

    (void)memset(&host_config, 0, sizeof(host_config));
    host_config.role = NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER;
    host_config.stream = &host_stream.view;
    host_config.fabric_handoff = capture_host_packet;
    host_config.board_info = capture_board_info;
    host_config.callback_user = &capture;
    REQUIRE(ninlil_v1_usb_bridge_init(&host_bridge, &host_config)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
        == NINLIL_V1_LAB_BOARD_OWNER_OK);
    now += 1u;

    for (i = 0u; i < 16u && capture.board_info_count == 0u; ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
    }
    REQUIRE(capture.board_info_count == 1u);
    REQUIRE(memcmp(capture.board_info.clock_epoch_id,
        binding->endpoint_a.clock_epoch_id, 16u) == 0);

    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&host_bridge,
                encoded_binding, encoded_length, now + 1000u, &usb_handle)
        == NINLIL_V1_USB_BRIDGE_OK);
    for (i = 0u; i < 80u; ++i, ++now) {
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        if (ninlil_v1_usb_bridge_take_completion(
                &host_bridge, usb_handle, &usb_completion)
            == NINLIL_V1_USB_BRIDGE_OK) {
            binding_done = 1;
            break;
        }
    }
    REQUIRE(binding_done != 0
        && usb_completion.reason
            == NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS
        && usb_completion.remote_status_code == NINLIL_NVB1_STATUS_INSTALLED
        && g_board_owner.pair_count == 1u
        && g_board_owner.radio_ready != 0u
        && g_board_provisioner.local_runtime_bound != 0u
        && memcmp(g_board_provisioner.local_runtime_id,
            binding->endpoint_a.runtime_id, 16u) == 0
        && memcmp(g_board_owner.radio.mapper.local_runtime_id,
            binding->endpoint_a.runtime_id, 16u) == 0);

    REQUIRE(make_application(
                g_crypto, binding, application, &application_length)
        == 0);
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&host_bridge, application,
                application_length, now + 1000u, &usb_handle)
        == NINLIL_V1_USB_BRIDGE_OK);
    for (i = 0u; i < 80u; ++i, ++now) {
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        if (ninlil_v1_usb_bridge_take_completion(
                &host_bridge, usb_handle, &usb_completion)
            == NINLIL_V1_USB_BRIDGE_OK) {
            application_done = 1;
            break;
        }
    }
    REQUIRE(application_done != 0
        && usb_completion.remote_status_code
            == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL
        && g_node_a.bus.last_tx_payload_len > 0u);
    radio_frame_length = g_node_a.bus.last_tx_payload_len;
    (void)memcpy(radio_frame, g_node_a.bus.last_tx_payload,
        radio_frame_length);
    REQUIRE(receive_frame(&g_node_b, peer_ops, peer_handle, radio_frame,
                radio_frame_length, peer_application,
                &peer_application_length)
        == 0);
    REQUIRE(verify_application(peer_application, peer_application_length,
                binding->pair_generation)
        == 0);

    REQUIRE(make_receipt(binding, peer_application, peer_application_length,
                receipt, &receipt_length)
        == 0);
    capture.response_code = NINLIL_NVB1_STATUS_REJECTED;
    REQUIRE(send_frame(&g_node_b, peer_ops, peer_handle, receipt,
                receipt_length, peer_path, 91u, 0x71u, 0u, 0u,
                receipt_frame, &receipt_frame_length)
        == 0);
    for (i = 0u; i < 8u
         && ninlil_sx1262_phy_state(g_node_a.phy)
             != NINLIL_SX1262_PHY_STATE_RX_ACTIVE;
         ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
    }
    REQUIRE(ninlil_sx1262_phy_state(g_node_a.phy)
        == NINLIL_SX1262_PHY_STATE_RX_ACTIVE);
    g_node_a.bus.rx_payload_len = receipt_frame_length;
    (void)memcpy(
        g_node_a.bus.rx_payload, receipt_frame, receipt_frame_length);
    g_node_a.bus.irq_status = 0x0002u;

    for (i = 0u; i < 100u && capture.count == 0u; ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
    }
    REQUIRE(capture.count == 1u);
    REQUIRE(verify_receipt(capture.packet, capture.length, 77u) == 0);
    for (i = 0u; i < 20u && g_board_owner.usb_receive_pending != 0u;
         ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
    }
    REQUIRE(g_board_owner.usb_receive_pending == 0u
        && g_board_owner.radio.rx.active == 0u
        && !ninlil_v1_lab_board_owner_is_fenced(&g_board_owner));

    capture.response_code = NINLIL_NVB1_STATUS_ACCEPTED_LOCAL;
    REQUIRE(send_frame(&g_node_b, peer_ops, peer_handle, receipt,
                receipt_length, peer_path, 91u, 0x72u, 0u, 0u,
                receipt_frame, &receipt_frame_length)
        == 0);
    for (i = 0u; i < 8u
         && ninlil_sx1262_phy_state(g_node_a.phy)
             != NINLIL_SX1262_PHY_STATE_RX_ACTIVE;
         ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
    }
    REQUIRE(ninlil_sx1262_phy_state(g_node_a.phy)
        == NINLIL_SX1262_PHY_STATE_RX_ACTIVE);
    g_node_a.bus.rx_payload_len = receipt_frame_length;
    (void)memcpy(
        g_node_a.bus.rx_payload, receipt_frame, receipt_frame_length);
    g_node_a.bus.irq_status = 0x0002u;
    for (i = 0u; i < 100u && capture.count == 1u; ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
    }
    REQUIRE(capture.count == 2u);
    REQUIRE(verify_receipt(capture.packet, capture.length, 77u) == 0);
    for (i = 0u; i < 20u && g_board_owner.usb_receive_pending != 0u;
         ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
    }
    REQUIRE(g_board_owner.usb_receive_pending == 0u
        && g_board_owner.radio.rx.active == 0u
        && !ninlil_v1_lab_board_owner_is_fenced(&g_board_owner));

    peer_ops->close(peer_ops->user, peer_handle);
    teardown_node(&g_node_b);
    REQUIRE(teardown_board_owner(&g_node_a) == 0);
    ninlil_v1_usb_bridge_clear(&host_bridge);
    ninlil_fake_byte_stream_close(&host_stream);
    ninlil_fake_byte_stream_close(&board_stream);
    return 0;
}

static int run_peer_board_owner_bootstrap(test_pcp_t *pcp)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_fake_byte_stream_t host_stream;
    ninlil_fake_byte_stream_t board_stream;
    ninlil_v1_usb_bridge_t host_bridge;
    ninlil_v1_usb_bridge_config_t host_config;
    ninlil_v1_usb_bridge_handle_t usb_handle;
    ninlil_v1_usb_bridge_completion_t usb_completion;
    host_capture_t capture;
    uint8_t encoded_binding[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    uint8_t application[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t receipt[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    size_t encoded_length = 0u;
    uint32_t application_length = 0u;
    uint32_t receipt_length = 0u;
    uint64_t now = 1u;
    uint32_t i;
    int binding_done = 0;
    int fabric_done = 0;

    REQUIRE(make_binding(
                g_crypto, &binding, encoded_binding, &encoded_length)
        == 0);
    binding.endpoint_a.clock_epoch_id[0] ^= 0x55u;
    REQUIRE(memcmp(binding.endpoint_a.clock_epoch_id,
                binding.endpoint_b.clock_epoch_id, 16u)
        != 0);
    REQUIRE(ninlil_v1_lab_binding_finalize(g_crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_binding_encode(g_crypto, &binding,
                encoded_binding, sizeof(encoded_binding), &encoded_length)
        == NINLIL_V1_LAB_BINDING_OK);

    (void)memset(&capture, 0, sizeof(capture));
    ninlil_fake_byte_stream_init(&host_stream);
    ninlil_fake_byte_stream_init(&board_stream);
    ninlil_fake_byte_stream_open_up(&host_stream, 1u);
    ninlil_fake_byte_stream_open_up(&board_stream, 1u);
    REQUIRE(setup_board_owner(&g_node_a, &binding, pcp, &board_stream,
                NINLIL_V1_LAB_ADOPT_PEER,
                NINLIL_V1_LAB_BOARD_OWNER_DATA_USB, NULL, NULL)
        == 0);

    (void)memset(&host_config, 0, sizeof(host_config));
    host_config.role = NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER;
    host_config.stream = &host_stream.view;
    host_config.fabric_handoff = capture_host_packet;
    host_config.board_info = capture_board_info;
    host_config.callback_user = &capture;
    REQUIRE(ninlil_v1_usb_bridge_init(&host_bridge, &host_config)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
        == NINLIL_V1_LAB_BOARD_OWNER_OK);
    now += 1u;
    for (i = 0u; i < 16u && capture.board_info_count == 0u; ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
    }
    REQUIRE(capture.board_info_count == 1u
        && memcmp(capture.board_info.clock_epoch_id,
               binding.endpoint_b.clock_epoch_id, 16u)
            == 0);

    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&host_bridge,
                encoded_binding, encoded_length, now + 1000u, &usb_handle)
        == NINLIL_V1_USB_BRIDGE_OK);
    for (i = 0u; i < 80u; ++i, ++now) {
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        if (ninlil_v1_usb_bridge_take_completion(
                &host_bridge, usb_handle, &usb_completion)
            == NINLIL_V1_USB_BRIDGE_OK) {
            binding_done = 1;
            break;
        }
    }
    REQUIRE(binding_done != 0
        && usb_completion.remote_status_code == NINLIL_NVB1_STATUS_INSTALLED
        && g_board_owner.pair_count == 1u
        && g_board_owner.radio_ready != 0u
        && g_board_provisioner.local_controller_mode == 0u
        && memcmp(g_board_provisioner.local_runtime_id,
               binding.endpoint_b.runtime_id, 16u)
            == 0
        && memcmp(g_board_owner.radio.mapper.local_runtime_id,
               binding.endpoint_b.runtime_id, 16u)
            == 0
        && g_board_owner.pairs[0].a_to_b.pcp == NULL
        && g_board_owner.pairs[0].b_to_a.pcp == pcp->pcp);

    REQUIRE(make_application(
                g_crypto, &binding, application, &application_length)
        == 0);
    REQUIRE(make_receipt(&binding, application, application_length,
                receipt, &receipt_length)
        == 0);
    REQUIRE(ninlil_v1_usb_bridge_submit_fabric(&host_bridge, receipt,
                receipt_length, now + 1000u, &usb_handle)
        == NINLIL_V1_USB_BRIDGE_OK);
    for (i = 0u; i < 80u; ++i, ++now) {
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        if (ninlil_v1_usb_bridge_take_completion(
                &host_bridge, usb_handle, &usb_completion)
            == NINLIL_V1_USB_BRIDGE_OK) {
            fabric_done = 1;
            break;
        }
    }
    REQUIRE(fabric_done != 0
        && usb_completion.remote_status_code
            == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL
        && g_node_a.bus.last_tx_payload_len > 0u);
    for (i = 0u; i < 20u && g_board_owner.radio.tx.active != 0u;
         ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
    }
    REQUIRE(g_board_owner.radio.tx.active == 0u
        && !ninlil_v1_lab_board_owner_is_fenced(&g_board_owner));

    REQUIRE(teardown_board_owner(&g_node_a) == 0);
    ninlil_v1_usb_bridge_clear(&host_bridge);
    ninlil_fake_byte_stream_close(&host_stream);
    ninlil_fake_byte_stream_close(&board_stream);
    ninlil_v1_lab_binding_clear(&binding);
    return 0;
}

#if TEST_PEER_RUNTIME_ENABLED
static int run_peer_runtime_bootstrap(test_pcp_t *pcp)
{
    ninlil_v1_lab_binding_t binding;
    test_peer_runtime_t peer_runtime;
    ninlil_fake_byte_stream_t host_stream;
    ninlil_fake_byte_stream_t board_stream;
    ninlil_v1_usb_bridge_t host_bridge;
    ninlil_v1_usb_bridge_config_t host_config;
    ninlil_v1_usb_bridge_handle_t usb_handle;
    ninlil_v1_usb_bridge_completion_t usb_completion;
    host_capture_t capture;
    ninlil_service_t *services[3];
    uint8_t encoded_binding[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    size_t encoded_length = 0u;
    uint64_t now = 1u;
    uint32_t done = 0u;
    uint32_t i;
    int binding_done = 0;
    ninlil_v1_lab_peer_runtime_status_t peer_status;
    ninlil_submission_result_t event_result;
    ninlil_runtime_t *runtime_handle = NULL;
    ninlil_transaction_snapshot_t event_snapshot;
    ninlil_target_snapshot_t event_target;
    uint8_t application[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t receipt[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t event[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t downlink_frame[255];
    uint8_t receipt_frame[255];
    uint8_t event_frame[255];
    uint32_t application_length = 0u;
    uint32_t receipt_length = 0u;
    uint32_t event_length = 0u;
    uint8_t downlink_frame_length = 0u;
    uint8_t receipt_frame_length = 0u;
    uint8_t event_frame_length = 0u;
    const uint8_t *downlink_path = NULL;
    const uint8_t *uplink_path = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *downlink_ops = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *uplink_ops = NULL;
    ninlil_fabric_packet_link_handle_t downlink_handle = NULL;
    ninlil_fabric_packet_link_handle_t uplink_handle = NULL;

    (void)memset(&binding, 0, sizeof(binding));
    (void)memset(&peer_runtime, 0, sizeof(peer_runtime));
    (void)memset(&capture, 0, sizeof(capture));
    (void)memset(services, 0, sizeof(services));
    REQUIRE(make_binding(
                g_crypto, &binding, encoded_binding, &encoded_length)
        == 0);
    REQUIRE(setup_peer_runtime(&peer_runtime, pcp) == 0);
    REQUIRE(ninlil_v1_lab_peer_runtime_step(&peer_runtime.runtime)
        == NINLIL_V1_LAB_PEER_RUNTIME_WAITING);
    REQUIRE(ninlil_v1_lab_peer_runtime_service(
                &peer_runtime.runtime, 1u, &services[0])
        == NINLIL_V1_LAB_PEER_RUNTIME_WAITING);

    ninlil_fake_byte_stream_init(&host_stream);
    ninlil_fake_byte_stream_init(&board_stream);
    ninlil_fake_byte_stream_open_up(&host_stream, 1u);
    ninlil_fake_byte_stream_open_up(&board_stream, 1u);
    REQUIRE(setup_board_owner(&g_node_a, &binding, pcp, &board_stream,
                NINLIL_V1_LAB_ADOPT_PEER,
                NINLIL_V1_LAB_BOARD_OWNER_DATA_LOCAL_FABRIC,
                ninlil_v1_lab_peer_runtime_pair_ready,
                &peer_runtime.runtime)
        == 0);

    (void)memset(&host_config, 0, sizeof(host_config));
    host_config.role = NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER;
    host_config.stream = &host_stream.view;
    host_config.fabric_handoff = capture_host_packet;
    host_config.board_info = capture_board_info;
    host_config.callback_user = &capture;
    REQUIRE(ninlil_v1_usb_bridge_init(&host_bridge, &host_config)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
        == NINLIL_V1_USB_BRIDGE_OK);
    REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
        == NINLIL_V1_LAB_BOARD_OWNER_OK);
    now += 1u;
    for (i = 0u; i < 16u && capture.board_info_count == 0u; ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
    }
    REQUIRE(capture.board_info_count == 1u);
    REQUIRE(ninlil_v1_usb_bridge_submit_binding(&host_bridge,
                encoded_binding, encoded_length, now + 1000u, &usb_handle)
        == NINLIL_V1_USB_BRIDGE_OK);
    for (i = 0u; i < 80u; ++i, ++now) {
        REQUIRE(ninlil_v1_usb_bridge_step(&host_bridge, now, 0u)
            == NINLIL_V1_USB_BRIDGE_OK);
        REQUIRE(transfer_fake_stream(&host_stream, &board_stream) == 0);
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(transfer_fake_stream(&board_stream, &host_stream) == 0);
        if (ninlil_v1_usb_bridge_take_completion(
                &host_bridge, usb_handle, &usb_completion)
            == NINLIL_V1_USB_BRIDGE_OK) {
            binding_done = 1;
            break;
        }
    }
    REQUIRE(binding_done != 0
        && usb_completion.remote_status_code == NINLIL_NVB1_STATUS_INSTALLED
        && g_board_owner.data_consumer
            == NINLIL_V1_LAB_BOARD_OWNER_DATA_LOCAL_FABRIC
        && !ninlil_v1_lab_board_owner_is_fenced(&g_board_owner));

    peer_status = ninlil_v1_lab_peer_runtime_step(&peer_runtime.runtime);
    if (peer_status != NINLIL_V1_LAB_PEER_RUNTIME_OK) {
        (void)fprintf(stderr, "peer runtime activation status=%u\n",
            (unsigned int)peer_status);
    }
    REQUIRE(peer_status == NINLIL_V1_LAB_PEER_RUNTIME_OK);
    REQUIRE(ninlil_v1_lab_peer_runtime_service(
                &peer_runtime.runtime, 1u, &services[0])
        == NINLIL_V1_LAB_PEER_RUNTIME_OK);
    REQUIRE(ninlil_v1_lab_peer_runtime_service(
                &peer_runtime.runtime, 2u, &services[1])
        == NINLIL_V1_LAB_PEER_RUNTIME_OK);
    REQUIRE(ninlil_v1_lab_peer_runtime_service(
                &peer_runtime.runtime, 3u, &services[2])
        == NINLIL_V1_LAB_PEER_RUNTIME_OK);
    REQUIRE(services[0] != NULL && services[1] != NULL && services[2] != NULL
        && services[0] != services[1] && services[0] != services[2]
        && services[1] != services[2]);
    REQUIRE(ninlil_v1_lab_peer_runtime_service(
                &peer_runtime.runtime, 4u, &services[0])
        == NINLIL_V1_LAB_PEER_RUNTIME_SERVICE);
    REQUIRE(ninlil_v1_lab_peer_runtime_handle(
                &peer_runtime.runtime, &runtime_handle)
        == NINLIL_V1_LAB_PEER_RUNTIME_OK);

    REQUIRE(setup_node(&g_node_b, &binding, encoded_binding, encoded_length,
                NINLIL_V1_LAB_SIDE_A, pcp)
        == 0);
    REQUIRE(ninlil_v1_lab_radio_packet_link_path(&g_node_b.packet_link, 0u,
                NINLIL_V1_LAB_FLOW_A_TO_B, &downlink_path, &downlink_ops)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(ninlil_v1_lab_radio_packet_link_path(&g_node_b.packet_link, 0u,
                NINLIL_V1_LAB_FLOW_B_TO_A, &uplink_path, &uplink_ops)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(downlink_ops->open(downlink_ops->user, &downlink_handle)
        == NINLIL_FABRIC_LINK_OK);
    REQUIRE(uplink_ops->open(uplink_ops->user, &uplink_handle)
        == NINLIL_FABRIC_LINK_OK);

    REQUIRE(make_application(g_crypto, &binding, application,
                &application_length)
        == 0);
    REQUIRE(send_frame(&g_node_b, downlink_ops, downlink_handle,
                application, application_length, downlink_path, 77u, 0x71u,
                0u, 0u, downlink_frame, &downlink_frame_length)
        == 0);
    for (i = 0u; i < 16u
         && ninlil_sx1262_phy_state(g_node_a.phy)
             != NINLIL_SX1262_PHY_STATE_RX_ACTIVE;
         ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
    }
    REQUIRE(ninlil_sx1262_phy_state(g_node_a.phy)
        == NINLIL_SX1262_PHY_STATE_RX_ACTIVE);
    g_node_a.bus.last_tx_payload_len = 0u;
    g_node_a.bus.rx_payload_len = downlink_frame_length;
    (void)memcpy(g_node_a.bus.rx_payload, downlink_frame,
        downlink_frame_length);
    g_node_a.bus.irq_status = 0x0002u;
    for (i = 0u; i < 128u && receipt_frame_length == 0u; ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(ninlil_v1_lab_peer_runtime_step(&peer_runtime.runtime)
            == NINLIL_V1_LAB_PEER_RUNTIME_OK);
        if (peer_runtime.delivery_count == 1u
            && g_node_a.bus.last_tx_payload_len > 0u) {
            receipt_frame_length = g_node_a.bus.last_tx_payload_len;
            (void)memcpy(receipt_frame, g_node_a.bus.last_tx_payload,
                receipt_frame_length);
        }
    }
    if (peer_runtime.delivery_count != 1u || receipt_frame_length == 0u) {
        (void)fprintf(stderr,
            "peer downlink progress delivery=%u tx_bytes=%u tx_active=%u "
            "radio_state=%u rx_active=%u rx_loaned=%u rx_port=%u "
            "ports=%u/%u fenced=%d loops=%u\n",
            (unsigned)peer_runtime.delivery_count,
            (unsigned)g_node_a.bus.last_tx_payload_len,
            (unsigned)g_board_owner.radio.tx.active,
            (unsigned)ninlil_sx1262_phy_state(g_node_a.phy),
            (unsigned)g_board_owner.radio.rx.active,
            (unsigned)g_board_owner.radio.rx.loaned,
            (unsigned)g_board_owner.radio.rx.port_index,
            (unsigned)g_board_owner.radio.ports[0].open,
            (unsigned)g_board_owner.radio.ports[1].open,
            ninlil_v1_lab_board_owner_is_fenced(&g_board_owner),
            (unsigned)i);
    }
    REQUIRE(peer_runtime.delivery_count == 1u
        && receipt_frame_length > 0u);
    REQUIRE(receive_frame(&g_node_b, downlink_ops, downlink_handle,
                receipt_frame, receipt_frame_length, receipt,
                &receipt_length)
        == 0);
    REQUIRE(verify_runtime_receipt(receipt, receipt_length) == 0);

    for (i = 0u; i < 32u && g_board_owner.radio.tx.active != 0u;
         ++i, ++now) {
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        REQUIRE(ninlil_v1_lab_peer_runtime_step(&peer_runtime.runtime)
            == NINLIL_V1_LAB_PEER_RUNTIME_OK);
    }
    REQUIRE(g_board_owner.radio.tx.active == 0u);
    g_node_a.bus.last_tx_payload_len = 0u;
    REQUIRE(submit_peer_event(services[1], &binding, &event_result) == 0);
    for (i = 0u; i < 128u && event_frame_length == 0u; ++i, ++now) {
        REQUIRE(ninlil_v1_lab_peer_runtime_step(&peer_runtime.runtime)
            == NINLIL_V1_LAB_PEER_RUNTIME_OK);
        REQUIRE(ninlil_v1_lab_board_owner_step(&g_board_owner, now, 0u)
            == NINLIL_V1_LAB_BOARD_OWNER_OK);
        if (g_node_a.bus.last_tx_payload_len > 0u) {
            event_frame_length = g_node_a.bus.last_tx_payload_len;
            (void)memcpy(event_frame, g_node_a.bus.last_tx_payload,
                event_frame_length);
        }
    }
    if (event_frame_length == 0u) {
        ninlil_status_t query_status;

        (void)memset(&event_target, 0, sizeof(event_target));
        event_target.abi_version = NINLIL_ABI_VERSION;
        event_target.struct_size = (uint16_t)sizeof(event_target);
        (void)memset(&event_snapshot, 0, sizeof(event_snapshot));
        event_snapshot.abi_version = NINLIL_ABI_VERSION;
        event_snapshot.struct_size = (uint16_t)sizeof(event_snapshot);
        event_snapshot.targets = &event_target;
        event_snapshot.target_capacity = 1u;
        query_status = ninlil_transaction_query(runtime_handle,
            &event_result.transaction_id, &event_snapshot);
        (void)fprintf(stderr,
            "peer event progress kind=%u entropy=%llu tx_active=%u "
            "radio_state=%u rx_active=%u ports=%u/%u loops=%u "
            "query=%d state=%u outcome=%u reason=%u target_state=%u "
            "target_reason=%u attempts=%u cumulative=%llu revision=%llu\n",
            (unsigned)event_result.kind,
            (unsigned long long)ninlil_test_entropy_call_count(
                peer_runtime.entropy),
            (unsigned)g_board_owner.radio.tx.active,
            (unsigned)ninlil_sx1262_phy_state(g_node_a.phy),
            (unsigned)g_board_owner.radio.rx.active,
            (unsigned)g_board_owner.radio.ports[0].open,
            (unsigned)g_board_owner.radio.ports[1].open,
            (unsigned)i,
            (int)query_status,
            (unsigned)event_snapshot.state,
            (unsigned)event_snapshot.outcome,
            (unsigned)event_snapshot.reason,
            (unsigned)event_target.state,
            (unsigned)event_target.reason,
            (unsigned)event_target.attempt_in_cycle,
            (unsigned long long)event_target.cumulative_attempts,
            (unsigned long long)event_snapshot.record_revision);
    }
    REQUIRE(event_frame_length > 0u);
    REQUIRE(receive_frame(&g_node_b, uplink_ops, uplink_handle,
                event_frame, event_frame_length, event, &event_length)
        == 0);
    REQUIRE(verify_peer_event(event, event_length, &binding) == 0);

    downlink_ops->close(downlink_ops->user, downlink_handle);
    uplink_ops->close(uplink_ops->user, uplink_handle);
    teardown_node(&g_node_b);

    REQUIRE(ninlil_v1_lab_peer_runtime_close_begin(&peer_runtime.runtime)
        == NINLIL_V1_LAB_PEER_RUNTIME_OK);
    for (i = 0u; i < 64u && done == 0u; ++i) {
        ninlil_v1_lab_peer_runtime_status_t status =
            ninlil_v1_lab_peer_runtime_close_step(
                &peer_runtime.runtime, &done);
        REQUIRE(status == NINLIL_V1_LAB_PEER_RUNTIME_OK
            || status == NINLIL_V1_LAB_PEER_RUNTIME_CLOSING);
    }
    REQUIRE(done == 1u);
    REQUIRE(teardown_peer_runtime(&peer_runtime) == 0);
    REQUIRE(teardown_board_owner(&g_node_a) == 0);
    ninlil_v1_usb_bridge_clear(&host_bridge);
    ninlil_fake_byte_stream_close(&host_stream);
    ninlil_fake_byte_stream_close(&board_stream);
    ninlil_v1_lab_binding_clear(&binding);
    return 0;
}
#endif

static void teardown_node(test_node_t *node)
{
    ninlil_sx1262_error_t sx_error;
    ninlil_radio_hal_error_t hal_error;

    ninlil_r7_frag_prod_bind_reset(&node->a_to_b);
    ninlil_r7_frag_prod_bind_reset(&node->b_to_a);
    ninlil_v1_lab_radio_packet_link_clear(&node->packet_link);
    if (node->hal != NULL) {
        (void)ninlil_radio_hal_shutdown(node->hal, &hal_error);
    }
    if (node->phy != NULL) {
        (void)ninlil_sx1262_phy_shutdown(node->phy, &sx_error);
    }
    if (node->backend != NULL) {
        (void)ninlil_sx1262_shutdown(node->backend, &sx_error);
    }
    ninlil_v1_lab_n6_owner_clear(&node->n6_owner);
    if (node->n6_storage != NULL) {
        ninlil_test_storage_destroy(node->n6_storage);
    }
}

static void teardown_pcp(test_pcp_t *pcp)
{
    ninlil_pcp_error_t error;

    if (pcp->pcp != NULL) {
        (void)ninlil_pcp_shutdown(pcp->pcp, &error);
    }
    ninlil_test_storage_destroy(pcp->storage);
    ninlil_test_clock_destroy(pcp->clock);
    ninlil_test_entropy_destroy(pcp->entropy);
}

int main(void)
{
    ninlil_r7_crypto_provider crypto;
    ninlil_v1_lab_binding_t binding;
    test_pcp_t pcp;
    uint8_t encoded_binding[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    uint8_t application[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t peer_application[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t receipt[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t origin_receipt[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t application_outer[255];
    uint8_t receipt_outer[255];
    uint32_t application_length = 0u;
    uint32_t peer_application_length = 0u;
    uint32_t receipt_length = 0u;
    uint32_t origin_receipt_length = 0u;
    size_t encoded_length = 0u;
    uint8_t application_outer_length = 0u;
    uint8_t receipt_outer_length = 0u;
    const uint8_t *path_a = NULL;
    const uint8_t *path_b = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *ops_a = NULL;
    const ninlil_fabric_packet_link_ops_v1_t *ops_b = NULL;
    ninlil_fabric_packet_link_handle_t handle_a = NULL;
    ninlil_fabric_packet_link_handle_t handle_b = NULL;
    ninlil_r7_coord_admit_t blocker;
    uint64_t blocker_authority;
    uint64_t blocker_sequence;

    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&crypto)
        == NINLIL_R7_CRYPTO_OK);
    g_crypto = &crypto;
    REQUIRE(make_binding(
                &crypto, &binding, encoded_binding, &encoded_length)
        == 0);
    REQUIRE(setup_pcp(&pcp) == 0);
    REQUIRE(run_board_owner_vertical(
                &binding, encoded_binding, encoded_length, &pcp)
        == 0);
    REQUIRE(run_peer_board_owner_bootstrap(&pcp) == 0);
#if TEST_PEER_RUNTIME_ENABLED
    REQUIRE(run_peer_runtime_bootstrap(&pcp) == 0);
#endif
    REQUIRE(setup_node(&g_node_a, &binding, encoded_binding, encoded_length,
                NINLIL_V1_LAB_SIDE_A, &pcp)
        == 0);
    REQUIRE(setup_node(&g_node_b, &binding, encoded_binding, encoded_length,
                NINLIL_V1_LAB_SIDE_B, &pcp)
        == 0);
    REQUIRE(ninlil_v1_lab_radio_packet_link_path(&g_node_a.packet_link, 0u,
                NINLIL_V1_LAB_FLOW_A_TO_B, &path_a, &ops_a)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(ninlil_v1_lab_radio_packet_link_path(&g_node_b.packet_link, 0u,
                NINLIL_V1_LAB_FLOW_A_TO_B, &path_b, &ops_b)
        == NINLIL_V1_LAB_RADIO_LINK_OK);
    REQUIRE(memcmp(path_a, path_b, 16u) == 0);
    REQUIRE(ops_a->open(ops_a->user, &handle_a) == NINLIL_FABRIC_LINK_OK);
    REQUIRE(ops_b->open(ops_b->user, &handle_b) == NINLIL_FABRIC_LINK_OK);

    REQUIRE(make_application(
                &crypto, &binding, application, &application_length)
        == 0);
    /* Complete one send so the next issued sequence can queue behind a
     * synthetic lower head owned by the same R2 authority. */
    REQUIRE(send_frame(&g_node_a, ops_a, handle_a, application,
                application_length, path_a, 77u, 0x51u, 0u, 0u,
                application_outer, &application_outer_length)
        == 0);
    blocker_authority = (uint64_t)(uintptr_t)pcp.pcp;
    blocker_sequence = g_node_a.a_to_b.last_completed_seq;
    REQUIRE(blocker_authority != 0u && blocker_sequence != 0u);
    (void)memset(&blocker, 0, sizeof(blocker));
    blocker.authority_token = blocker_authority;
    blocker.permit_sequence = blocker_sequence;
    blocker.bind_token = (uintptr_t)&blocker;
    blocker.outer_len = 1u;
    blocker.outer_digest[0] = 0xa5u;
    blocker.issue_now_ms = 1000u;
    REQUIRE(ninlil_r7_frag_issue_coordinator_admit(&blocker)
        == NINLIL_R7_COORD_OK);
    REQUIRE(send_frame(&g_node_a, ops_a, handle_a, application,
                application_length, path_a, 77u, 0x52u, blocker_authority,
                blocker_sequence, application_outer,
                &application_outer_length)
        == 0);
    REQUIRE(receive_frame(&g_node_b, ops_b, handle_b, application_outer,
                application_outer_length, peer_application,
                &peer_application_length)
        == 0);
    REQUIRE(verify_application(peer_application, peer_application_length,
                binding.pair_generation)
        == 0);

    REQUIRE(make_receipt(&binding, peer_application, peer_application_length,
                receipt, &receipt_length)
        == 0);
    REQUIRE(send_frame(&g_node_b, ops_b, handle_b, receipt, receipt_length,
                path_b, 91u, 0x61u, 0u, 0u, receipt_outer,
                &receipt_outer_length)
        == 0);
    REQUIRE(receive_frame(&g_node_a, ops_a, handle_a, receipt_outer,
                receipt_outer_length, origin_receipt,
                &origin_receipt_length)
        == 0);
    REQUIRE(verify_receipt(origin_receipt, origin_receipt_length, 77u) == 0);
    REQUIRE(duplicate_is_rejected(&g_node_a, ops_a, handle_a, receipt_outer,
                receipt_outer_length)
        == 0);

    ops_a->close(ops_a->user, handle_a);
    ops_b->close(ops_b->user, handle_b);
    teardown_node(&g_node_a);
    teardown_node(&g_node_b);
    teardown_pcp(&pcp);
    ninlil_v1_lab_binding_clear(&binding);
    g_crypto = NULL;
    (void)fprintf(stdout, "v1_lab_radio_packet_link_vertical_test OK\n");
    return 0;
}
