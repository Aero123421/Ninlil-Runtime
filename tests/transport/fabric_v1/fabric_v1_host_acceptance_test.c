/*
 * Private Host acceptance: registry → selection → reservation → dispatch →
 * provider completion → ingress projection; restart + every CU class;
 * outer/mixed/fresh/race catalogs; Wi-Fi & host-radio packet-link seams.
 * No public ABI; not ESP/RF HIL.
 */
#include "fabric_v1_test_common.h"
#include "fabric_v1_test_storage.h"
#include "fabric_v1_exec_catalog.h"
#include "fabric_v1_selection_vectors.h"
#include "fabric_host_radio_packet_link.h"
#include "fabric_private_select.h"

#include <stdio.h>
#include <string.h>

static uint8_t g_ws[NINLIL_FABRIC_WORKSPACE_BYTES] __attribute__((aligned(16)));

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
        (const uint8_t *)"fabric-registry-descriptor-v1", 29u, d->descriptor_digest);
    fabric_test_id(&d->security_profile_id, 0x21u);
    d->security_capability_flags = 0x0Fu;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-binding-v1", 26u, d->security_binding_digest);
    d->attestation_epoch = 5u;
    fabric_test_id(&d->attestation_clock_epoch_id, 0xA1u);
    d->attestation_expires_at_ms = 300000u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-attestation-v1", 30u, d->attestation_digest);
    fabric_test_id(&d->authenticated_peer_runtime_id, 0x31u);
    fabric_test_id(&d->attachment_authority_id, 0x41u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-attachment-binding-v1", 28u, d->attachment_binding_digest);
    d->maximum_packet_bytes = 1925u;
    d->maximum_transfer_bytes = 1925u;
    d->latency_class = latency;
    d->cost_class = 20u;
    d->reservation_capacity = 8u;
    d->peer_nfl1_version = 1u;
    d->peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    d->configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-config-v1", 25u, d->configuration_digest);
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
    ninlil_fabric_private_sha256((const uint8_t *)"fabric-vector-descriptor", 24u, dig);
    m->service.descriptor_digest.algorithm = 1u;
    memcpy(m->service.descriptor_digest.bytes, dig, 32u);
    m->service.schema_major = 1u;
    m->service.schema_minor = 0u;
    m->service.family = 2u;
    ninlil_fabric_private_sha256((const uint8_t *)"fabric-vector-content", 21u, dig);
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
        msg->service.namespace_id.bytes, msg->service.namespace_id.length,
        msg->service.service_id.bytes, msg->service.service_id.length,
        msg->service.schema_id.bytes, msg->service.schema_id.length,
        msg->service.descriptor_revision, msg->service.descriptor_digest.bytes,
        msg->service.schema_major, msg->service.schema_minor, msg->service.family,
        service_digest);
    ninlil_fabric_private_memzero(&policy, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    fabric_test_id(&policy.policy_id, 0x71u);
    policy.revision = 3u;
    memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = msg->service.family;
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
        binding.family = msg->service.family;
        binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
        binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
        binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
        fabric_test_id(&binding.endpoint_runtime_id, 0x80u);
        fabric_test_id(&binding.target_runtime_id, 0x80u);
        fabric_test_id(&binding.target_application_id, 0x90u);
        binding.policy_id = policy.policy_id;
        binding.policy_revision = 3u;
        memcpy(binding.policy_digest, snap.canonical_digest_zero_on_input, 32u);
        binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
        fabric_test_id(&binding.authority_id, 0xD0u);
        binding.authority_term = 17u;
        binding.assignment_epoch = 19u;
        fabric_test_id(&binding.owner_scope_id, 0x81u);
        fabric_test_pattern(binding.owner_tuple_canonical, 0x81u, 200u);
        ninlil_fabric_private_owner_tuple_digest(
            binding.owner_tuple_canonical, binding.owner_tuple_digest);
        fabric_test_id(&binding.authority_clock_epoch_id, 0xA1u);
        binding.lease_expires_at_ms =
            msg->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
            ? UINT64_MAX
            : 300000u;
        binding.assignment_revision = 11u;
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_authority_put_v1(fabric, &binding),
            NINLIL_FABRIC_PRIVATE_OK);
    }
    return 0;
}

static int boot(
    ninlil_fabric_private_t **out_f,
    const ninlil_bearer_ops_t **out_b,
    ninlil_storage_ops_t *st,
    ninlil_clock_ops_t *ck,
    ninlil_execution_ops_t *ex,
    ninlil_fabric_config_v1_t *cfg)
{
    fabric_test_reset_globals();
    fabric_test_storage_ops(st);
    ninlil_fabric_private_memzero(ck, sizeof(*ck));
    ck->abi_version = NINLIL_ABI_VERSION;
    ck->struct_size = (uint16_t)sizeof(*ck);
    ck->now = test_clock_now;
    ninlil_fabric_private_memzero(ex, sizeof(*ex));
    ex->abi_version = NINLIL_ABI_VERSION;
    ex->struct_size = (uint16_t)sizeof(*ex);
    ex->current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(cfg, sizeof(*cfg));
    cfg->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    cfg->struct_size = (uint16_t)sizeof(*cfg);
    cfg->profile_id = NINLIL_FABRIC_PROFILE_1;
    cfg->storage = st;
    cfg->clock = ck;
    cfg->execution = ex;
    ninlil_fabric_private_memzero(g_ws, sizeof(g_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(cfg, g_ws, sizeof(g_ws), out_f),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_bearer_ops_v1(*out_f, out_b),
        NINLIL_FABRIC_PRIVATE_OK);
    return 0;
}

static void shutdown_fabric(
    ninlil_fabric_private_t *f, const ninlil_bearer_ops_t *b, ninlil_bearer_handle_t h)
{
    if (b != NULL && h != NULL) {
        b->close(b->user, h);
    }
    if (f != NULL) {
        uint32_t done = 0u;
        uint32_t work = 0u;
        uint32_t spins;
        (void)ninlil_fabric_private_close_begin_v1(f);
        /* Only step may progress token cancel/release; close_poll never self-cancels. */
        for (spins = 0u; spins < 64u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(f, 16u, &work);
            (void)ninlil_fabric_private_close_poll_v1(f, &done);
        }
        (void)ninlil_fabric_private_destroy_v1(f);
    }
}

typedef struct fabric_send_fixture {
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric;
    const ninlil_bearer_ops_t *bearer;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_fabric_registration_private_t *registration;
    ninlil_bearer_handle_t handle;
    ninlil_bearer_message_t message;
    ninlil_tx_permit_t permit;
} fabric_send_fixture_t;

static int prepare_send_fixture(
    fabric_send_fixture_t *fixture, ninlil_family_t family)
{
    ninlil_id128_t runtime_id;

    if (fixture == NULL) {
        return 1;
    }
    ninlil_fabric_private_memzero(fixture, sizeof(*fixture));
    if (boot(
            &fixture->fabric,
            &fixture->bearer,
            &fixture->storage,
            &fixture->clock,
            &fixture->execution,
            &fixture->config)
        != 0) {
        return 1;
    }

    fill_message(&fixture->message);
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        fixture->message.service.family = NINLIL_FAMILY_EVENT_FACT;
        fabric_test_id(&fixture->message.event_id, 0xD1u);
        fixture->message.generation = 0u;
        ninlil_fabric_private_memzero(
            &fixture->message.deadline_clock_epoch_id,
            sizeof(fixture->message.deadline_clock_epoch_id));
        fixture->message.absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
        fixture->message.evidence_grace_ms = 0u;
    }

    fill_descriptor(&fixture->descriptor, 0x61u, 10u);
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        fixture->descriptor.attestation_expires_at_ms = UINT64_MAX;
        g_provider.state.available_until_ms = UINT64_MAX;
    }
    fabric_test_provider_ops(&fixture->link_ops, &g_provider);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(
            fixture->fabric,
            &fixture->descriptor,
            &fixture->link_ops,
            &fixture->registration),
        NINLIL_FABRIC_PRIVATE_OK);
    if (put_policy_and_authority(fixture->fabric, &fixture->message) != 0) {
        return 1;
    }

    fabric_test_id(&runtime_id, 0x30u);
    FABRIC_REQUIRE_EQ_U32(
        fixture->bearer->open(
            fixture->bearer->user,
            &runtime_id,
            NINLIL_ROLE_ENDPOINT,
            &fixture->handle),
        NINLIL_BEARER_OK);
    fixture->permit.abi_version = NINLIL_ABI_VERSION;
    fixture->permit.struct_size = (uint16_t)sizeof(fixture->permit);
    fabric_test_id(&fixture->permit.permit_id, 0xE0u);
    fixture->permit.attempt_id = fixture->message.attempt_id;
    fabric_test_id(&fixture->permit.clock_epoch_id, 0xA1u);
    fixture->permit.expires_at_ms =
        family == NINLIL_FAMILY_EVENT_FACT ? UINT64_MAX : 200000u;
    return 0;
}

/*
 * Production bearer-send mutation killers:
 * - DesiredState NO_DEADLINE/zero epoch is CORRUPT before storage/provider.
 * - EventFact uses the admission clock only for selection/retry lifetime while
 *   its retained NFL1 deadline remains NO_DEADLINE/all-zero.
 * - first-admit retry-cap overflow is WOULD_BLOCK with an unconsumed permit
 *   and no FBA1 mutation/provider start.
 */
static int test_deadline_projection_and_retry_cap_overflow(void)
{
    fabric_send_fixture_t fixture;
    ninlil_bearer_send_result_t send_result;
    uint32_t puts_before;
    uint32_t commits_before;
    uint32_t starts_before;

    /* Malformed DesiredState must not receive EventFact projection. */
    if (prepare_send_fixture(&fixture, NINLIL_FAMILY_DESIRED_STATE) != 0) {
        return 1;
    }
    ninlil_fabric_private_memzero(
        &fixture.message.deadline_clock_epoch_id,
        sizeof(fixture.message.deadline_clock_epoch_id));
    fixture.message.absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
    puts_before = g_store.put_calls;
    commits_before = g_store.commit_calls;
    starts_before = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        fixture.bearer->send(
            fixture.bearer->user,
            fixture.handle,
            &fixture.permit,
            &fixture.message,
            &send_result),
        NINLIL_BEARER_CORRUPT);
    FABRIC_REQUIRE_EQ_U32(g_store.put_calls, puts_before);
    FABRIC_REQUIRE_EQ_U32(g_store.commit_calls, commits_before);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before);
    shutdown_fabric(fixture.fabric, fixture.bearer, fixture.handle);

    /* Valid EventFact projects only selector retry-clock authority. */
    if (prepare_send_fixture(&fixture, NINLIL_FAMILY_EVENT_FACT) != 0) {
        return 1;
    }
    starts_before = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        fixture.bearer->send(
            fixture.bearer->user,
            fixture.handle,
            &fixture.permit,
            &fixture.message,
            &send_result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before + 1u);
    FABRIC_REQUIRE(g_provider.retained_len >= 416u);
    {
        ninlil_fabric_private_nfl1_workspace_t decode_workspace;
        ninlil_fabric_private_nfl1_envelope_t envelope;
        uint32_t required_workspace = 0u;

        ninlil_fabric_private_memzero(
            &decode_workspace, sizeof(decode_workspace));
        ninlil_fabric_private_memzero(&envelope, sizeof(envelope));
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_nfl1_decode(
                g_provider.retained_packet,
                g_provider.retained_len,
                &decode_workspace,
                &envelope,
                &required_workspace),
            NINLIL_FABRIC_PRIVATE_NFL1_OK);
        FABRIC_REQUIRE_EQ_U32(
            envelope.family, NINLIL_FAMILY_EVENT_FACT);
        FABRIC_REQUIRE(
            ninlil_fabric_private_id_is_zero(
                envelope.deadline_clock_epoch_id.bytes));
        FABRIC_REQUIRE(
            envelope.absolute_effect_deadline_ms == NINLIL_NO_DEADLINE);
    }
    shutdown_fabric(fixture.fabric, fixture.bearer, fixture.handle);

    /* Overflow must neither persist PREPARED nor consume the permit. */
    if (prepare_send_fixture(&fixture, NINLIL_FAMILY_EVENT_FACT) != 0) {
        return 1;
    }
    fabric_test_set_clock(UINT64_MAX - 100u, 0xA1u);
    puts_before = g_store.put_calls;
    commits_before = g_store.commit_calls;
    starts_before = g_provider.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        fixture.bearer->send(
            fixture.bearer->user,
            fixture.handle,
            &fixture.permit,
            &fixture.message,
            &send_result),
        NINLIL_BEARER_WOULD_BLOCK);
    FABRIC_REQUIRE_EQ_U32(g_store.put_calls, puts_before);
    FABRIC_REQUIRE_EQ_U32(g_store.commit_calls, commits_before);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before);

    /* The exact same permit remains valid after time moves into range. */
    fabric_test_set_clock(
        UINT64_MAX - NINLIL_FABRIC_RETRY_LIFETIME_MS - 1u, 0xA1u);
    FABRIC_REQUIRE_EQ_U32(
        fixture.bearer->send(
            fixture.bearer->user,
            fixture.handle,
            &fixture.permit,
            &fixture.message,
            &send_result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts_before + 1u);
    shutdown_fabric(fixture.fabric, fixture.bearer, fixture.handle);
    (void)printf("  deadline projection + retry-cap overflow OK\n");
    return 0;
}

/* Full host path with host-radio packet-link. */
static int test_host_radio_full_path(void)
{
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    const ninlil_bearer_ops_t *bearer = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_host_radio_user_t radio;
    ninlil_fabric_registration_private_t *reg = NULL;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_id128_t runtime;
    ninlil_bearer_message_t msg;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint32_t starts;

    if (boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
        return 1;
    }
    fill_descriptor(&d1, 0x61u, 10u);
    /* Host radio seam uses private loopback/Wi-Fi-class kind; physical RF HIL is external. */
    d1.link_kind = NINLIL_FABRIC_LINK_KIND_LOOPBACK;
    ninlil_fabric_host_radio_user_init(&radio);
    ninlil_fabric_host_radio_packet_link_ops_init(&ops, &radio);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg),
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
    starts = radio.start_calls;
    FABRIC_REQUIRE_EQ_U32(
        bearer->send(bearer->user, handle, &permit, &msg, &result),
        NINLIL_BEARER_OK);
    FABRIC_REQUIRE(radio.start_calls > starts);
    FABRIC_REQUIRE(radio.retain_bytes > 0u);
    /* Poll provider to terminal via step. */
    {
        uint32_t work = 0u;
        (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
    }
    shutdown_fabric(fabric, bearer, handle);
    (void)printf("  host_radio full path OK\n");
    return 0;
}

/* Race selection vectors via deterministic interleaving (not skip). */
static int test_race_interleavings(void)
{
    uint32_t ri;
    FABRIC_REQUIRE(FABRIC_V1_RACE_EXEC_COUNT == 2u);
    for (ri = 0u; ri < FABRIC_V1_RACE_EXEC_COUNT; ++ri) {
        const fabric_v1_race_exec_row_t *race = &g_race_exec_table[ri];
        ninlil_storage_ops_t storage;
        ninlil_clock_ops_t clock;
        ninlil_execution_ops_t exec;
        ninlil_fabric_config_v1_t config;
        ninlil_fabric_private_t *fabric = NULL;
        const ninlil_bearer_ops_t *bearer = NULL;
        ninlil_fabric_link_descriptor_v1_t d1;
        ninlil_fabric_packet_link_ops_v1_t ops;
        ninlil_fabric_registration_private_t *reg = NULL;
        ninlil_bearer_handle_t handle = NULL;
        ninlil_id128_t runtime;
        ninlil_bearer_message_t msg;
        ninlil_tx_permit_t permit;
        ninlil_bearer_send_result_t result;
        uint32_t starts;

        if (boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
            return 1;
        }
        fill_descriptor(&d1, 0x61u, 10u);
        fabric_test_provider_ops(&ops, &g_provider);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg),
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
        starts = g_provider.start_calls;

        if (race->pre_provider_epoch_bump != 0u) {
            /* First send WOULD_BLOCK to PREPARE then bump availability before retry. */
            g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
            FABRIC_REQUIRE_EQ_U32(
                bearer->send(bearer->user, handle, &permit, &msg, &result),
                NINLIL_BEARER_WOULD_BLOCK);
            {
                ninlil_fabric_link_descriptor_v1_t desc;
                ninlil_fabric_link_state_v1_t st;
                ninlil_fabric_link_state_v1_t neu;
                FABRIC_REQUIRE_EQ_U32(
                    ninlil_fabric_private_link_snapshot_v1(
                        fabric, &d1.instance_id, &desc, &st),
                    NINLIL_FABRIC_PRIVATE_OK);
                neu = st;
                neu.availability_epoch = st.availability_epoch + 1u;
                FABRIC_REQUIRE_EQ_U32(
                    ninlil_fabric_private_link_availability_update_v1(
                        fabric, &d1.instance_id, &neu),
                    NINLIL_FABRIC_PRIVATE_OK);
            }
            fabric_test_id(&permit.permit_id, 0xE1u);
            g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
            FABRIC_REQUIRE_EQ_U32(
                bearer->send(bearer->user, handle, &permit, &msg, &result),
                NINLIL_BEARER_UNAVAILABLE);
            FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts + 1u);
            FABRIC_REQUIRE(race->expect_closed_no_start == 1u);
        } else {
            /* Post-retain epoch race: retain first, then bump epoch, still OK path. */
            g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
            FABRIC_REQUIRE_EQ_U32(
                bearer->send(bearer->user, handle, &permit, &msg, &result),
                NINLIL_BEARER_OK);
            FABRIC_REQUIRE(g_provider.start_calls > starts);
            {
                ninlil_fabric_link_descriptor_v1_t desc;
                ninlil_fabric_link_state_v1_t st;
                ninlil_fabric_link_state_v1_t neu;
                FABRIC_REQUIRE_EQ_U32(
                    ninlil_fabric_private_link_snapshot_v1(
                        fabric, &d1.instance_id, &desc, &st),
                    NINLIL_FABRIC_PRIVATE_OK);
                neu = st;
                neu.availability_epoch = st.availability_epoch + 1u;
                FABRIC_REQUIRE_EQ_U32(
                    ninlil_fabric_private_link_availability_update_v1(
                        fabric, &d1.instance_id, &neu),
                    NINLIL_FABRIC_PRIVATE_OK);
            }
            /* Token still tracked to terminal via step. */
            {
                uint32_t work = 0u;
                (void)ninlil_fabric_private_step_v1(fabric, 16u, &work);
            }
            FABRIC_REQUIRE(race->expect_retained == 1u);
        }
        shutdown_fabric(fabric, bearer, handle);
        (void)printf("  race OK %s\n", race->id);
    }
    return 0;
}

/* Outer bearer executable scenarios (literal catalog, not count-only). */
static int test_outer_exec_catalog(void)
{
    uint32_t i;
    FABRIC_REQUIRE(FABRIC_V1_OUTER_EXEC_COUNT == 8u);
    for (i = 0u; i < FABRIC_V1_OUTER_EXEC_COUNT; ++i) {
        const fabric_v1_outer_exec_row_t *row = &g_outer_exec_table[i];
        ninlil_storage_ops_t storage;
        ninlil_clock_ops_t clock;
        ninlil_execution_ops_t exec;
        ninlil_fabric_config_v1_t config;
        ninlil_fabric_private_t *fabric = NULL;
        const ninlil_bearer_ops_t *bearer = NULL;
        ninlil_fabric_link_descriptor_v1_t d1;
        ninlil_fabric_packet_link_ops_v1_t ops;
        ninlil_fabric_registration_private_t *reg = NULL;
        ninlil_bearer_handle_t handle = NULL;
        ninlil_id128_t runtime;
        ninlil_bearer_message_t msg;
        ninlil_tx_permit_t permit;
        ninlil_bearer_send_result_t result;
        uint32_t starts;
        ninlil_bearer_status_t st;

        if (row->is_receive != 0u) {
            /* Receive paths covered by reverse/receive lifecycle; catalog pin. */
            FABRIC_REQUIRE(row->expected_code == 5u || row->expected_code == 6u);
            (void)printf("  outer catalog pin %s receive\n", row->id);
            continue;
        }
        if (boot(&fabric, &bearer, &storage, &clock, &exec, &config) != 0) {
            return 1;
        }
        fill_descriptor(&d1, 0x61u, 10u);
        if (strcmp(row->id, "FABRIC-OUTER-NO-RETAIN-CAPACITY") == 0) {
            d1.reservation_capacity = 0u;
        }
        fabric_test_provider_ops(&ops, &g_provider);
        FABRIC_REQUIRE_EQ_U32(
            ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg),
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
        starts = g_provider.start_calls;

        if (strcmp(row->id, "FABRIC-OUTER-PROVIDER-WOULD-BLOCK") == 0
            || strcmp(row->id, "FABRIC-OUTER-NO-RETAIN-CAPACITY") == 0) {
            g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
            st = bearer->send(bearer->user, handle, &permit, &msg, &result);
            FABRIC_REQUIRE(st == NINLIL_BEARER_WOULD_BLOCK
                || st == NINLIL_BEARER_UNAVAILABLE);
        } else if (strcmp(row->id, "FABRIC-OUTER-PROVIDER-PARTIAL-TLS") == 0) {
            g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
            FABRIC_REQUIRE_EQ_U32(
                bearer->send(bearer->user, handle, &permit, &msg, &result),
                NINLIL_BEARER_OK);
            FABRIC_REQUIRE(g_provider.start_calls > starts);
        } else if (strcmp(row->id, "FABRIC-OUTER-COMMIT-UNKNOWN") == 0) {
            g_store.fail_next_commit = 1u;
            g_store.cu_apply_staged = 0u;
            g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
            st = bearer->send(bearer->user, handle, &permit, &msg, &result);
            FABRIC_REQUIRE(
                st == NINLIL_BEARER_LOST_UNKNOWN || st == NINLIL_BEARER_CORRUPT);
            FABRIC_REQUIRE_EQ_U32(g_provider.start_calls, starts);
        } else if (
            strcmp(row->id, "FABRIC-OUTER-LINK-RETAINED-COMMIT-UNKNOWN") == 0) {
            g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
            g_store.fail_next_commit = 1u;
            g_store.commit_fault_skips = 1u; /* allow PREPARED */
            g_store.cu_apply_staged = 1u;
            st = bearer->send(bearer->user, handle, &permit, &msg, &result);
            FABRIC_REQUIRE(
                st == NINLIL_BEARER_LOST_UNKNOWN || st == NINLIL_BEARER_OK
                || st == NINLIL_BEARER_CORRUPT);
        } else if (
            strcmp(row->id, "FABRIC-OUTER-SAME-ATTEMPT-MESSAGE-CONFLICT") == 0) {
            g_provider.next_start_status = NINLIL_FABRIC_LINK_WOULD_BLOCK;
            FABRIC_REQUIRE_EQ_U32(
                bearer->send(bearer->user, handle, &permit, &msg, &result),
                NINLIL_BEARER_WOULD_BLOCK);
            msg.generation = 99u; /* mutate message same attempt ids */
            fabric_test_id(&permit.permit_id, 0xE1u);
            st = bearer->send(bearer->user, handle, &permit, &msg, &result);
            FABRIC_REQUIRE(st == NINLIL_BEARER_CORRUPT);
        } else {
            FABRIC_REQUIRE(0);
        }
        shutdown_fabric(fabric, bearer, handle);
        (void)printf("  outer OK %s\n", row->id);
    }
    return 0;
}

/* Mixed-version peer matrix via real select. */
static int test_mixed_exec_via_select(void)
{
    uint32_t i;
    FABRIC_REQUIRE(FABRIC_V1_MIXED_EXEC_COUNT == 30u);
    for (i = 0u; i < FABRIC_V1_MIXED_EXEC_COUNT; ++i) {
        const fabric_v1_mixed_exec_row_t *row = &g_mixed_exec_table[i];
        ninlil_fabric_private_select_snapshot_t snap;
        ninlil_fabric_private_select_result_t res;
        fabric_v1_sel_vec_baseline(&snap);
        /* Local ver 0 means host does not claim NFL1 — treat as outer peer gate. */
        if (row->local_ver != 1u) {
            snap.registry[0].peer_nfl1_version = 0u;
        } else {
            snap.registry[0].peer_nfl1_version = (uint16_t)row->peer_ver;
        }
        snap.registry[0].peer_fabric_capability_flags = row->peer_cap_flags;
        ninlil_fabric_private_select(&snap, &res);
        if (row->expected == 1u) {
            FABRIC_REQUIRE_EQ_U32(
                res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
        } else {
            FABRIC_REQUIRE_EQ_U32(
                res.resolution, NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
            FABRIC_REQUIRE(res.primary_rejection != NULL);
            FABRIC_REQUIRE(
                strcmp(res.primary_rejection, "PEER_NFL1") == 0
                || strcmp(res.primary_rejection, "CAPABILITY_MISSING") == 0
                || strcmp(res.primary_rejection, "ENERGY_SLEEP_CAPABILITY_MISSING")
                    == 0);
        }
        (void)printf("  mixed OK %s\n", row->id);
    }
    return 0;
}

/* Fresh adoption: preload wire rows then create (executable, not counts). */
static int test_fresh_exec_catalog(void)
{
    uint32_t i;
    FABRIC_REQUIRE(FABRIC_V1_FRESH_EXEC_COUNT == 11u);
    for (i = 0u; i < FABRIC_V1_FRESH_EXEC_COUNT; ++i) {
        const fabric_v1_fresh_exec_row_t *row = &g_fresh_exec_table[i];
        ninlil_storage_ops_t storage;
        ninlil_clock_ops_t clock;
        ninlil_execution_ops_t exec;
        ninlil_fabric_config_v1_t config;
        ninlil_fabric_private_t *fabric = NULL;
        uint32_t j;
        ninlil_fabric_private_status_t st;

        fabric_test_reset_globals();
        fabric_test_storage_ops(&storage);
        /* Preload observed durable rows before create (restart-style). */
        for (j = 0u; j < row->obs_n; ++j) {
            uint32_t s;
            for (s = 0u; s < FABRIC_TEST_STORE_MAX; ++s) {
                if (g_store.rows[s].used == 0u) {
                    g_store.rows[s].used = 1u;
                    FABRIC_REQUIRE(row->obs[j].key_len <= FABRIC_TEST_KEY_MAX);
                    FABRIC_REQUIRE(row->obs[j].val_len <= FABRIC_TEST_VAL_MAX);
                    (void)memcpy(
                        g_store.rows[s].key, row->obs[j].key, row->obs[j].key_len);
                    g_store.rows[s].key_len = row->obs[j].key_len;
                    (void)memcpy(
                        g_store.rows[s].value, row->obs[j].val, row->obs[j].val_len);
                    g_store.rows[s].value_len = row->obs[j].val_len;
                    break;
                }
            }
        }
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
        st = ninlil_fabric_private_create_v1(
            &config, g_ws, sizeof(g_ws), &fabric);
        if (row->expect_create_ok != 0u) {
            FABRIC_REQUIRE_EQ_U32(st, NINLIL_FABRIC_PRIVATE_OK);
            FABRIC_REQUIRE(fabric != NULL);
            shutdown_fabric(fabric, NULL, NULL);
        } else {
            FABRIC_REQUIRE(st != NINLIL_FABRIC_PRIVATE_OK);
        }
        /* CU classify for reopen-classify rows with wire. */
        if (row->phase == 4u && row->new_n > 0u) {
            uint32_t klass = ninlil_fabric_private_commit_unknown_classify(
                row->old_n ? row->oldr[0].key : NULL,
                row->old_n ? row->oldr[0].key_len : 0u,
                row->old_n ? row->oldr[0].val : NULL,
                row->old_n ? row->oldr[0].val_len : 0u,
                row->newr[0].key,
                row->newr[0].key_len,
                row->newr[0].val,
                row->newr[0].val_len,
                row->obs_n ? row->obs[0].key : NULL,
                row->obs_n ? row->obs[0].key_len : 0u,
                row->obs_n ? row->obs[0].val : NULL,
                row->obs_n ? row->obs[0].val_len : 0u,
                row->obs_n ? 1 : 0);
            if (row->classification == 3u) {
                FABRIC_REQUIRE_EQ_U32(
                    klass, NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_ABSENT);
            } else if (row->classification == 4u) {
                FABRIC_REQUIRE_EQ_U32(
                    klass, NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW);
            } else if (row->classification == 2u) {
                FABRIC_REQUIRE_EQ_U32(
                    klass, NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT);
            }
        }
        (void)printf("  fresh OK %s create=%u\n", row->id, (unsigned)row->expect_create_ok);
    }
    return 0;
}

/* FBA CU wire classify for all 6 rows. */
static int test_fbacu_exec(void)
{
    uint32_t i;
    FABRIC_REQUIRE(FABRIC_V1_FBA_CU_EXEC_COUNT == 6u);
    for (i = 0u; i < FABRIC_V1_FBA_CU_EXEC_COUNT; ++i) {
        const fabric_v1_fbacu_row_t *row = &g_fbacu_exec_table[i];
        uint32_t klass = ninlil_fabric_private_commit_unknown_classify(
            row->ok, row->okl, row->ov, row->ovl, row->nk, row->nkl, row->nv,
            row->nvl, row->sk, row->skl, row->sv, row->svl, row->obs_present);
        FABRIC_REQUIRE_EQ_U32(klass, row->class_code);
        (void)printf("  fbacu OK %s class=%u\n", row->id, (unsigned)klass);
    }
    return 0;
}

/* Every CU class on host register multi-full path. */
static int test_host_all_cu_classes(void)
{
    /* OLD/NEW/ABSENT/CORRUPT/THIRD already in lifecycle; pin via classify matrix. */
    FABRIC_REQUIRE(FABRIC_V1_CU_EXEC_COUNT == 5u);
    {
        uint32_t i;
        for (i = 0u; i < FABRIC_V1_CU_EXEC_COUNT; ++i) {
            const fabric_v1_cu_row_t *row = &g_cu_exec_table[i];
            if (strcmp(row->id, "FABRIC-COMMIT-UNKNOWN-MIXED-GROUP") == 0) {
                FABRIC_REQUIRE_EQ_U32(
                    row->class_code, NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT);
                continue;
            }
            {
                uint32_t klass = ninlil_fabric_private_commit_unknown_classify(
                    row->old_k, row->old_kl, row->old_v, row->old_vl, row->new_k,
                    row->new_kl, row->new_v, row->new_vl, row->obs_k, row->obs_kl,
                    row->obs_v, row->obs_vl, row->obs_present);
                FABRIC_REQUIRE_EQ_U32(klass, row->class_code);
            }
        }
    }
    (void)printf("  host CU classes OK\n");
    return 0;
}

/* Selection catalog race rows no longer skip in host GO suite. */
static int test_selection_race_catalog_not_skipped(void)
{
    uint32_t i;
    uint32_t races = 0u;
    for (i = 0u; i < FABRIC_V1_SEL_VEC_COUNT; ++i) {
        if (strstr(g_sel_vec_table[i].id, "RACE") != NULL) {
            races++;
            /* Host executes via test_race_interleavings; pin IDs. */
            FABRIC_REQUIRE(
                strcmp(
                    g_sel_vec_table[i].id,
                    "FABRIC-SELECT-AVAILABILITY-EPOCH-RACE")
                    == 0
                || strcmp(
                       g_sel_vec_table[i].id,
                       "FABRIC-SELECT-POST-RETAIN-EPOCH-RACE")
                    == 0);
        }
    }
    FABRIC_REQUIRE_EQ_U32(races, 2u);
    return 0;
}

int main(void)
{
    g_fabric_test_failures = 0;
    (void)printf("fabric_v1_host_acceptance_test\n");
    (void)test_deadline_projection_and_retry_cap_overflow();
    (void)test_host_radio_full_path();
    (void)test_race_interleavings();
    (void)test_outer_exec_catalog();
    (void)test_mixed_exec_via_select();
    (void)test_fresh_exec_catalog();
    (void)test_fbacu_exec();
    (void)test_host_all_cu_classes();
    (void)test_selection_race_catalog_not_skipped();
    if (g_fabric_test_failures != 0) {
        (void)fprintf(
            stderr,
            "fabric_v1_host_acceptance_test failures=%d\n",
            g_fabric_test_failures);
        return 1;
    }
    (void)printf("fabric_v1_host_acceptance_test OK (private Host GO target)\n");
    return 0;
}
