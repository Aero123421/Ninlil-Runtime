#include <ninlil/posix_tls_v1.h>

#include "in_memory_storage.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PORT_WORKSPACE_BYTES 16384u

#define CHECK(condition_)                                                   \
    do {                                                                    \
        if (!(condition_)) {                                                \
            (void)fprintf(                                                  \
                stderr, "posix_tls_v1_registration:%d: %s\n", __LINE__,    \
                #condition_);                                               \
            return 0;                                                       \
        }                                                                   \
    } while (0)

typedef union port_workspace {
    max_align_t alignment;
    uint8_t bytes[PORT_WORKSPACE_BYTES];
} port_workspace_t;

typedef union fabric_workspace {
    max_align_t alignment;
    uint8_t bytes[NINLIL_FABRIC_WORKSPACE_BYTES];
} fabric_workspace_t;

typedef struct test_environment {
    uint64_t context_id;
    uint64_t now_ms;
    ninlil_id128_t clock_epoch_id;
    uint32_t execution_calls;
    uint32_t reenter_at_call;
    ninlil_posix_tls_v1_t *reenter_port;
    ninlil_posix_tls_status_t nested_status;
    ninlil_posix_tls_state_v1_t nested_state;
} test_environment_t;

static fabric_workspace_t g_fabric_workspace;
static fabric_workspace_t g_other_fabric_workspace;
static fabric_workspace_t g_commit_unknown_fabric_workspace;
static port_workspace_t g_port_workspace;
static port_workspace_t g_commit_unknown_port_workspace;

static void fill_bytes(uint8_t *bytes, size_t count, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < count; ++i) {
        bytes[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_id(ninlil_id128_t *id, uint8_t seed)
{
    fill_bytes(id->bytes, sizeof(id->bytes), seed);
}

static uint64_t test_current_context_id(void *user)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->execution_calls += 1u;
    if (environment->reenter_at_call == environment->execution_calls
        && environment->reenter_port != NULL) {
        (void)memset(
            &environment->nested_state, 0xa5,
            sizeof(environment->nested_state));
        environment->nested_status = ninlil_posix_tls_v1_state(
            environment->reenter_port, &environment->nested_state);
    }
    return environment->context_id;
}

static ninlil_port_status_t test_now(
    void *user, ninlil_time_sample_t *out_sample)
{
    test_environment_t *environment = (test_environment_t *)user;
    if (out_sample == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    (void)memset(out_sample, 0, sizeof(*out_sample));
    out_sample->abi_version = NINLIL_ABI_VERSION;
    out_sample->struct_size = (uint16_t)sizeof(*out_sample);
    out_sample->clock_epoch_id = environment->clock_epoch_id;
    out_sample->now_ms = environment->now_ms;
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static void init_clock_execution(
    test_environment_t *environment,
    ninlil_clock_ops_t *clock,
    ninlil_execution_ops_t *execution)
{
    (void)memset(environment, 0, sizeof(*environment));
    environment->context_id = 1u;
    environment->now_ms = 1000u;
    fill_id(&environment->clock_epoch_id, 0x11u);
    (void)memset(clock, 0, sizeof(*clock));
    clock->abi_version = NINLIL_ABI_VERSION;
    clock->struct_size = (uint16_t)sizeof(*clock);
    clock->user = environment;
    clock->now = test_now;
    (void)memset(execution, 0, sizeof(*execution));
    execution->abi_version = NINLIL_ABI_VERSION;
    execution->struct_size = (uint16_t)sizeof(*execution);
    execution->user = environment;
    execution->current_context_id = test_current_context_id;
}

static void init_leaf(
    ninlil_posix_tls_leaf_expectation_v1_t *leaf,
    uint32_t role,
    uint8_t seed,
    uint32_t credential_generation)
{
    (void)memset(leaf, 0, sizeof(*leaf));
    leaf->api_version = NINLIL_POSIX_TLS_API_VERSION;
    leaf->struct_size = (uint16_t)sizeof(*leaf);
    leaf->role = role;
    fill_id(&leaf->runtime_id, seed);
    fill_bytes(leaf->leaf_spki_sha256, 32u, (uint8_t)(seed + 0x10u));
    fill_id(&leaf->authority_id, (uint8_t)(seed + 0x20u));
    leaf->authority_term = 3u;
    fill_bytes(
        leaf->authorized_attachment_binding_digest, 32u,
        (uint8_t)(seed + 0x30u));
    leaf->credential_generation = credential_generation;
    leaf->revocation_generation = credential_generation + 1u;
}

static void init_port_config(
    ninlil_posix_tls_config_v1_t *config,
    const ninlil_storage_ops_t *storage,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution,
    uint8_t instance_seed)
{
    static const char ca_path[] = "/tmp/ca.pem";
    static const char cert_path[] = "/tmp/cert.pem";
    static const char key_path[] = "/tmp/key.pem";
    static const uint8_t storage_namespace[] = "posix-tls-test";
    ninlil_fabric_link_descriptor_v1_t *descriptor;

    (void)memset(config, 0, sizeof(*config));
    config->api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->struct_size = (uint16_t)sizeof(*config);
    config->role = NINLIL_POSIX_TLS_ROLE_CLIENT;
    fill_id(&config->instance_id, instance_seed);
    config->endpoint.api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->endpoint.struct_size = (uint16_t)sizeof(config->endpoint);
    config->endpoint.address_kind = NINLIL_POSIX_TLS_ADDRESS_IPV4;
    config->endpoint.port = 443u;
    config->endpoint.address[0] = 127u;
    config->endpoint.address[3] = 1u;
    config->tls_paths.api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->tls_paths.struct_size = (uint16_t)sizeof(config->tls_paths);
    config->tls_paths.ca_pem_path = ca_path;
    config->tls_paths.cert_pem_path = cert_path;
    config->tls_paths.key_pem_path = key_path;
    config->authorization.api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->authorization.struct_size =
        (uint16_t)sizeof(config->authorization);
    config->authorization.assignment_epoch = 2u;
    init_leaf(
        &config->authorization.local_leaf,
        NINLIL_POSIX_TLS_ROLE_CLIENT, 0x41u, 7u);
    init_leaf(
        &config->authorization.peer_leaf,
        NINLIL_POSIX_TLS_ROLE_SERVER, 0x81u, 9u);
    config->authorization.peer_leaf.authority_id =
        config->authorization.local_leaf.authority_id;
    config->authorization.peer_leaf.authority_term =
        config->authorization.local_leaf.authority_term;
    (void)memcpy(
        config->authorization.peer_leaf
            .authorized_attachment_binding_digest,
        config->authorization.local_leaf
            .authorized_attachment_binding_digest,
        sizeof(config->authorization.peer_leaf
                   .authorized_attachment_binding_digest));
    fill_id(&config->authorization.registry_epoch_id, 0xc1u);
    fill_bytes(
        config->authorization.credential_reference_digest, 32u, 0xd1u);
    config->authorization.credential_revision = 7u;

    descriptor = &config->link_descriptor;
    descriptor->api_version = NINLIL_FABRIC_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    descriptor->instance_id = config->instance_id;
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    descriptor->descriptor_revision = 1u;
    fill_bytes(descriptor->descriptor_digest, 32u, 0x12u);
    fill_id(&descriptor->security_profile_id, 0x32u);
    descriptor->security_capability_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    fill_bytes(descriptor->security_binding_digest, 32u, 0x52u);
    descriptor->attestation_epoch = 1u;
    descriptor->attestation_clock_epoch_id =
        ((test_environment_t *)clock->user)->clock_epoch_id;
    descriptor->attestation_expires_at_ms = 2000u;
    fill_bytes(descriptor->attestation_digest, 32u, 0x72u);
    descriptor->authenticated_peer_runtime_id =
        config->authorization.peer_leaf.runtime_id;
    descriptor->attachment_authority_id =
        config->authorization.local_leaf.authority_id;
    (void)memcpy(
        descriptor->attachment_binding_digest,
        config->authorization.local_leaf.authorized_attachment_binding_digest,
        sizeof(descriptor->attachment_binding_digest));
    descriptor->maximum_packet_bytes = 1925u;
    descriptor->maximum_transfer_bytes = 1925u;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision =
        config->authorization.credential_revision;
    (void)memcpy(
        descriptor->configuration_digest,
        config->authorization.credential_reference_digest,
        sizeof(descriptor->configuration_digest));

    config->storage_namespace.data = storage_namespace;
    config->storage_namespace.length =
        (uint32_t)(sizeof(storage_namespace) - 1u);
    config->storage = storage;
    config->clock = clock;
    config->execution = execution;
}

static int create_fabric(
    ninlil_test_storage_t *storage,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution,
    fabric_workspace_t *workspace,
    ninlil_fabric_v1_t **out_fabric)
{
    ninlil_fabric_config_v1_t config;

    (void)memset(&config, 0, sizeof(config));
    config.api_version = NINLIL_FABRIC_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = ninlil_test_storage_ops(storage);
    config.clock = clock;
    config.execution = execution;
    (void)memset(workspace, 0, sizeof(*workspace));
    return ninlil_fabric_v1_create(
               &config, workspace->bytes, NINLIL_FABRIC_WORKSPACE_BYTES,
               out_fabric)
        == NINLIL_FABRIC_OK;
}

static int close_fabric(ninlil_fabric_v1_t *fabric)
{
    uint32_t done = 0u;
    CHECK(ninlil_fabric_v1_close_begin(fabric) == NINLIL_FABRIC_OK);
    CHECK(ninlil_fabric_v1_close_poll(fabric, &done) == NINLIL_FABRIC_OK);
    CHECK(done == 1u);
    CHECK(ninlil_fabric_v1_destroy(fabric) == NINLIL_FABRIC_OK);
    return 1;
}

static int test_registration_lifecycle(void)
{
    const ninlil_test_storage_config_t storage_config = {
        4u, 600u, 600000u};
    test_environment_t environment;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_test_storage_t *storage;
    ninlil_test_storage_t *other_storage;
    ninlil_fabric_v1_t *fabric = NULL;
    ninlil_fabric_v1_t *other_fabric = NULL;
    ninlil_posix_tls_config_v1_t port_config;
    ninlil_posix_tls_v1_t *port = NULL;
    ninlil_posix_tls_registration_v1_t *registration = NULL;
    ninlil_posix_tls_registration_v1_t *duplicate =
        (ninlil_posix_tls_registration_v1_t *)(uintptr_t)1u;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_link_state_v1_t link_state;
    ninlil_posix_tls_state_v1_t port_state;
    uint32_t done = 99u;
    uint32_t work_done = 0u;

    init_clock_execution(&environment, &clock, &execution);
    storage = ninlil_test_storage_create(&storage_config);
    other_storage = ninlil_test_storage_create(&storage_config);
    CHECK(storage != NULL && other_storage != NULL);
    CHECK(create_fabric(
        storage, &clock, &execution, &g_fabric_workspace, &fabric));
    init_port_config(
        &port_config, ninlil_test_storage_ops(storage), &clock, &execution,
        0x21u);
    (void)memset(&g_port_workspace, 0xa5, sizeof(g_port_workspace));
    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_port_workspace.bytes, PORT_WORKSPACE_BYTES,
              &port)
          == NINLIL_POSIX_TLS_OK);

    environment.context_id = 2u;
    CHECK(create_fabric(
        other_storage, &clock, &execution, &g_other_fabric_workspace,
        &other_fabric));
    environment.context_id = 1u;
    CHECK(ninlil_posix_tls_v1_register_fabric(
              port, other_fabric, &registration)
          == NINLIL_POSIX_TLS_WRONG_THREAD);
    CHECK(registration == NULL);

    environment.reenter_port = port;
    environment.reenter_at_call = environment.execution_calls + 3u;
    environment.nested_status = NINLIL_POSIX_TLS_OK;
    CHECK(ninlil_posix_tls_v1_register_fabric(
              port, fabric, &registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(registration != NULL);
    CHECK(environment.nested_status == NINLIL_POSIX_TLS_REENTRANT);
    environment.reenter_at_call = 0u;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    (void)memset(&link_state, 0, sizeof(link_state));
    CHECK(ninlil_fabric_v1_link_snapshot(
              fabric, &port_config.instance_id, &descriptor, &link_state)
          == NINLIL_FABRIC_OK);
    CHECK(memcmp(
              &descriptor, &port_config.link_descriptor,
              sizeof(descriptor)) == 0);
    CHECK(link_state.api_version == NINLIL_FABRIC_API_VERSION);
    CHECK(link_state.struct_size == (uint16_t)sizeof(link_state));
    CHECK(link_state.availability_epoch == 1u);
    CHECK(link_state.available == 0u);
    CHECK(memcmp(
              &link_state.availability_clock_epoch_id,
              &environment.clock_epoch_id,
              sizeof(environment.clock_epoch_id)) == 0);

    CHECK(ninlil_posix_tls_v1_register_fabric(port, fabric, &duplicate)
          == NINLIL_POSIX_TLS_DENIED);
    CHECK(duplicate == NULL);
    duplicate = (ninlil_posix_tls_registration_v1_t *)(uintptr_t)1u;
    CHECK(ninlil_posix_tls_v1_register_fabric(
              port, other_fabric, &duplicate)
          == NINLIL_POSIX_TLS_DENIED);
    CHECK(duplicate == NULL);

    environment.context_id = 2u;
    CHECK(ninlil_posix_tls_v1_unregister_begin(port, registration)
          == NINLIL_POSIX_TLS_WRONG_THREAD);
    environment.context_id = 1u;
    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(done == 0u);
    CHECK(ninlil_posix_tls_v1_destroy(port)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(ninlil_posix_tls_v1_unregister_begin(port, registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_unregister_poll(port, registration, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    done = 99u;
    CHECK(ninlil_posix_tls_v1_unregister_poll(port, registration, &done)
          == NINLIL_POSIX_TLS_INVALID_ARGUMENT);
    CHECK(done == 0u);
    CHECK(ninlil_posix_tls_v1_step(port, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_state(port, &port_state)
          == NINLIL_POSIX_TLS_OK);
    CHECK(port_state.operational_state == NINLIL_POSIX_TLS_STATE_CLOSED);
    CHECK(ninlil_posix_tls_v1_destroy(port) == NINLIL_POSIX_TLS_OK);

    CHECK(close_fabric(fabric));
    environment.context_id = 2u;
    CHECK(close_fabric(other_fabric));
    environment.context_id = 1u;
    CHECK(ninlil_test_storage_live_handles(storage) == 0u);
    CHECK(ninlil_test_storage_live_handles(other_storage) == 0u);
    ninlil_test_storage_destroy(storage);
    ninlil_test_storage_destroy(other_storage);
    return 1;
}

static int test_register_commit_unknown_fences(void)
{
    const ninlil_test_storage_config_t storage_config = {
        4u, 600u, 600000u};
    test_environment_t environment;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_test_storage_t *storage;
    ninlil_fabric_v1_t *fabric = NULL;
    ninlil_posix_tls_config_v1_t port_config;
    ninlil_posix_tls_v1_t *port = NULL;
    ninlil_posix_tls_registration_v1_t *registration =
        (ninlil_posix_tls_registration_v1_t *)(uintptr_t)1u;
    ninlil_posix_tls_state_v1_t state;
    uint32_t done = 0u;
    uint32_t work_done = 0u;

    init_clock_execution(&environment, &clock, &execution);
    storage = ninlil_test_storage_create(&storage_config);
    CHECK(storage != NULL);
    CHECK(create_fabric(
        storage, &clock, &execution, &g_commit_unknown_fabric_workspace,
        &fabric));
    init_port_config(
        &port_config, ninlil_test_storage_ops(storage), &clock, &execution,
        0x31u);
    (void)memset(
        &g_commit_unknown_port_workspace, 0xa5,
        sizeof(g_commit_unknown_port_workspace));
    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_commit_unknown_port_workspace.bytes,
              PORT_WORKSPACE_BYTES, &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_test_storage_fault_enqueue(
        storage, NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, 0));
    CHECK(ninlil_posix_tls_v1_register_fabric(
              port, fabric, &registration)
          == NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN);
    CHECK(registration == NULL);
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_STORAGE);
    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_step(port, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_destroy(port) == NINLIL_POSIX_TLS_OK);
    CHECK(close_fabric(fabric));
    CHECK(ninlil_test_storage_live_handles(storage) == 0u);
    ninlil_test_storage_destroy(storage);
    return 1;
}

static int cleanup_restart_fenced_port(ninlil_posix_tls_v1_t *port)
{
    uint32_t done = 0u;

    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_destroy(port) == NINLIL_POSIX_TLS_OK);
    return 1;
}

static int test_dirty_restart_fences(void)
{
    const ninlil_test_storage_config_t storage_config = {
        4u, 600u, 600000u};
    test_environment_t environment;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_test_storage_t *storage;
    ninlil_posix_tls_config_v1_t port_config;
    ninlil_posix_tls_v1_t *port = NULL;
    ninlil_posix_tls_state_v1_t state;
    uint32_t work_done = 99u;

    init_clock_execution(&environment, &clock, &execution);
    storage = ninlil_test_storage_create(&storage_config);
    CHECK(storage != NULL);
    init_port_config(
        &port_config, ninlil_test_storage_ops(storage), &clock, &execution,
        0x41u);
    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_port_workspace.bytes, PORT_WORKSPACE_BYTES,
              &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(port != NULL);

    ninlil_test_storage_simulate_crash(storage);
    port = NULL;
    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_port_workspace.bytes, PORT_WORKSPACE_BYTES,
              &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(port != NULL);
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_STORAGE);
    CHECK(ninlil_posix_tls_v1_step(port, 1u, &work_done)
          == NINLIL_POSIX_TLS_DENIED);
    CHECK(work_done == 0u);
    CHECK(cleanup_restart_fenced_port(port));

    ninlil_test_storage_simulate_crash(storage);
    port = NULL;
    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_port_workspace.bytes, PORT_WORKSPACE_BYTES,
              &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(cleanup_restart_fenced_port(port));
    CHECK(ninlil_test_storage_live_handles(storage) == 0u);
    ninlil_test_storage_destroy(storage);
    return 1;
}

static int test_create_and_clean_marker_commit_unknown(void)
{
    const ninlil_test_storage_config_t storage_config = {
        4u, 600u, 600000u};
    test_environment_t environment;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_test_storage_t *storage;
    ninlil_posix_tls_config_v1_t port_config;
    ninlil_posix_tls_v1_t *port =
        (ninlil_posix_tls_v1_t *)(uintptr_t)1u;
    ninlil_posix_tls_state_v1_t state;
    uint32_t done = 99u;
    uint32_t work_done = 99u;

    init_clock_execution(&environment, &clock, &execution);
    storage = ninlil_test_storage_create(&storage_config);
    CHECK(storage != NULL);
    init_port_config(
        &port_config, ninlil_test_storage_ops(storage), &clock, &execution,
        0x51u);
    CHECK(ninlil_test_storage_fault_enqueue(
        storage, NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, 0));
    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_commit_unknown_port_workspace.bytes,
              PORT_WORKSPACE_BYTES, &port)
          == NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN);
    CHECK(port == NULL);

    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_commit_unknown_port_workspace.bytes,
              PORT_WORKSPACE_BYTES, &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(port != NULL);
    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_test_storage_fault_enqueue(
        storage, NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, 0));
    CHECK(ninlil_posix_tls_v1_step(port, 1u, &work_done)
          == NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN);
    CHECK(work_done == 0u);
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_STORAGE);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN);
    CHECK(done == 0u);
    CHECK(ninlil_posix_tls_v1_destroy(port)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);

    ninlil_test_storage_simulate_crash(storage);
    port = NULL;
    CHECK(ninlil_posix_tls_v1_create(
              &port_config, g_commit_unknown_port_workspace.bytes,
              PORT_WORKSPACE_BYTES, &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(cleanup_restart_fenced_port(port));
    CHECK(ninlil_test_storage_live_handles(storage) == 0u);
    ninlil_test_storage_destroy(storage);
    return 1;
}

int main(void)
{
    CHECK(test_registration_lifecycle());
    CHECK(test_register_commit_unknown_fences());
    CHECK(test_dirty_restart_fences());
    CHECK(test_create_and_clean_marker_commit_unknown());
    (void)puts("posix_tls_v1_registration: PASS");
    return 0;
}
