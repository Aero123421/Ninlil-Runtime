/* SPDX-License-Identifier: Apache-2.0 */
#include <ninlil/posix_tls_v1.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_WORKSPACE_BYTES 16384u

#define CHECK(condition_)                                                   \
    do {                                                                    \
        if (!(condition_)) {                                                \
            (void)fprintf(                                                  \
                stderr, "posix_tls_v1_lifecycle:%d: %s\n", __LINE__,       \
                #condition_);                                               \
            return 0;                                                       \
        }                                                                   \
    } while (0)

typedef union test_workspace {
    max_align_t alignment;
    uint8_t bytes[TEST_WORKSPACE_BYTES];
} test_workspace_t;

typedef struct test_environment {
    uint64_t context_id;
    uint64_t now_ms;
    ninlil_id128_t clock_epoch_id;
    uint32_t execution_calls;
    uint32_t clock_calls;
    uint32_t storage_calls;
    uint8_t reenter;
    ninlil_posix_tls_v1_t *port;
    ninlil_posix_tls_status_t nested_status;
    ninlil_posix_tls_state_v1_t nested_state;
    uint32_t transaction_mode;
    uint32_t lifecycle_length;
    uint32_t staged_length;
    uint8_t lifecycle_present;
    uint8_t staged_present;
    uint8_t lifecycle_value[256];
    uint8_t staged_value[256];
} test_environment_t;

typedef struct test_fixture {
    test_environment_t environment;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_posix_tls_config_v1_t config;
    char ca_path[32];
    char cert_path[32];
    char key_path[32];
    uint8_t storage_namespace[16];
    test_workspace_t workspace;
} test_fixture_t;

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

static uint64_t fake_current_context_id(void *user)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->execution_calls += 1u;
    if (environment->reenter != 0u && environment->port != NULL) {
        (void)memset(
            &environment->nested_state, 0xa5,
            sizeof(environment->nested_state));
        environment->nested_status = ninlil_posix_tls_v1_state(
            environment->port, &environment->nested_state);
    }
    return environment->context_id;
}

static ninlil_port_status_t fake_now(
    void *user, ninlil_time_sample_t *out_sample)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->clock_calls += 1u;
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

static ninlil_storage_status_t fake_storage_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->storage_calls += 1u;
    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    if (storage_namespace.data == NULL || storage_namespace.length == 0u
        || expected_schema != NINLIL_STORAGE_SCHEMA_M1A
        || out_handle == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out_handle = (ninlil_storage_handle_t)environment;
    return NINLIL_STORAGE_OK;
}

static void fake_storage_close(void *user, ninlil_storage_handle_t handle)
{
    test_environment_t *environment = (test_environment_t *)user;
    (void)handle;
    environment->storage_calls += 1u;
}

static ninlil_storage_status_t fake_storage_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    test_environment_t *environment = (test_environment_t *)user;
    (void)mode;
    environment->storage_calls += 1u;
    if (out_txn != NULL) {
        *out_txn = NULL;
    }
    if (handle != (ninlil_storage_handle_t)environment || out_txn == NULL
        || (mode != NINLIL_STORAGE_READ_ONLY
            && mode != NINLIL_STORAGE_READ_WRITE)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    environment->transaction_mode = mode;
    environment->staged_present = 0u;
    environment->staged_length = 0u;
    *out_txn = (ninlil_storage_txn_t)environment;
    return NINLIL_STORAGE_OK;
}

static int fake_key_is_lifecycle(ninlil_bytes_view_t key)
{
    static const char expected[] = "lifecycle.full.v1";
    return key.data != NULL
        && key.length == (uint32_t)(sizeof(expected) - 1u)
        && memcmp(key.data, expected, sizeof(expected) - 1u) == 0;
}

static ninlil_storage_status_t fake_storage_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->storage_calls += 1u;
    if (txn != (ninlil_storage_txn_t)environment || inout_value == NULL
        || inout_value->data == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    inout_value->length = 0u;
    if (!fake_key_is_lifecycle(key)
        || environment->lifecycle_present == 0u) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (inout_value->capacity < environment->lifecycle_length) {
        inout_value->length = environment->lifecycle_length;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    memcpy(
        inout_value->data,
        environment->lifecycle_value,
        environment->lifecycle_length);
    inout_value->length = environment->lifecycle_length;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t fake_storage_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->storage_calls += 1u;
    if (txn != (ninlil_storage_txn_t)environment
        || environment->transaction_mode != NINLIL_STORAGE_READ_WRITE
        || !fake_key_is_lifecycle(key) || value.data == NULL
        || value.length == 0u
        || value.length > sizeof(environment->staged_value)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    memcpy(environment->staged_value, value.data, value.length);
    environment->staged_length = value.length;
    environment->staged_present = 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t fake_storage_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    test_environment_t *environment = (test_environment_t *)user;
    (void)txn;
    (void)key;
    environment->storage_calls += 1u;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t fake_storage_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    test_environment_t *environment = (test_environment_t *)user;
    (void)txn;
    (void)prefix;
    environment->storage_calls += 1u;
    if (out_iter != NULL) {
        *out_iter = NULL;
    }
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t fake_storage_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    test_environment_t *environment = (test_environment_t *)user;
    (void)iter;
    (void)inout_key;
    (void)inout_value;
    environment->storage_calls += 1u;
    return NINLIL_STORAGE_IO_ERROR;
}

static void fake_storage_iter_close(void *user, ninlil_storage_iter_t iter)
{
    test_environment_t *environment = (test_environment_t *)user;
    (void)iter;
    environment->storage_calls += 1u;
}

static ninlil_storage_status_t fake_storage_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    test_environment_t *environment = (test_environment_t *)user;
    (void)handle;
    (void)out_capacity;
    environment->storage_calls += 1u;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t fake_storage_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t durability)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->storage_calls += 1u;
    if (txn != (ninlil_storage_txn_t)environment
        || environment->transaction_mode != NINLIL_STORAGE_READ_WRITE
        || durability != NINLIL_DURABILITY_FULL
        || environment->staged_present == 0u) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    memcpy(
        environment->lifecycle_value,
        environment->staged_value,
        environment->staged_length);
    environment->lifecycle_length = environment->staged_length;
    environment->lifecycle_present = 1u;
    environment->transaction_mode = 0u;
    environment->staged_present = 0u;
    environment->staged_length = 0u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t fake_storage_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    test_environment_t *environment = (test_environment_t *)user;
    environment->storage_calls += 1u;
    if (txn != (ninlil_storage_txn_t)environment) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    environment->transaction_mode = 0u;
    environment->staged_present = 0u;
    environment->staged_length = 0u;
    return NINLIL_STORAGE_OK;
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

static void init_fixture(test_fixture_t *fixture)
{
    ninlil_fabric_link_descriptor_v1_t *descriptor;

    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->environment.context_id = 41u;
    fixture->environment.now_ms = 1000u;
    fill_id(&fixture->environment.clock_epoch_id, 0x11u);

    fixture->storage.abi_version = NINLIL_ABI_VERSION;
    fixture->storage.struct_size = (uint16_t)sizeof(fixture->storage);
    fixture->storage.user = &fixture->environment;
    fixture->storage.open = fake_storage_open;
    fixture->storage.close = fake_storage_close;
    fixture->storage.begin = fake_storage_begin;
    fixture->storage.get = fake_storage_get;
    fixture->storage.put = fake_storage_put;
    fixture->storage.erase = fake_storage_erase;
    fixture->storage.iter_open = fake_storage_iter_open;
    fixture->storage.iter_next = fake_storage_iter_next;
    fixture->storage.iter_close = fake_storage_iter_close;
    fixture->storage.capacity = fake_storage_capacity;
    fixture->storage.commit = fake_storage_commit;
    fixture->storage.rollback = fake_storage_rollback;

    fixture->clock.abi_version = NINLIL_ABI_VERSION;
    fixture->clock.struct_size = (uint16_t)sizeof(fixture->clock);
    fixture->clock.user = &fixture->environment;
    fixture->clock.now = fake_now;
    fixture->execution.abi_version = NINLIL_ABI_VERSION;
    fixture->execution.struct_size = (uint16_t)sizeof(fixture->execution);
    fixture->execution.user = &fixture->environment;
    fixture->execution.current_context_id = fake_current_context_id;

    (void)memcpy(fixture->ca_path, "/tmp/ca.pem", sizeof("/tmp/ca.pem"));
    (void)memcpy(
        fixture->cert_path, "/tmp/cert.pem", sizeof("/tmp/cert.pem"));
    (void)memcpy(
        fixture->key_path, "/tmp/key.pem", sizeof("/tmp/key.pem"));
    fill_bytes(
        fixture->storage_namespace, sizeof(fixture->storage_namespace), 0x31u);
    (void)memset(fixture->workspace.bytes, 0xa5, TEST_WORKSPACE_BYTES);

    fixture->config.api_version = NINLIL_POSIX_TLS_API_VERSION;
    fixture->config.struct_size = (uint16_t)sizeof(fixture->config);
    fixture->config.role = NINLIL_POSIX_TLS_ROLE_CLIENT;
    fill_id(&fixture->config.instance_id, 0x21u);
    fixture->config.endpoint.api_version = NINLIL_POSIX_TLS_API_VERSION;
    fixture->config.endpoint.struct_size =
        (uint16_t)sizeof(fixture->config.endpoint);
    fixture->config.endpoint.address_kind = NINLIL_POSIX_TLS_ADDRESS_IPV4;
    fixture->config.endpoint.port = 443u;
    fixture->config.endpoint.address[0] = 127u;
    fixture->config.endpoint.address[3] = 1u;
    fixture->config.tls_paths.api_version = NINLIL_POSIX_TLS_API_VERSION;
    fixture->config.tls_paths.struct_size =
        (uint16_t)sizeof(fixture->config.tls_paths);
    fixture->config.tls_paths.ca_pem_path = fixture->ca_path;
    fixture->config.tls_paths.cert_pem_path = fixture->cert_path;
    fixture->config.tls_paths.key_pem_path = fixture->key_path;
    fixture->config.authorization.api_version =
        NINLIL_POSIX_TLS_API_VERSION;
    fixture->config.authorization.struct_size =
        (uint16_t)sizeof(fixture->config.authorization);
    fixture->config.authorization.assignment_epoch = 2u;
    init_leaf(
        &fixture->config.authorization.local_leaf,
        NINLIL_POSIX_TLS_ROLE_CLIENT, 0x41u, 7u);
    init_leaf(
        &fixture->config.authorization.peer_leaf,
        NINLIL_POSIX_TLS_ROLE_SERVER, 0x81u, 9u);
    fixture->config.authorization.peer_leaf.authority_id =
        fixture->config.authorization.local_leaf.authority_id;
    fixture->config.authorization.peer_leaf.authority_term =
        fixture->config.authorization.local_leaf.authority_term;
    (void)memcpy(
        fixture->config.authorization.peer_leaf
            .authorized_attachment_binding_digest,
        fixture->config.authorization.local_leaf
            .authorized_attachment_binding_digest,
        sizeof(fixture->config.authorization.peer_leaf
                   .authorized_attachment_binding_digest));
    fill_id(&fixture->config.authorization.registry_epoch_id, 0xc1u);
    fill_bytes(
        fixture->config.authorization.credential_reference_digest, 32u,
        0xd1u);
    fixture->config.authorization.credential_revision = 7u;

    descriptor = &fixture->config.link_descriptor;
    descriptor->api_version = NINLIL_FABRIC_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    descriptor->instance_id = fixture->config.instance_id;
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
        fixture->environment.clock_epoch_id;
    descriptor->attestation_expires_at_ms = 2000u;
    fill_bytes(descriptor->attestation_digest, 32u, 0x72u);
    descriptor->authenticated_peer_runtime_id =
        fixture->config.authorization.peer_leaf.runtime_id;
    descriptor->attachment_authority_id =
        fixture->config.authorization.local_leaf.authority_id;
    (void)memcpy(
        descriptor->attachment_binding_digest,
        fixture->config.authorization.local_leaf
            .authorized_attachment_binding_digest,
        sizeof(descriptor->attachment_binding_digest));
    descriptor->maximum_packet_bytes = 1925u;
    descriptor->maximum_transfer_bytes = 1925u;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision =
        fixture->config.authorization.credential_revision;
    (void)memcpy(
        descriptor->configuration_digest,
        fixture->config.authorization.credential_reference_digest,
        sizeof(descriptor->configuration_digest));

    fixture->config.storage_namespace.data = fixture->storage_namespace;
    fixture->config.storage_namespace.length =
        (uint32_t)sizeof(fixture->storage_namespace);
    fixture->config.storage = &fixture->storage;
    fixture->config.clock = &fixture->clock;
    fixture->config.execution = &fixture->execution;
}

static int bytes_equal_value(
    const uint8_t *bytes, size_t count, uint8_t expected)
{
    size_t i;
    for (i = 0u; i < count; ++i) {
        if (bytes[i] != expected) {
            return 0;
        }
    }
    return 1;
}

static int expect_invalid_create(test_fixture_t *fixture)
{
    ninlil_posix_tls_v1_t *port = (ninlil_posix_tls_v1_t *)(uintptr_t)1u;
    CHECK(ninlil_posix_tls_v1_create(
              &fixture->config, fixture->workspace.bytes,
              TEST_WORKSPACE_BYTES, &port)
          == NINLIL_POSIX_TLS_INVALID_ARGUMENT);
    CHECK(port == NULL);
    CHECK(bytes_equal_value(
        fixture->workspace.bytes, TEST_WORKSPACE_BYTES, 0xa5u));
    CHECK(fixture->environment.storage_calls == 0u);
    return 1;
}

static int test_create_validation(void)
{
    test_fixture_t fixture;

    init_fixture(&fixture);
    fixture.storage.capacity = NULL;
    CHECK(expect_invalid_create(&fixture));
    CHECK(fixture.environment.execution_calls == 0u);
    CHECK(fixture.environment.clock_calls == 0u);

    init_fixture(&fixture);
    fixture.ca_path[1] = (char)0xc0;
    CHECK(expect_invalid_create(&fixture));
    CHECK(fixture.environment.execution_calls == 0u);

    init_fixture(&fixture);
    (void)memset(
        fixture.config.authorization.peer_leaf.leaf_spki_sha256, 0, 32u);
    CHECK(expect_invalid_create(&fixture));

    init_fixture(&fixture);
    fixture.config.authorization.peer_leaf.authority_id.bytes[0] ^= 0x01u;
    CHECK(expect_invalid_create(&fixture));
    CHECK(fixture.environment.execution_calls == 0u);
    CHECK(fixture.environment.clock_calls == 0u);

    init_fixture(&fixture);
    fixture.config.authorization.credential_revision = 8u;
    fixture.config.link_descriptor.configuration_revision = 8u;
    CHECK(expect_invalid_create(&fixture));

    init_fixture(&fixture);
    fixture.config.link_descriptor.direction_mask =
        NINLIL_FABRIC_LINK_DIRECTION_SEND;
    CHECK(expect_invalid_create(&fixture));
    CHECK(fixture.environment.execution_calls == 1u);
    CHECK(fixture.environment.clock_calls == 1u);

    init_fixture(&fixture);
    fixture.config.link_descriptor.attestation_expires_at_ms =
        fixture.environment.now_ms;
    CHECK(expect_invalid_create(&fixture));
    CHECK(fixture.environment.execution_calls == 1u);
    CHECK(fixture.environment.clock_calls == 1u);

    init_fixture(&fixture);
    fixture.environment.context_id = 0u;
    {
        ninlil_posix_tls_v1_t *port =
            (ninlil_posix_tls_v1_t *)(uintptr_t)1u;
        CHECK(ninlil_posix_tls_v1_create(
                  &fixture.config, fixture.workspace.bytes,
                  TEST_WORKSPACE_BYTES, &port)
              == NINLIL_POSIX_TLS_WRONG_THREAD);
        CHECK(port == NULL);
        CHECK(bytes_equal_value(
            fixture.workspace.bytes, TEST_WORKSPACE_BYTES, 0xa5u));
        CHECK(fixture.environment.clock_calls == 0u);
    }
    return 1;
}

static int test_lifecycle(void)
{
    test_fixture_t fixture;
    ninlil_posix_tls_v1_t *port = NULL;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_link_descriptor_v1_t expected_descriptor;
    ninlil_posix_tls_state_v1_t state;
    uint32_t required_bytes = 99u;
    uint32_t required_alignment = 99u;
    uint32_t done = 99u;
    uint32_t work_done = 0u;

    init_fixture(&fixture);
    CHECK(ninlil_posix_tls_v1_workspace_required(
              &required_bytes, &required_alignment)
          == NINLIL_POSIX_TLS_OK);
    CHECK(required_bytes <= TEST_WORKSPACE_BYTES);
    CHECK(required_alignment <= _Alignof(test_workspace_t));
    CHECK(ninlil_posix_tls_v1_create(
              &fixture.config, fixture.workspace.bytes,
              TEST_WORKSPACE_BYTES, &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(port != NULL);
    fixture.environment.port = port;
    expected_descriptor = fixture.config.link_descriptor;
    CHECK(fixture.environment.execution_calls == 1u);
    CHECK(fixture.environment.clock_calls == 1u);
    CHECK(fixture.environment.storage_calls != 0u);
    CHECK(fixture.environment.lifecycle_present == 1u);
    CHECK(fixture.environment.lifecycle_length == 112u);
    CHECK(memcmp(fixture.environment.lifecycle_value, "PTR1", 4u) == 0);
    CHECK(fixture.environment.lifecycle_value[4] == 0u);
    CHECK(fixture.environment.lifecycle_value[5] == 1u);
    CHECK(fixture.environment.lifecycle_value[6] == 5u);
    CHECK(fixture.environment.lifecycle_value[7] == 1u);
    CHECK(fixture.environment.lifecycle_value[11] == 100u);
    CHECK(fixture.environment.lifecycle_value[12] == 0u);
    CHECK(fixture.environment.lifecycle_value[13] == 1u);
    CHECK(fixture.environment.lifecycle_value[14] == 0u);
    CHECK(fixture.environment.lifecycle_value[15] == 0u);
    CHECK(fixture.environment.lifecycle_value[23] == 1u);
    CHECK(memcmp(
              &fixture.environment.lifecycle_value[24],
              fixture.config.instance_id.bytes,
              16u) == 0);
    CHECK(memcmp(
              &fixture.environment.lifecycle_value[40],
              fixture.config.link_descriptor.descriptor_digest,
              32u) == 0);
    CHECK(memcmp(
              &fixture.environment.lifecycle_value[80],
              fixture.config.link_descriptor.configuration_digest,
              32u) == 0);

    (void)memset(&state, 0xa5, sizeof(state));
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.api_version == NINLIL_POSIX_TLS_API_VERSION);
    CHECK(state.struct_size == (uint16_t)sizeof(state));
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_CREATED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_NONE);
    CHECK(state.availability_epoch == 1u);
    CHECK(state.local_port == 0u);

    (void)memset(fixture.ca_path, 0, sizeof(fixture.ca_path));
    (void)memset(fixture.cert_path, 0, sizeof(fixture.cert_path));
    (void)memset(fixture.key_path, 0, sizeof(fixture.key_path));
    (void)memset(
        fixture.storage_namespace, 0, sizeof(fixture.storage_namespace));
    (void)memset(&fixture.config.link_descriptor, 0,
                 sizeof(fixture.config.link_descriptor));
    fixture.execution.current_context_id = NULL;
    (void)memset(&descriptor, 0, sizeof(descriptor));
    CHECK(ninlil_posix_tls_v1_descriptor_snapshot(port, &descriptor)
          == NINLIL_POSIX_TLS_OK);
    CHECK(memcmp(
              &descriptor, &expected_descriptor, sizeof(descriptor)) == 0);

    fixture.environment.context_id = 42u;
    (void)memset(&state, 0xa5, sizeof(state));
    CHECK(ninlil_posix_tls_v1_state(port, &state)
          == NINLIL_POSIX_TLS_WRONG_THREAD);
    CHECK(bytes_equal_value((const uint8_t *)&state, sizeof(state), 0u));
    fixture.environment.context_id = 41u;

    fixture.environment.reenter = 1u;
    fixture.environment.nested_status = NINLIL_POSIX_TLS_OK;
    CHECK(ninlil_posix_tls_v1_descriptor_snapshot(port, &descriptor)
          == NINLIL_POSIX_TLS_OK);
    CHECK(fixture.environment.nested_status == NINLIL_POSIX_TLS_REENTRANT);
    CHECK(bytes_equal_value(
        (const uint8_t *)&fixture.environment.nested_state,
        sizeof(fixture.environment.nested_state), 0u));
    fixture.environment.reenter = 0u;

    CHECK(ninlil_posix_tls_v1_destroy(port)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(done == 0u);
    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_DRAINING);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_LOCAL_CLOSE);
    CHECK(ninlil_posix_tls_v1_step(port, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(fixture.environment.lifecycle_value[14] == 1u);
    CHECK(fixture.environment.lifecycle_value[15] == 0u);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_state(port, &state) == NINLIL_POSIX_TLS_OK);
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_CLOSED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_LOCAL_CLOSE);
    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_CLOSED);
    done = 0u;
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(fixture.environment.storage_calls != 0u);
    CHECK(ninlil_posix_tls_v1_destroy(port) == NINLIL_POSIX_TLS_OK);
    CHECK(bytes_equal_value(
        fixture.workspace.bytes, TEST_WORKSPACE_BYTES, 0u));
    (void)memset(&state, 0xa5, sizeof(state));
    CHECK(ninlil_posix_tls_v1_state(port, &state)
          == NINLIL_POSIX_TLS_INVALID_ARGUMENT);
    CHECK(bytes_equal_value((const uint8_t *)&state, sizeof(state), 0u));
    return 1;
}

static int test_server_ephemeral_port(void)
{
    test_fixture_t fixture;
    ninlil_posix_tls_v1_t *port = NULL;
    uint32_t done = 0u;
    uint32_t work_done = 0u;

    init_fixture(&fixture);
    fixture.config.role = NINLIL_POSIX_TLS_ROLE_SERVER;
    fixture.config.endpoint.port = 0u;
    (void)memset(fixture.config.endpoint.address, 0,
                 sizeof(fixture.config.endpoint.address));
    fixture.config.authorization.local_leaf.role =
        NINLIL_POSIX_TLS_ROLE_SERVER;
    fixture.config.authorization.peer_leaf.role =
        NINLIL_POSIX_TLS_ROLE_CLIENT;
    CHECK(ninlil_posix_tls_v1_create(
              &fixture.config, fixture.workspace.bytes,
              TEST_WORKSPACE_BYTES, &port)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_step(port, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_close_poll(port, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_destroy(port) == NINLIL_POSIX_TLS_OK);
    return 1;
}

int main(void)
{
    CHECK(test_create_validation());
    CHECK(test_lifecycle());
    CHECK(test_server_ephemeral_port());
    (void)puts("posix_tls_v1_lifecycle: PASS");
    return 0;
}
