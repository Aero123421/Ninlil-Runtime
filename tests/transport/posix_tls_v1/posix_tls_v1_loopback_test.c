/* SPDX-License-Identifier: Apache-2.0 */
#include <ninlil/posix_tls_v1.h>

#include "nfl1_codec.h"
#include "in_memory_storage.h"
#include "posix_tls_v1_test_hooks.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PORT_WORKSPACE_BYTES 16384u

#define CHECK(condition_)                                                   \
    do {                                                                    \
        if (!(condition_)) {                                                \
            (void)fprintf(                                                  \
                stderr, "posix_tls_v1_loopback:%d: %s\n", __LINE__,       \
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
    int reenter;
    ninlil_posix_tls_v1_t *reenter_port;
    ninlil_posix_tls_status_t nested_status;
    uint32_t nested_work_done;
} test_environment_t;

static port_workspace_t g_server_workspace;
static port_workspace_t g_client_workspace;
static fabric_workspace_t g_fabric_workspace;

static void fill_bytes(uint8_t *bytes, size_t count, uint8_t value)
{
    size_t i;
    for (i = 0u; i < count; ++i) {
        bytes[i] = value;
    }
}

static void fill_runtime_id(ninlil_id128_t *id, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < sizeof(id->bytes); ++i) {
        id->bytes[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static int build_canonical_nfl1(
    uint8_t out_packet[587], uint8_t seed, uint32_t *out_length)
{
    static const uint8_t namespace_id = (uint8_t)'n';
    static const uint8_t service_id = (uint8_t)'s';
    static const uint8_t schema_id = (uint8_t)'x';
    ninlil_fabric_private_nfl1_envelope_t envelope;

    memset(&envelope, 0, sizeof(envelope));
    envelope.api_version = NINLIL_FABRIC_API_VERSION;
    envelope.struct_size = (uint16_t)sizeof(envelope);
    envelope.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    fill_runtime_id(&envelope.transaction_id, seed);
    fill_runtime_id(&envelope.attempt_id, (uint8_t)(seed + 1u));
    fill_runtime_id(&envelope.source_runtime_id, (uint8_t)(seed + 2u));
    fill_runtime_id(
        &envelope.source_application_id, (uint8_t)(seed + 3u));
    fill_runtime_id(&envelope.source_device_id, (uint8_t)(seed + 4u));
    fill_runtime_id(
        &envelope.source_installation_id, (uint8_t)(seed + 5u));
    fill_runtime_id(&envelope.source_site_id, (uint8_t)(seed + 6u));
    envelope.source_binding_epoch = 7u;
    envelope.source_membership_epoch = 9u;
    envelope.source_flags = 7u;
    fill_runtime_id(&envelope.target_runtime_id, (uint8_t)(seed + 7u));
    fill_runtime_id(
        &envelope.target_application_id, (uint8_t)(seed + 8u));
    fill_runtime_id(&envelope.target_device_id, (uint8_t)(seed + 9u));
    fill_runtime_id(
        &envelope.target_installation_id, (uint8_t)(seed + 10u));
    fill_runtime_id(&envelope.target_site_id, (uint8_t)(seed + 11u));
    envelope.target_binding_epoch = 11u;
    envelope.target_membership_epoch = 13u;
    envelope.target_flags = 7u;
    fill_runtime_id(&envelope.authority_id, (uint8_t)(seed + 12u));
    envelope.authority_term = 17u;
    envelope.assignment_epoch = 19u;
    envelope.descriptor_revision = 23u;
    envelope.descriptor_digest.algorithm = 1u;
    fill_bytes(envelope.descriptor_digest.bytes, 32u, 0x31u);
    envelope.schema_major = 1u;
    envelope.family = NINLIL_FAMILY_DESIRED_STATE;
    envelope.content_digest.algorithm = 1u;
    fill_bytes(envelope.content_digest.bytes, 32u, 0x32u);
    envelope.generation = 29u;
    fill_runtime_id(
        &envelope.deadline_clock_epoch_id, (uint8_t)(seed + 13u));
    envelope.absolute_effect_deadline_ms = 200000u;
    envelope.evidence_grace_ms = 5000u;
    envelope.required_evidence = NINLIL_EVIDENCE_VERIFIED;
    fill_runtime_id(&envelope.route_policy_id, (uint8_t)(seed + 14u));
    envelope.route_policy_revision = 31u;
    envelope.route_policy_digest.algorithm = 1u;
    fill_bytes(envelope.route_policy_digest.bytes, 32u, 0x33u);
    fill_runtime_id(&envelope.selected_path_id, (uint8_t)(seed + 15u));
    envelope.path_selection_epoch = 37u;
    envelope.namespace_id.bytes = &namespace_id;
    envelope.namespace_id.length = 1u;
    envelope.service_id.bytes = &service_id;
    envelope.service_id.length = 1u;
    envelope.schema_id.bytes = &schema_id;
    envelope.schema_id.length = 1u;
    return ninlil_fabric_private_nfl1_encode(
               &envelope, out_packet, 587u, out_length)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
        && *out_length == 587u;
}

static void init_packet_view(
    ninlil_fabric_packet_view_v1_t *view,
    ninlil_tx_permit_t *permit,
    const uint8_t *packet,
    uint32_t packet_length,
    const test_environment_t *environment,
    uint8_t seed)
{
    memset(view, 0, sizeof(*view));
    memset(permit, 0, sizeof(*permit));
    view->api_version = NINLIL_FABRIC_API_VERSION;
    view->struct_size = (uint16_t)sizeof(*view);
    view->bytes = packet;
    view->length = packet_length;
    fill_runtime_id(&view->transaction_id, seed);
    fill_runtime_id(&view->attempt_id, (uint8_t)(seed + 1u));
    fill_runtime_id(&view->selected_path_id, (uint8_t)(seed + 2u));
    view->path_selection_epoch = 1u;
    permit->abi_version = NINLIL_ABI_VERSION;
    permit->struct_size = (uint16_t)sizeof(*permit);
    fill_runtime_id(&permit->permit_id, (uint8_t)(seed + 3u));
    permit->attempt_id = view->attempt_id;
    permit->clock_epoch_id = environment->clock_epoch_id;
    permit->expires_at_ms = UINT64_MAX - 1u;
    view->permit = permit;
}

static uint64_t test_current_context_id(void *user)
{
    test_environment_t *environment = (test_environment_t *)user;
    if (environment->reenter != 0 && environment->reenter_port != NULL) {
        environment->reenter = 0;
        environment->nested_work_done = 99u;
        environment->nested_status = ninlil_posix_tls_v1_step(
            environment->reenter_port, 1u,
            &environment->nested_work_done);
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
    memset(out_sample, 0, sizeof(*out_sample));
    out_sample->abi_version = NINLIL_ABI_VERSION;
    out_sample->struct_size = (uint16_t)sizeof(*out_sample);
    out_sample->clock_epoch_id = environment->clock_epoch_id;
    out_sample->now_ms = environment->now_ms;
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static void init_platform(
    test_environment_t *environment,
    ninlil_clock_ops_t *clock,
    ninlil_execution_ops_t *execution)
{
    memset(environment, 0, sizeof(*environment));
    environment->context_id = 1u;
    environment->now_ms = 1000u;
    fill_runtime_id(&environment->clock_epoch_id, 0x11u);
    memset(clock, 0, sizeof(*clock));
    clock->abi_version = NINLIL_ABI_VERSION;
    clock->struct_size = (uint16_t)sizeof(*clock);
    clock->user = environment;
    clock->now = test_now;
    memset(execution, 0, sizeof(*execution));
    execution->abi_version = NINLIL_ABI_VERSION;
    execution->struct_size = (uint16_t)sizeof(*execution);
    execution->user = environment;
    execution->current_context_id = test_current_context_id;
}

static int make_path(
    char out[1024], const char *cert_dir, const char *name)
{
    int length = snprintf(out, 1024u, "%s/%s", cert_dir, name);
    return length > 0 && length < 1024;
}

static int certificate_spki_sha256(
    const char *path, uint8_t out_digest[32])
{
    BIO *bio = NULL;
    X509 *certificate = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *der = NULL;
    unsigned int digest_length = 0u;
    int der_length;
    int ok = 0;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        goto out;
    }
    certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (certificate == NULL) {
        goto out;
    }
    key = X509_get_pubkey(certificate);
    if (key == NULL) {
        goto out;
    }
    der_length = i2d_PUBKEY(key, &der);
    if (der_length <= 0 || der == NULL
        || EVP_Digest(
               der, (size_t)der_length, out_digest, &digest_length,
               EVP_sha256(), NULL)
            != 1
        || digest_length != 32u) {
        goto out;
    }
    ok = 1;
out:
    OPENSSL_free(der);
    EVP_PKEY_free(key);
    X509_free(certificate);
    BIO_free(bio);
    return ok;
}

static void init_leaf(
    ninlil_posix_tls_leaf_expectation_v1_t *leaf,
    uint32_t role,
    const uint8_t spki[32])
{
    memset(leaf, 0, sizeof(*leaf));
    leaf->api_version = NINLIL_POSIX_TLS_API_VERSION;
    leaf->struct_size = (uint16_t)sizeof(*leaf);
    leaf->role = role;
    fill_runtime_id(
        &leaf->runtime_id,
        role == NINLIL_POSIX_TLS_ROLE_CLIENT ? 0x31u : 0x32u);
    memcpy(leaf->leaf_spki_sha256, spki, 32u);
    fill_bytes(leaf->authority_id.bytes, 16u, 0xd0u);
    leaf->authority_id.bytes[15] = 0xdfu;
    leaf->authority_term = 7u;
    fill_bytes(leaf->authorized_attachment_binding_digest, 32u, 0xb1u);
    leaf->credential_generation = 1u;
    leaf->revocation_generation = 1u;
}

static int init_port_config(
    ninlil_posix_tls_config_v1_t *config,
    uint32_t role,
    uint16_t port,
    uint8_t instance_seed,
    const char *namespace_text,
    const char *cert_dir,
    const char *cert_name,
    const char *key_name,
    const ninlil_storage_ops_t *storage,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution)
{
    static char ca_path[1024];
    static char client_cert_path[1024];
    static char client_key_path[1024];
    static char server_cert_path[1024];
    char valid_client_cert_path[1024];
    uint8_t client_spki[32];
    uint8_t server_spki[32];
    ninlil_fabric_link_descriptor_v1_t *descriptor;
    ninlil_posix_tls_leaf_expectation_v1_t client_leaf;
    ninlil_posix_tls_leaf_expectation_v1_t server_leaf;

    if (!make_path(ca_path, cert_dir, "ca.cert.pem")
        || !make_path(
            client_cert_path, cert_dir,
            role == NINLIL_POSIX_TLS_ROLE_CLIENT ? cert_name
                                                 : "client.cert.pem")
        || !make_path(
            client_key_path, cert_dir,
            role == NINLIL_POSIX_TLS_ROLE_CLIENT ? key_name
                                                 : "client.key.pem")
        || !make_path(server_cert_path, cert_dir, "server.cert.pem")
        || !make_path(
            valid_client_cert_path, cert_dir, "client.cert.pem")
        || !certificate_spki_sha256(valid_client_cert_path, client_spki)
        || !certificate_spki_sha256(server_cert_path, server_spki)) {
        return 0;
    }
    init_leaf(&client_leaf, NINLIL_POSIX_TLS_ROLE_CLIENT, client_spki);
    init_leaf(&server_leaf, NINLIL_POSIX_TLS_ROLE_SERVER, server_spki);

    memset(config, 0, sizeof(*config));
    config->api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->struct_size = (uint16_t)sizeof(*config);
    config->role = role;
    fill_runtime_id(&config->instance_id, instance_seed);
    config->endpoint.api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->endpoint.struct_size = (uint16_t)sizeof(config->endpoint);
    config->endpoint.address_kind = NINLIL_POSIX_TLS_ADDRESS_IPV4;
    config->endpoint.port = port;
    config->endpoint.address[0] = 127u;
    config->endpoint.address[3] = 1u;
    config->tls_paths.api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->tls_paths.struct_size = (uint16_t)sizeof(config->tls_paths);
    config->tls_paths.ca_pem_path = ca_path;
    config->tls_paths.cert_pem_path = role == NINLIL_POSIX_TLS_ROLE_CLIENT
        ? client_cert_path : server_cert_path;
    config->tls_paths.key_pem_path = role == NINLIL_POSIX_TLS_ROLE_CLIENT
        ? client_key_path : NULL;
    if (role == NINLIL_POSIX_TLS_ROLE_SERVER) {
        static char server_key_path[1024];
        if (!make_path(server_key_path, cert_dir, "server.key.pem")) {
            return 0;
        }
        config->tls_paths.key_pem_path = server_key_path;
    }
    config->authorization.api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->authorization.struct_size =
        (uint16_t)sizeof(config->authorization);
    config->authorization.assignment_epoch = 11u;
    config->authorization.local_leaf =
        role == NINLIL_POSIX_TLS_ROLE_CLIENT ? client_leaf : server_leaf;
    config->authorization.peer_leaf =
        role == NINLIL_POSIX_TLS_ROLE_CLIENT ? server_leaf : client_leaf;
    fill_runtime_id(&config->authorization.registry_epoch_id, 0xe1u);
    fill_bytes(
        config->authorization.credential_reference_digest, 32u, 0xacu);
    config->authorization.credential_revision = 1u;

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
    fill_runtime_id(&descriptor->security_profile_id, 0x21u);
    descriptor->security_capability_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    fill_bytes(descriptor->security_binding_digest, 32u, 0x22u);
    descriptor->attestation_epoch = 1u;
    descriptor->attestation_clock_epoch_id =
        ((test_environment_t *)clock->user)->clock_epoch_id;
    descriptor->attestation_expires_at_ms = UINT64_MAX - 1u;
    fill_bytes(descriptor->attestation_digest, 32u, 0x23u);
    descriptor->authenticated_peer_runtime_id =
        config->authorization.peer_leaf.runtime_id;
    descriptor->attachment_authority_id =
        config->authorization.local_leaf.authority_id;
    memcpy(
        descriptor->attachment_binding_digest,
        config->authorization.local_leaf
            .authorized_attachment_binding_digest,
        32u);
    descriptor->maximum_packet_bytes = 587u;
    descriptor->maximum_transfer_bytes = 587u;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    memcpy(
        descriptor->configuration_digest,
        config->authorization.credential_reference_digest,
        32u);
    config->storage_namespace.data = (const uint8_t *)namespace_text;
    config->storage_namespace.length = (uint32_t)strlen(namespace_text);
    config->storage = storage;
    config->clock = clock;
    config->execution = execution;
    return 1;
}

static int create_port(
    const ninlil_posix_tls_config_v1_t *config,
    port_workspace_t *workspace,
    ninlil_posix_tls_v1_t **out_port)
{
    memset(workspace, 0xa5, sizeof(*workspace));
    return ninlil_posix_tls_v1_create(
               config, workspace->bytes, PORT_WORKSPACE_BYTES, out_port)
        == NINLIL_POSIX_TLS_OK;
}

static int port_state(
    ninlil_posix_tls_v1_t *port, ninlil_posix_tls_state_v1_t *out_state)
{
    memset(out_state, 0, sizeof(*out_state));
    return ninlil_posix_tls_v1_state(port, out_state)
        == NINLIL_POSIX_TLS_OK;
}

static int drive_server_listening(
    ninlil_posix_tls_v1_t *server, uint16_t *out_port)
{
    uint32_t i;
    for (i = 0u; i < 10000u; ++i) {
        ninlil_posix_tls_state_v1_t state;
        uint32_t work_done = 99u;
        ninlil_posix_tls_status_t status = ninlil_posix_tls_v1_step(
            server, 64u, &work_done);
        if (status != NINLIL_POSIX_TLS_OK
            && status != NINLIL_POSIX_TLS_WOULD_BLOCK) {
            return 0;
        }
        if (!port_state(server, &state)) {
            return 0;
        }
        if (state.operational_state == NINLIL_POSIX_TLS_STATE_LISTENING) {
            *out_port = state.local_port;
            return state.local_port != 0u;
        }
    }
    return 0;
}

static int drive_pair_to_state(
    ninlil_posix_tls_v1_t *server,
    ninlil_posix_tls_v1_t *client,
    uint32_t expected_state)
{
    uint32_t i;
    for (i = 0u; i < 20000u; ++i) {
        ninlil_posix_tls_state_v1_t server_state;
        ninlil_posix_tls_state_v1_t client_state;
        uint32_t server_work = 99u;
        uint32_t client_work = 99u;
        ninlil_posix_tls_status_t server_status =
            NINLIL_POSIX_TLS_WOULD_BLOCK;
        ninlil_posix_tls_status_t client_status =
            NINLIL_POSIX_TLS_WOULD_BLOCK;

        if (!port_state(server, &server_state)
            || !port_state(client, &client_state)) {
            return 0;
        }
        if (server_state.operational_state != expected_state) {
            server_status =
                ninlil_posix_tls_v1_step(server, 64u, &server_work);
        }
        if (client_state.operational_state != expected_state) {
            client_status =
                ninlil_posix_tls_v1_step(client, 64u, &client_work);
        }
        if ((server_status != NINLIL_POSIX_TLS_OK
             && server_status != NINLIL_POSIX_TLS_WOULD_BLOCK)
            || (client_status != NINLIL_POSIX_TLS_OK
                && client_status != NINLIL_POSIX_TLS_WOULD_BLOCK)
            || !port_state(server, &server_state)
            || !port_state(client, &client_state)) {
            return 0;
        }
        if (server_state.operational_state == expected_state
            && client_state.operational_state == expected_state) {
            return 1;
        }
    }
    return 0;
}

static int drive_authenticated(
    ninlil_posix_tls_v1_t *server, ninlil_posix_tls_v1_t *client)
{
    return drive_pair_to_state(
        server, client, NINLIL_POSIX_TLS_STATE_AUTHENTICATED);
}

static int drive_attached(
    ninlil_posix_tls_v1_t *server, ninlil_posix_tls_v1_t *client)
{
    return drive_pair_to_state(
        server, client, NINLIL_POSIX_TLS_STATE_ATTACHED);
}

static int close_port(ninlil_posix_tls_v1_t *port)
{
    uint32_t done = 0u;
    uint32_t i;

    CHECK(ninlil_posix_tls_v1_close_begin(port) == NINLIL_POSIX_TLS_OK);
    for (i = 0u; i < 8u; ++i) {
        uint32_t work_done = 99u;
        ninlil_posix_tls_status_t status =
            ninlil_posix_tls_v1_close_poll(port, &done);

        if (status == NINLIL_POSIX_TLS_OK) {
            break;
        }
        CHECK(status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        CHECK(done == 0u);
        status = ninlil_posix_tls_v1_step(port, 1u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
    }
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_destroy(port) == NINLIL_POSIX_TLS_OK);
    return 1;
}

typedef struct data_test_pair {
    test_environment_t environment;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_test_storage_t *storage;
    ninlil_fabric_v1_t *fabric;
    ninlil_posix_tls_config_v1_t server_config;
    ninlil_posix_tls_config_v1_t client_config;
    ninlil_posix_tls_v1_t *server;
    ninlil_posix_tls_v1_t *client;
    ninlil_posix_tls_registration_v1_t *server_registration;
    ninlil_posix_tls_registration_v1_t *client_registration;
} data_test_pair_t;

static int setup_data_test_pair(
    data_test_pair_t *pair, const char *cert_dir, uint8_t seed)
{
    const ninlil_test_storage_config_t storage_config = {
        8u, 600u, 600000u};
    ninlil_fabric_config_v1_t fabric_config;
    uint16_t bound_port = 0u;

    memset(pair, 0, sizeof(*pair));
    init_platform(&pair->environment, &pair->clock, &pair->execution);
    pair->storage = ninlil_test_storage_create(&storage_config);
    CHECK(pair->storage != NULL);
    memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = ninlil_test_storage_ops(pair->storage);
    fabric_config.clock = &pair->clock;
    fabric_config.execution = &pair->execution;
    memset(&g_fabric_workspace, 0, sizeof(g_fabric_workspace));
    CHECK(ninlil_fabric_v1_create(
              &fabric_config,
              g_fabric_workspace.bytes,
              NINLIL_FABRIC_WORKSPACE_BYTES,
              &pair->fabric)
          == NINLIL_FABRIC_OK);
    CHECK(init_port_config(
        &pair->server_config,
        NINLIL_POSIX_TLS_ROLE_SERVER,
        0u,
        seed,
        "data-test-server",
        cert_dir,
        "server.cert.pem",
        "server.key.pem",
        ninlil_test_storage_ops(pair->storage),
        &pair->clock,
        &pair->execution));
    CHECK(create_port(
        &pair->server_config, &g_server_workspace, &pair->server));
    CHECK(drive_server_listening(pair->server, &bound_port));
    CHECK(init_port_config(
        &pair->client_config,
        NINLIL_POSIX_TLS_ROLE_CLIENT,
        bound_port,
        (uint8_t)(seed + 1u),
        "data-test-client",
        cert_dir,
        "client.cert.pem",
        "client.key.pem",
        ninlil_test_storage_ops(pair->storage),
        &pair->clock,
        &pair->execution));
    CHECK(create_port(
        &pair->client_config, &g_client_workspace, &pair->client));
    CHECK(ninlil_posix_tls_v1_register_fabric(
              pair->server, pair->fabric, &pair->server_registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_register_fabric(
              pair->client, pair->fabric, &pair->client_registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(drive_attached(pair->server, pair->client));
    return 1;
}

static int close_data_test_pair_keep_storage(data_test_pair_t *pair)
{
    uint32_t done = 0u;

    if (pair->client_registration != NULL) {
        CHECK(ninlil_posix_tls_v1_unregister_begin(
                  pair->client, pair->client_registration)
              == NINLIL_POSIX_TLS_OK);
        CHECK(ninlil_posix_tls_v1_unregister_poll(
                  pair->client, pair->client_registration, &done)
              == NINLIL_POSIX_TLS_OK);
        CHECK(done == 1u);
        pair->client_registration = NULL;
    }
    if (pair->server_registration != NULL) {
        done = 0u;
        CHECK(ninlil_posix_tls_v1_unregister_begin(
                  pair->server, pair->server_registration)
              == NINLIL_POSIX_TLS_OK);
        CHECK(ninlil_posix_tls_v1_unregister_poll(
                  pair->server, pair->server_registration, &done)
              == NINLIL_POSIX_TLS_OK);
        CHECK(done == 1u);
        pair->server_registration = NULL;
    }
    if (pair->client != NULL) {
        CHECK(close_port(pair->client));
    }
    if (pair->server != NULL) {
        CHECK(close_port(pair->server));
    }
    CHECK(ninlil_fabric_v1_close_begin(pair->fabric) == NINLIL_FABRIC_OK);
    done = 0u;
    CHECK(ninlil_fabric_v1_close_poll(pair->fabric, &done)
          == NINLIL_FABRIC_OK);
    CHECK(done == 1u);
    CHECK(ninlil_fabric_v1_destroy(pair->fabric) == NINLIL_FABRIC_OK);
    pair->client = NULL;
    pair->server = NULL;
    pair->fabric = NULL;
    return 1;
}

static int teardown_data_test_pair(data_test_pair_t *pair)
{
    CHECK(close_data_test_pair_keep_storage(pair));
    CHECK(ninlil_test_storage_live_handles(pair->storage) == 0u);
    ninlil_test_storage_destroy(pair->storage);
    memset(pair, 0, sizeof(*pair));
    return 1;
}

static int recreate_data_test_pair_from_clean(
    data_test_pair_t *pair,
    uint64_t *out_server_restored_epoch,
    uint64_t *out_client_restored_epoch)
{
    ninlil_fabric_config_v1_t fabric_config;
    ninlil_posix_tls_state_v1_t state;
    uint16_t bound_port = 0u;

    memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = ninlil_test_storage_ops(pair->storage);
    fabric_config.clock = &pair->clock;
    fabric_config.execution = &pair->execution;
    memset(&g_fabric_workspace, 0, sizeof(g_fabric_workspace));
    CHECK(ninlil_fabric_v1_create(
              &fabric_config,
              g_fabric_workspace.bytes,
              NINLIL_FABRIC_WORKSPACE_BYTES,
              &pair->fabric)
          == NINLIL_FABRIC_OK);

    CHECK(create_port(
        &pair->server_config, &g_server_workspace, &pair->server));
    CHECK(port_state(pair->server, &state));
    *out_server_restored_epoch = state.availability_epoch;
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_CREATED);
    CHECK(drive_server_listening(pair->server, &bound_port));
    pair->client_config.endpoint.port = bound_port;
    CHECK(create_port(
        &pair->client_config, &g_client_workspace, &pair->client));
    CHECK(port_state(pair->client, &state));
    *out_client_restored_epoch = state.availability_epoch;
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_CREATED);
    CHECK(ninlil_posix_tls_v1_register_fabric(
              pair->server, pair->fabric, &pair->server_registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_register_fabric(
              pair->client, pair->fabric, &pair->client_registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(drive_attached(pair->server, pair->client));
    return 1;
}

static int drive_reconnected(data_test_pair_t *pair)
{
    uint32_t i;

    pair->environment.now_ms += 100000u;
    for (i = 0u; i < 50000u; ++i) {
        ninlil_posix_tls_state_v1_t server_state;
        ninlil_posix_tls_state_v1_t client_state;
        uint32_t work_done = 99u;
        ninlil_posix_tls_status_t status = ninlil_posix_tls_v1_step(
            pair->server, 64u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        work_done = 99u;
        status = ninlil_posix_tls_v1_step(
            pair->client, 64u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        CHECK(port_state(pair->server, &server_state));
        CHECK(port_state(pair->client, &client_state));
        if (server_state.operational_state == NINLIL_POSIX_TLS_STATE_ATTACHED
            && client_state.operational_state
                == NINLIL_POSIX_TLS_STATE_ATTACHED) {
            return 1;
        }
    }
    return 0;
}

static int send_one_success(
    data_test_pair_t *pair,
    ninlil_posix_tls_v1_t *sender,
    ninlil_posix_tls_v1_t *receiver,
    uint8_t seed,
    ninlil_fabric_packet_token_t *out_released_token)
{
    uint8_t packet[587];
    uint32_t packet_length = 0u;
    ninlil_fabric_packet_view_v1_t view;
    ninlil_tx_permit_t permit;
    ninlil_fabric_packet_token_t token = NULL;
    int send_done = 0;
    int received = 0;
    uint32_t i;

    CHECK(build_canonical_nfl1(packet, seed, &packet_length));
    init_packet_view(
        &view,
        &permit,
        packet,
        packet_length,
        &pair->environment,
        (uint8_t)(seed + 0x20u));
    CHECK(ninlil_posix_tls_v1_test_start_send(sender, &view, &token)
          == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(token != NULL);
    for (i = 0u; i < 20000u; ++i) {
        uint32_t work_done = 99u;
        ninlil_posix_tls_status_t status = ninlil_posix_tls_v1_step(
            sender, 1u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        work_done = 99u;
        status = ninlil_posix_tls_v1_step(receiver, 1u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        if (send_done == 0) {
            ninlil_fabric_link_completion_v1_t completion;
            CHECK(ninlil_posix_tls_v1_test_poll_send(
                      sender, token, &completion)
                  == NINLIL_FABRIC_LINK_OK);
            CHECK(completion.kind
                      == NINLIL_FABRIC_LINK_COMPLETION_PENDING
                  || completion.kind
                      == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
            send_done = completion.kind
                == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        }
        if (received == 0) {
            const uint8_t *bytes = NULL;
            uint32_t length = 0u;
            void *receive_token = NULL;
            ninlil_fabric_link_status_t receive_status =
                ninlil_posix_tls_v1_test_receive_next(
                    receiver, &bytes, &length, &receive_token);
            CHECK(receive_status == NINLIL_FABRIC_LINK_EMPTY
                  || receive_status == NINLIL_FABRIC_LINK_OK);
            if (receive_status == NINLIL_FABRIC_LINK_OK) {
                CHECK(length == packet_length);
                CHECK(memcmp(bytes, packet, length) == 0);
                ninlil_posix_tls_v1_test_release_received(
                    receiver, receive_token);
                received = 1;
            }
        }
        if (send_done != 0 && received != 0) {
            break;
        }
    }
    CHECK(send_done != 0 && received != 0);
    if (out_released_token != NULL) {
        *out_released_token = token;
    }
    ninlil_posix_tls_v1_test_release_send(sender, token);
    return 1;
}

static int test_clean_recreate_restores_epoch(const char *cert_dir)
{
    data_test_pair_t pair;
    uint8_t old_session[16];
    uint8_t new_session[16];
    uint8_t packet[587];
    uint32_t packet_length = 0u;
    uint32_t next_sequence = 0u;
    uint32_t crossed = 0u;
    size_t tx_offset = 0u;
    uint64_t server_restored_epoch = 0u;
    uint64_t client_restored_epoch = 0u;
    ninlil_fabric_packet_view_v1_t view;
    ninlil_tx_permit_t permit;
    ninlil_fabric_packet_token_t old_token = NULL;
    ninlil_fabric_packet_token_t new_token = NULL;
    ninlil_fabric_link_completion_v1_t completion;
    ninlil_posix_tls_state_v1_t state;

    CHECK(setup_data_test_pair(&pair, cert_dir, 0xd1u));
    CHECK(ninlil_posix_tls_v1_test_session_snapshot(
        pair.client,
        old_session,
        &next_sequence,
        &tx_offset,
        &crossed));
    CHECK(next_sequence == 0u);
    CHECK(send_one_success(
        &pair, pair.client, pair.server, 0x91u, &old_token));
    CHECK(old_token != NULL);
    CHECK(close_data_test_pair_keep_storage(&pair));
    CHECK(recreate_data_test_pair_from_clean(
        &pair, &server_restored_epoch, &client_restored_epoch));
    CHECK(server_restored_epoch == 3u);
    CHECK(client_restored_epoch == 3u);
    CHECK(port_state(pair.server, &state));
    CHECK(state.availability_epoch == server_restored_epoch + 1u);
    CHECK(port_state(pair.client, &state));
    CHECK(state.availability_epoch == client_restored_epoch + 1u);
    CHECK(ninlil_posix_tls_v1_test_session_snapshot(
        pair.client,
        new_session,
        &next_sequence,
        &tx_offset,
        &crossed));
    CHECK(memcmp(old_session, new_session, sizeof(old_session)) != 0);
    CHECK(next_sequence == 0u);

    CHECK(build_canonical_nfl1(packet, 0x92u, &packet_length));
    init_packet_view(
        &view,
        &permit,
        packet,
        packet_length,
        &pair.environment,
        0xa2u);
    CHECK(ninlil_posix_tls_v1_test_start_send(
              pair.client, &view, &new_token)
          == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(new_token != NULL && new_token != old_token);
    memset(&completion, 0xa5, sizeof(completion));
    CHECK(ninlil_posix_tls_v1_test_poll_send(
              pair.client, old_token, &completion)
          == NINLIL_FABRIC_LINK_CORRUPT);
    CHECK(ninlil_posix_tls_v1_test_cancel_send(pair.client, new_token)
          == NINLIL_FABRIC_LINK_OK);
    ninlil_posix_tls_v1_test_release_send(pair.client, new_token);
    CHECK(send_one_success(
        &pair, pair.client, pair.server, 0x93u, NULL));
    CHECK(teardown_data_test_pair(&pair));
    return 1;
}

static int test_crash_restart_fenced(
    const char *cert_dir, int persist_unavailable)
{
    data_test_pair_t pair;
    ninlil_posix_tls_state_v1_t state;
    uint32_t done = 0u;
    uint32_t work_done = 99u;

    CHECK(setup_data_test_pair(
        &pair,
        cert_dir,
        persist_unavailable != 0 ? 0xe1u : 0xe5u));
    if (persist_unavailable != 0) {
        CHECK(ninlil_posix_tls_v1_unregister_begin(
                  pair.client, pair.client_registration)
              == NINLIL_POSIX_TLS_OK);
        CHECK(ninlil_posix_tls_v1_unregister_poll(
                  pair.client, pair.client_registration, &done)
              == NINLIL_POSIX_TLS_OK);
        CHECK(done == 1u);
        pair.client_registration = NULL;
        CHECK(port_state(pair.client, &state));
        CHECK(state.availability_epoch == 3u);
    } else {
        CHECK(port_state(pair.client, &state));
        CHECK(state.availability_epoch == 2u);
    }
    CHECK(ninlil_posix_tls_v1_test_abandon_without_clean_marker(
        pair.client));
    CHECK(ninlil_posix_tls_v1_test_abandon_without_clean_marker(
        pair.server));
    ninlil_test_storage_simulate_crash(pair.storage);

    pair.client = NULL;
    CHECK(create_port(
        &pair.client_config, &g_client_workspace, &pair.client));
    CHECK(port_state(pair.client, &state));
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_STORAGE);
    CHECK(ninlil_posix_tls_v1_step(pair.client, 1u, &work_done)
          == NINLIL_POSIX_TLS_DENIED);
    CHECK(work_done == 0u);
    CHECK(close_port(pair.client));
    pair.client = NULL;
    CHECK(ninlil_test_storage_live_handles(pair.storage) == 0u);
    ninlil_test_storage_destroy(pair.storage);
    memset(&pair, 0, sizeof(pair));
    return 1;
}

static int test_close_waits_for_retained_io(const char *cert_dir)
{
    data_test_pair_t pair;
    uint8_t first_packet[587];
    uint8_t second_packet[587];
    uint32_t first_length = 0u;
    uint32_t second_length = 0u;
    ninlil_fabric_packet_view_v1_t view;
    ninlil_tx_permit_t permit;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_completion_v1_t completion;
    const uint8_t *loan_bytes = NULL;
    uint32_t loan_length = 0u;
    void *loan_token = NULL;
    uint32_t done = 99u;

    CHECK(setup_data_test_pair(&pair, cert_dir, 0xf1u));
    CHECK(build_canonical_nfl1(first_packet, 0xb1u, &first_length));
    CHECK(build_canonical_nfl1(second_packet, 0xb2u, &second_length));
    init_packet_view(
        &view,
        &permit,
        first_packet,
        first_length,
        &pair.environment,
        0xc1u);
    CHECK(ninlil_posix_tls_v1_test_start_send(
              pair.client, &view, &token)
          == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(ninlil_posix_tls_v1_test_prime_coalesced_rx(
        pair.client,
        first_packet,
        first_length,
        second_packet,
        second_length));
    CHECK(ninlil_posix_tls_v1_test_receive_next(
              pair.client, &loan_bytes, &loan_length, &loan_token)
          == NINLIL_FABRIC_LINK_OK);
    CHECK(loan_bytes != NULL && loan_length == first_length
          && loan_token != NULL);

    CHECK(ninlil_posix_tls_v1_close_begin(pair.client)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_close_poll(pair.client, &done)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(done == 0u);
    CHECK(ninlil_posix_tls_v1_unregister_begin(
              pair.client, pair.client_registration)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(ninlil_posix_tls_v1_test_poll_send(
              pair.client, token, &completion)
          == NINLIL_FABRIC_LINK_OK);
    CHECK(completion.kind
          == NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE);
    ninlil_posix_tls_v1_test_release_send(pair.client, token);
    ninlil_posix_tls_v1_test_release_received(pair.client, loan_token);

    CHECK(ninlil_posix_tls_v1_unregister_begin(
              pair.client, pair.client_registration)
          == NINLIL_POSIX_TLS_OK);
    done = 0u;
    CHECK(ninlil_posix_tls_v1_unregister_poll(
              pair.client, pair.client_registration, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    pair.client_registration = NULL;
    CHECK(close_port(pair.client));
    pair.client = NULL;
    CHECK(teardown_data_test_pair(&pair));
    return 1;
}

static int test_uncertain_boundary_and_reconnect(const char *cert_dir)
{
    data_test_pair_t pair;
    uint8_t packet[587];
    uint32_t packet_length = 0u;
    ninlil_fabric_packet_view_v1_t view;
    ninlil_tx_permit_t permit;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_completion_v1_t completion;
    uint8_t session_0[16];
    uint8_t session_1[16];
    uint8_t session_2[16];
    uint32_t next_sequence = 99u;
    uint32_t crossed = 99u;
    size_t tx_offset = 99u;
    uint32_t work_done = 99u;

    CHECK(setup_data_test_pair(&pair, cert_dir, 0xa1u));
    CHECK(ninlil_posix_tls_v1_test_session_snapshot(
        pair.client,
        session_0,
        &next_sequence,
        &tx_offset,
        &crossed));
    CHECK(next_sequence == 0u);
    CHECK(build_canonical_nfl1(packet, 0x11u, &packet_length));
    init_packet_view(
        &view,
        &permit,
        packet,
        packet_length,
        &pair.environment,
        0x21u);
    CHECK(ninlil_posix_tls_v1_test_start_send(
              pair.client, &view, &token)
          == NINLIL_FABRIC_LINK_RETAINED);
    ninlil_posix_tls_v1_test_fail_next_write_before_positive(pair.client);
    CHECK(ninlil_posix_tls_v1_step(pair.client, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_test_poll_send(
              pair.client, token, &completion)
          == NINLIL_FABRIC_LINK_OK);
    CHECK(completion.kind
          == NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE);
    ninlil_posix_tls_v1_test_release_send(pair.client, token);
    token = NULL;
    CHECK(drive_reconnected(&pair));
    CHECK(ninlil_posix_tls_v1_test_session_snapshot(
        pair.client,
        session_1,
        &next_sequence,
        &tx_offset,
        &crossed));
    CHECK(memcmp(session_0, session_1, sizeof(session_0)) != 0);
    CHECK(next_sequence == 0u);

    CHECK(build_canonical_nfl1(packet, 0x31u, &packet_length));
    init_packet_view(
        &view,
        &permit,
        packet,
        packet_length,
        &pair.environment,
        0x41u);
    CHECK(ninlil_posix_tls_v1_test_start_send(
              pair.client, &view, &token)
          == NINLIL_FABRIC_LINK_RETAINED);
    ninlil_posix_tls_v1_test_set_write_limit(pair.client, 64u);
    work_done = 99u;
    CHECK(ninlil_posix_tls_v1_step(pair.client, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_test_session_snapshot(
        pair.client,
        session_1,
        &next_sequence,
        &tx_offset,
        &crossed));
    CHECK(tx_offset == 64u && crossed == 1u);
    ninlil_posix_tls_v1_test_fail_next_write_before_positive(pair.client);
    work_done = 99u;
    CHECK(ninlil_posix_tls_v1_step(pair.client, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_test_poll_send(
              pair.client, token, &completion)
          == NINLIL_FABRIC_LINK_OK);
    CHECK(completion.kind
          == NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN);
    ninlil_posix_tls_v1_test_release_send(pair.client, token);
    token = NULL;
    ninlil_posix_tls_v1_test_set_write_limit(pair.client, 0u);
    CHECK(drive_reconnected(&pair));
    CHECK(ninlil_posix_tls_v1_test_session_snapshot(
        pair.client,
        session_2,
        &next_sequence,
        &tx_offset,
        &crossed));
    CHECK(memcmp(session_1, session_2, sizeof(session_1)) != 0);
    CHECK(next_sequence == 0u);
    CHECK(send_one_success(
        &pair, pair.client, pair.server, 0x51u, NULL));
    {
        ninlil_posix_tls_state_v1_t client_state;
        ninlil_posix_tls_state_v1_t server_state;
        CHECK(port_state(pair.client, &client_state));
        CHECK(port_state(pair.server, &server_state));
        CHECK(client_state.accepted_send_count == 3u);
        CHECK(server_state.accepted_receive_count == 1u);
    }
    CHECK(teardown_data_test_pair(&pair));
    return 1;
}

static int test_rejected_wire_record(const char *cert_dir, uint32_t mode)
{
    data_test_pair_t pair;
    uint8_t packet[587];
    uint32_t packet_length = 0u;
    ninlil_fabric_packet_view_v1_t view;
    ninlil_tx_permit_t permit;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_completion_v1_t completion;
    ninlil_posix_tls_state_v1_t server_state;
    int rejected = 0;
    uint32_t i;

    CHECK(mode >= 1u && mode <= 3u);
    CHECK(setup_data_test_pair(
        &pair, cert_dir, (uint8_t)(0xb0u + (uint8_t)mode * 2u)));
    if (mode != 1u) {
        CHECK(send_one_success(
            &pair, pair.client, pair.server,
            (uint8_t)(0x60u + (uint8_t)mode), NULL));
    }
    CHECK(build_canonical_nfl1(
        packet, (uint8_t)(0x70u + (uint8_t)mode), &packet_length));
    init_packet_view(
        &view,
        &permit,
        packet,
        packet_length,
        &pair.environment,
        (uint8_t)(0x80u + (uint8_t)mode));
    CHECK(ninlil_posix_tls_v1_test_start_send(
              pair.client, &view, &token)
          == NINLIL_FABRIC_LINK_RETAINED);
    if (mode == 1u) {
        CHECK(ninlil_posix_tls_v1_test_corrupt_pending_record(pair.client));
    } else if (mode == 2u) {
        CHECK(ninlil_posix_tls_v1_test_set_pending_sequence(
            pair.client, 0u));
    } else {
        CHECK(ninlil_posix_tls_v1_test_set_pending_sequence(
            pair.client, 2u));
    }
    for (i = 0u; i < 20000u; ++i) {
        uint32_t work_done = 99u;
        ninlil_posix_tls_status_t status = ninlil_posix_tls_v1_step(
            pair.client, 1u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        work_done = 99u;
        status = ninlil_posix_tls_v1_step(pair.server, 1u, &work_done);
        if (status == NINLIL_POSIX_TLS_CORRUPT) {
            CHECK(work_done == 0u);
            rejected = 1;
            break;
        }
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
    }
    CHECK(rejected != 0);
    CHECK(ninlil_posix_tls_v1_test_poll_send(
              pair.client, token, &completion)
          == NINLIL_FABRIC_LINK_OK);
    CHECK(completion.kind
          == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
    ninlil_posix_tls_v1_test_release_send(pair.client, token);
    CHECK(port_state(pair.server, &server_state));
    CHECK(server_state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(server_state.reason == NINLIL_POSIX_TLS_REASON_TLS);
    CHECK(server_state.accepted_receive_count
          == (mode == 1u ? 0u : 1u));
    CHECK(teardown_data_test_pair(&pair));
    return 1;
}

static int test_coalesced_rx_preserves_remainder(const char *cert_dir)
{
    data_test_pair_t pair;
    uint8_t first_packet[587];
    uint8_t second_packet[587];
    uint32_t first_length = 0u;
    uint32_t second_length = 0u;
    const uint8_t *bytes = NULL;
    uint32_t length = 0u;
    void *receive_token = NULL;
    uint32_t work_done = 99u;
    ninlil_posix_tls_state_v1_t server_state;

    CHECK(setup_data_test_pair(&pair, cert_dir, 0xc1u));
    CHECK(build_canonical_nfl1(
        first_packet, 0x21u, &first_length));
    CHECK(build_canonical_nfl1(
        second_packet, 0x41u, &second_length));
    CHECK(ninlil_posix_tls_v1_test_prime_coalesced_rx(
        pair.server,
        first_packet,
        first_length,
        second_packet,
        second_length));
    CHECK(ninlil_posix_tls_v1_test_receive_next(
              pair.server, &bytes, &length, &receive_token)
          == NINLIL_FABRIC_LINK_OK);
    CHECK(length == first_length);
    CHECK(memcmp(bytes, first_packet, length) == 0);
    ninlil_posix_tls_v1_test_release_received(
        pair.server, receive_token);

    CHECK(ninlil_posix_tls_v1_step(pair.server, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    bytes = NULL;
    length = 0u;
    receive_token = NULL;
    CHECK(ninlil_posix_tls_v1_test_receive_next(
              pair.server, &bytes, &length, &receive_token)
          == NINLIL_FABRIC_LINK_OK);
    CHECK(length == second_length);
    CHECK(memcmp(bytes, second_packet, length) == 0);
    ninlil_posix_tls_v1_test_release_received(
        pair.server, receive_token);
    CHECK(port_state(pair.server, &server_state));
    CHECK(server_state.accepted_receive_count == 2u);
    CHECK(teardown_data_test_pair(&pair));
    return 1;
}

static int run_negative(
    const char *cert_dir,
    const char *cert_name,
    const char *key_name,
    int wrong_peer_spki,
    test_environment_t *environment,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution,
    const ninlil_storage_ops_t *storage)
{
    ninlil_posix_tls_config_v1_t server_config;
    ninlil_posix_tls_config_v1_t client_config;
    ninlil_posix_tls_v1_t *server = NULL;
    ninlil_posix_tls_v1_t *client = NULL;
    ninlil_posix_tls_state_v1_t state;
    uint16_t bound_port = 0u;
    uint32_t i;
    int denied = 0;

    CHECK(init_port_config(
        &server_config, NINLIL_POSIX_TLS_ROLE_SERVER, 0u, 0x61u,
        "neg-server", cert_dir, "server.cert.pem", "server.key.pem",
        storage, clock, execution));
    if (wrong_peer_spki != 0) {
        /* The server must reject this accepted peer without fencing listener. */
        server_config.authorization.peer_leaf.leaf_spki_sha256[0] ^= 0x40u;
    }
    CHECK(create_port(&server_config, &g_server_workspace, &server));
    CHECK(drive_server_listening(server, &bound_port));
    CHECK(init_port_config(
        &client_config, NINLIL_POSIX_TLS_ROLE_CLIENT, bound_port, 0x71u,
        "neg-client", cert_dir, cert_name, key_name,
        storage, clock, execution));
    if (wrong_peer_spki != 0) {
        client_config.authorization.peer_leaf.leaf_spki_sha256[0] ^= 0x80u;
    }
    CHECK(create_port(&client_config, &g_client_workspace, &client));
    for (i = 0u; i < 20000u; ++i) {
        uint32_t server_work = 99u;
        uint32_t client_work = 99u;
        ninlil_posix_tls_status_t server_status =
            ninlil_posix_tls_v1_step(server, 64u, &server_work);
        ninlil_posix_tls_status_t client_status =
            ninlil_posix_tls_v1_step(client, 64u, &client_work);
        if (client_status == NINLIL_POSIX_TLS_DENIED
            || (wrong_peer_spki != 0
                && client_status == NINLIL_POSIX_TLS_TLS)) {
            CHECK(client_work == 0u);
            denied = 1;
            break;
        }
        if (client_status != NINLIL_POSIX_TLS_OK
            && client_status != NINLIL_POSIX_TLS_WOULD_BLOCK) {
            break;
        }
        if (server_status != NINLIL_POSIX_TLS_OK
            && server_status != NINLIL_POSIX_TLS_WOULD_BLOCK
            && server_status != NINLIL_POSIX_TLS_DENIED
            && server_status != NINLIL_POSIX_TLS_TLS) {
            break;
        }
        CHECK(port_state(client, &state));
        if (state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED) {
            denied = state.reason
                == NINLIL_POSIX_TLS_REASON_PEER_AUTHORIZATION;
            break;
        }
    }
    CHECK(denied != 0);
    CHECK(port_state(client, &state));
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_PEER_AUTHORIZATION
          || (wrong_peer_spki != 0
              && state.reason == NINLIL_POSIX_TLS_REASON_TLS));
    CHECK(state.availability_epoch == 1u);
    if (wrong_peer_spki != 0) {
        int server_listening = 0;
        for (i = 0u; i < 20000u; ++i) {
            uint32_t server_work = 99u;
            ninlil_posix_tls_status_t server_status =
                ninlil_posix_tls_v1_step(server, 64u, &server_work);
            CHECK(server_status == NINLIL_POSIX_TLS_OK
                  || server_status == NINLIL_POSIX_TLS_WOULD_BLOCK
                  || server_status == NINLIL_POSIX_TLS_DENIED
                  || server_status == NINLIL_POSIX_TLS_TLS);
            CHECK(port_state(server, &state));
            if (state.operational_state
                == NINLIL_POSIX_TLS_STATE_LISTENING) {
                server_listening = 1;
                break;
            }
        }
        CHECK(server_listening != 0);
    }
    CHECK(close_port(client));
    CHECK(close_port(server));
    environment->now_ms += 1u;
    return 1;
}

static int run_commit_unknown_negative(
    const char *cert_dir,
    test_environment_t *environment,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution,
    ninlil_test_storage_t *storage)
{
    ninlil_posix_tls_config_v1_t server_config;
    ninlil_posix_tls_config_v1_t client_config;
    ninlil_posix_tls_v1_t *server = NULL;
    ninlil_posix_tls_v1_t *client = NULL;
    ninlil_posix_tls_state_v1_t state;
    ninlil_posix_tls_status_t status;
    uint16_t bound_port = 0u;
    uint32_t work_done = 99u;

    CHECK(init_port_config(
        &server_config, NINLIL_POSIX_TLS_ROLE_SERVER, 0u, 0x81u,
        "cu-server", cert_dir, "server.cert.pem", "server.key.pem",
        ninlil_test_storage_ops(storage), clock, execution));
    CHECK(create_port(&server_config, &g_server_workspace, &server));
    CHECK(drive_server_listening(server, &bound_port));
    CHECK(init_port_config(
        &client_config, NINLIL_POSIX_TLS_ROLE_CLIENT, bound_port, 0x91u,
        "cu-client", cert_dir, "client.cert.pem", "client.key.pem",
        ninlil_test_storage_ops(storage), clock, execution));
    CHECK(create_port(&client_config, &g_client_workspace, &client));
    CHECK(drive_authenticated(server, client));
    CHECK(ninlil_test_storage_fault_enqueue(
        storage,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u,
        1,
        1));
    status = ninlil_posix_tls_v1_step(client, 1u, &work_done);
    CHECK(status == NINLIL_POSIX_TLS_STORAGE_COMMIT_UNKNOWN);
    CHECK(work_done == 0u);
    CHECK(port_state(client, &state));
    CHECK(state.operational_state == NINLIL_POSIX_TLS_STATE_FENCED);
    CHECK(state.reason == NINLIL_POSIX_TLS_REASON_STORAGE);
    CHECK(state.availability_epoch == 1u);
    CHECK(close_port(client));
    CHECK(close_port(server));
    environment->now_ms += 1u;
    return 1;
}

static int run_bidirectional_data_path(
    test_environment_t *environment,
    ninlil_posix_tls_v1_t *client,
    ninlil_posix_tls_v1_t *server)
{
    uint8_t client_packet[587];
    uint8_t server_packet[587];
    uint32_t client_packet_length = 0u;
    uint32_t server_packet_length = 0u;
    ninlil_fabric_packet_view_v1_t client_view;
    ninlil_fabric_packet_view_v1_t server_view;
    ninlil_tx_permit_t client_permit;
    ninlil_tx_permit_t server_permit;
    ninlil_fabric_packet_token_t client_token = NULL;
    ninlil_fabric_packet_token_t server_token = NULL;
    int client_done = 0;
    int server_done = 0;
    int client_received = 0;
    int server_received = 0;
    uint32_t i;

    CHECK(build_canonical_nfl1(
        client_packet, 0x41u, &client_packet_length));
    CHECK(build_canonical_nfl1(
        server_packet, 0x81u, &server_packet_length));
    init_packet_view(
        &client_view,
        &client_permit,
        client_packet,
        client_packet_length,
        environment,
        0x21u);
    init_packet_view(
        &server_view,
        &server_permit,
        server_packet,
        server_packet_length,
        environment,
        0x61u);
    CHECK(ninlil_posix_tls_v1_test_start_send(
              client, &client_view, &client_token)
          == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(client_token != NULL);
    CHECK(ninlil_posix_tls_v1_test_start_send(
              server, &server_view, &server_token)
          == NINLIL_FABRIC_LINK_RETAINED);
    CHECK(server_token != NULL);
    {
        ninlil_fabric_packet_token_t blocked_token =
            (ninlil_fabric_packet_token_t)(uintptr_t)1u;
        CHECK(ninlil_posix_tls_v1_test_start_send(
                  client, &client_view, &blocked_token)
              == NINLIL_FABRIC_LINK_WOULD_BLOCK);
        CHECK(blocked_token == NULL);
    }

    for (i = 0u; i < 20000u; ++i) {
        uint32_t work_done = 99u;
        ninlil_posix_tls_status_t status = ninlil_posix_tls_v1_step(
            client, 1u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        work_done = 99u;
        status = ninlil_posix_tls_v1_step(server, 1u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        if (client_done == 0) {
            ninlil_fabric_link_completion_v1_t completion;
            CHECK(ninlil_posix_tls_v1_test_poll_send(
                      client, client_token, &completion)
                  == NINLIL_FABRIC_LINK_OK);
            CHECK(completion.kind
                      == NINLIL_FABRIC_LINK_COMPLETION_PENDING
                  || completion.kind
                      == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
            client_done = completion.kind
                == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        }
        if (server_done == 0) {
            ninlil_fabric_link_completion_v1_t completion;
            CHECK(ninlil_posix_tls_v1_test_poll_send(
                      server, server_token, &completion)
                  == NINLIL_FABRIC_LINK_OK);
            CHECK(completion.kind
                      == NINLIL_FABRIC_LINK_COMPLETION_PENDING
                  || completion.kind
                      == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
            server_done = completion.kind
                == NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        }
        if (server_received == 0) {
            const uint8_t *bytes = NULL;
            uint32_t length = 0u;
            void *receive_token = NULL;
            ninlil_fabric_link_status_t receive_status =
                ninlil_posix_tls_v1_test_receive_next(
                    server, &bytes, &length, &receive_token);
            CHECK(receive_status == NINLIL_FABRIC_LINK_EMPTY
                  || receive_status == NINLIL_FABRIC_LINK_OK);
            if (receive_status == NINLIL_FABRIC_LINK_OK) {
                const uint8_t *blocked_bytes =
                    (const uint8_t *)(uintptr_t)1u;
                uint32_t blocked_length = 99u;
                void *blocked_token = (void *)(uintptr_t)1u;
                CHECK(length == client_packet_length);
                CHECK(memcmp(bytes, client_packet, length) == 0);
                CHECK(ninlil_posix_tls_v1_test_receive_next(
                          server,
                          &blocked_bytes,
                          &blocked_length,
                          &blocked_token)
                      == NINLIL_FABRIC_LINK_WOULD_BLOCK);
                CHECK(blocked_bytes == NULL && blocked_length == 0u
                      && blocked_token == NULL);
                ninlil_posix_tls_v1_test_release_received(
                    server, receive_token);
                server_received = 1;
            }
        }
        if (client_received == 0) {
            const uint8_t *bytes = NULL;
            uint32_t length = 0u;
            void *receive_token = NULL;
            ninlil_fabric_link_status_t receive_status =
                ninlil_posix_tls_v1_test_receive_next(
                    client, &bytes, &length, &receive_token);
            CHECK(receive_status == NINLIL_FABRIC_LINK_EMPTY
                  || receive_status == NINLIL_FABRIC_LINK_OK);
            if (receive_status == NINLIL_FABRIC_LINK_OK) {
                CHECK(length == server_packet_length);
                CHECK(memcmp(bytes, server_packet, length) == 0);
                ninlil_posix_tls_v1_test_release_received(
                    client, receive_token);
                client_received = 1;
            }
        }
        if (client_done != 0 && server_done != 0
            && client_received != 0 && server_received != 0) {
            break;
        }
    }
    CHECK(client_done != 0 && server_done != 0
          && client_received != 0 && server_received != 0);
    ninlil_posix_tls_v1_test_release_send(client, client_token);
    ninlil_posix_tls_v1_test_release_send(server, server_token);
    {
        ninlil_posix_tls_state_v1_t client_state;
        ninlil_posix_tls_state_v1_t server_state;
        CHECK(port_state(client, &client_state));
        CHECK(port_state(server, &server_state));
        CHECK(client_state.accepted_send_count == 1u);
        CHECK(client_state.accepted_receive_count == 1u);
        CHECK(server_state.accepted_send_count == 1u);
        CHECK(server_state.accepted_receive_count == 1u);
    }
    return 1;
}

static int test_loopback(const char *cert_dir)
{
    static const uint8_t client_storage_namespace[] = {
        0x00u, 0xffu, 0x2fu, 0x80u, 0x41u, 0x00u, 0x7fu};
    const ninlil_test_storage_config_t storage_config = {
        8u, 600u, 600000u};
    test_environment_t environment;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t execution;
    ninlil_test_storage_t *storage = NULL;
    ninlil_fabric_config_v1_t fabric_config;
    ninlil_fabric_v1_t *fabric = NULL;
    ninlil_posix_tls_config_v1_t server_config;
    ninlil_posix_tls_config_v1_t client_config;
    ninlil_posix_tls_v1_t *server = NULL;
    ninlil_posix_tls_v1_t *client = NULL;
    ninlil_posix_tls_registration_v1_t *registration = NULL;
    ninlil_posix_tls_registration_v1_t *server_registration = NULL;
    ninlil_posix_tls_state_v1_t server_state;
    ninlil_posix_tls_state_v1_t client_state;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_link_state_v1_t link_state;
    uint16_t bound_port = 0u;
    uint32_t i;
    uint32_t work_done = 99u;
    uint32_t done = 99u;
    int reached_backoff = 0;

    init_platform(&environment, &clock, &execution);
    storage = ninlil_test_storage_create(&storage_config);
    CHECK(storage != NULL);
    memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = ninlil_test_storage_ops(storage);
    fabric_config.clock = &clock;
    fabric_config.execution = &execution;
    memset(&g_fabric_workspace, 0, sizeof(g_fabric_workspace));
    CHECK(ninlil_fabric_v1_create(
              &fabric_config, g_fabric_workspace.bytes,
              NINLIL_FABRIC_WORKSPACE_BYTES, &fabric)
          == NINLIL_FABRIC_OK);

    CHECK(init_port_config(
        &server_config, NINLIL_POSIX_TLS_ROLE_SERVER, 0u, 0x41u,
        "main-server", cert_dir, "server.cert.pem", "server.key.pem",
        ninlil_test_storage_ops(storage), &clock, &execution));
    CHECK(create_port(&server_config, &g_server_workspace, &server));
    CHECK(ninlil_posix_tls_v1_step(server, 0u, &work_done)
          == NINLIL_POSIX_TLS_INVALID_ARGUMENT);
    CHECK(work_done == 0u);
    work_done = 99u;
    CHECK(ninlil_posix_tls_v1_step(server, 65u, &work_done)
          == NINLIL_POSIX_TLS_INVALID_ARGUMENT);
    CHECK(work_done == 0u);
    environment.context_id = 2u;
    work_done = 99u;
    CHECK(ninlil_posix_tls_v1_step(server, 1u, &work_done)
          == NINLIL_POSIX_TLS_WRONG_THREAD);
    CHECK(work_done == 0u);
    environment.context_id = 1u;
    environment.reenter_port = server;
    environment.reenter = 1;
    CHECK(ninlil_posix_tls_v1_step(server, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(environment.nested_status == NINLIL_POSIX_TLS_REENTRANT);
    CHECK(environment.nested_work_done == 0u);
    environment.reenter_port = NULL;
    CHECK(drive_server_listening(server, &bound_port));

    CHECK(init_port_config(
        &client_config, NINLIL_POSIX_TLS_ROLE_CLIENT, bound_port, 0x51u,
        "main-client", cert_dir, "client.cert.pem", "client.key.pem",
        ninlil_test_storage_ops(storage), &clock, &execution));
    client_config.storage_namespace.data = client_storage_namespace;
    client_config.storage_namespace.length =
        (uint32_t)sizeof(client_storage_namespace);
    CHECK(create_port(&client_config, &g_client_workspace, &client));
    CHECK(ninlil_posix_tls_v1_register_fabric(
              client, fabric, &registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(registration != NULL);
    CHECK(drive_authenticated(server, client));
    CHECK(port_state(client, &client_state));
    CHECK(client_state.operational_state
          == NINLIL_POSIX_TLS_STATE_AUTHENTICATED);
    CHECK(client_state.availability_epoch == 1u);
    CHECK(client_state.reconnect_count == 0u);
    memset(&descriptor, 0, sizeof(descriptor));
    memset(&link_state, 0, sizeof(link_state));
    CHECK(ninlil_fabric_v1_link_snapshot(
              fabric, &client_config.instance_id, &descriptor, &link_state)
          == NINLIL_FABRIC_OK);
    CHECK(link_state.available == 0u);
    CHECK(link_state.availability_epoch == 1u);

    /* Registered-before-attach publishes exactly one available transition. */
    CHECK(drive_attached(server, client));
    CHECK(port_state(client, &client_state));
    CHECK(client_state.operational_state == NINLIL_POSIX_TLS_STATE_ATTACHED);
    CHECK(client_state.availability_epoch == 2u);
    CHECK(client_state.reconnect_count == 0u);
    memset(&descriptor, 0, sizeof(descriptor));
    memset(&link_state, 0, sizeof(link_state));
    CHECK(ninlil_fabric_v1_link_snapshot(
              fabric, &client_config.instance_id, &descriptor, &link_state)
          == NINLIL_FABRIC_OK);
    CHECK(link_state.available == 1u);
    CHECK(link_state.availability_epoch == 2u);
    CHECK(link_state.available_until_ms
          == client_config.link_descriptor.attestation_expires_at_ms);
    CHECK(memcmp(
              &link_state.availability_clock_epoch_id,
              &client_config.link_descriptor.attestation_clock_epoch_id,
              sizeof(link_state.availability_clock_epoch_id))
          == 0);

    /* Attach-before-register is captured by register's provider snapshot. */
    CHECK(port_state(server, &server_state));
    CHECK(server_state.operational_state == NINLIL_POSIX_TLS_STATE_ATTACHED);
    CHECK(server_state.availability_epoch == 2u);
    CHECK(ninlil_posix_tls_v1_register_fabric(
              server, fabric, &server_registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(server_registration != NULL);
    memset(&descriptor, 0, sizeof(descriptor));
    memset(&link_state, 0, sizeof(link_state));
    CHECK(ninlil_fabric_v1_link_snapshot(
              fabric, &server_config.instance_id, &descriptor, &link_state)
          == NINLIL_FABRIC_OK);
    CHECK(link_state.available == 1u);
    CHECK(link_state.availability_epoch == 2u);
    CHECK(run_bidirectional_data_path(&environment, client, server));
    done = 99u;
    CHECK(ninlil_posix_tls_v1_unregister_begin(
              server, server_registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_unregister_poll(
              server, server_registration, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    server_registration = NULL;

    /* Drop the live server, retain the client registration, then reconnect. */
    CHECK(close_port(server));
    server = NULL;
    for (i = 0u; i < 20000u; ++i) {
        ninlil_posix_tls_status_t status;
        work_done = 99u;
        status = ninlil_posix_tls_v1_step(client, 1u, &work_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
              || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        CHECK(port_state(client, &client_state));
        if (client_state.operational_state == NINLIL_POSIX_TLS_STATE_BACKOFF) {
            reached_backoff = 1;
            break;
        }
    }
    CHECK(reached_backoff != 0);
    CHECK(client_state.reconnect_count == 0u);
    CHECK(client_state.availability_epoch == 3u);
    memset(&link_state, 0, sizeof(link_state));
    CHECK(ninlil_fabric_v1_link_snapshot(
              fabric, &client_config.instance_id, &descriptor, &link_state)
          == NINLIL_FABRIC_OK);
    CHECK(link_state.available == 0u);
    CHECK(link_state.available_until_ms == 0u);
    CHECK(link_state.availability_epoch == 3u);
    CHECK(init_port_config(
        &server_config, NINLIL_POSIX_TLS_ROLE_SERVER, bound_port, 0x42u,
        "main-server-2", cert_dir, "server.cert.pem", "server.key.pem",
        ninlil_test_storage_ops(storage), &clock, &execution));
    CHECK(create_port(&server_config, &g_server_workspace, &server));
    CHECK(drive_server_listening(server, &bound_port));
    environment.now_ms += 100000u;
    CHECK(drive_authenticated(server, client));
    CHECK(drive_attached(server, client));
    CHECK(port_state(client, &client_state));
    CHECK(client_state.operational_state
          == NINLIL_POSIX_TLS_STATE_ATTACHED);
    CHECK(client_state.reconnect_count == 1u);
    CHECK(client_state.availability_epoch == 4u);
    memset(&link_state, 0, sizeof(link_state));
    CHECK(ninlil_fabric_v1_link_snapshot(
              fabric, &client_config.instance_id, &descriptor, &link_state)
          == NINLIL_FABRIC_OK);
    CHECK(link_state.available == 1u);
    CHECK(link_state.availability_epoch == 4u);
    CHECK(link_state.available_until_ms
          == client_config.link_descriptor.attestation_expires_at_ms);

    CHECK(ninlil_posix_tls_v1_unregister_begin(client, registration)
          == NINLIL_POSIX_TLS_OK);
    CHECK(ninlil_posix_tls_v1_unregister_poll(client, registration, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_close_begin(client) == NINLIL_POSIX_TLS_OK);
    done = 99u;
    CHECK(ninlil_posix_tls_v1_close_poll(client, &done)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(done == 0u);
    CHECK(ninlil_posix_tls_v1_step(client, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_close_poll(client, &done)
          == NINLIL_POSIX_TLS_WOULD_BLOCK);
    CHECK(done == 0u);
    CHECK(ninlil_posix_tls_v1_step(client, 1u, &work_done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(work_done == 1u);
    CHECK(ninlil_posix_tls_v1_close_poll(client, &done)
          == NINLIL_POSIX_TLS_OK);
    CHECK(done == 1u);
    CHECK(ninlil_posix_tls_v1_destroy(client) == NINLIL_POSIX_TLS_OK);
    client = NULL;
    CHECK(close_port(server));
    server = NULL;
    CHECK(ninlil_fabric_v1_close_begin(fabric) == NINLIL_FABRIC_OK);
    CHECK(ninlil_fabric_v1_close_poll(fabric, &done) == NINLIL_FABRIC_OK);
    CHECK(done == 1u);
    CHECK(ninlil_fabric_v1_destroy(fabric) == NINLIL_FABRIC_OK);
    fabric = NULL;

    CHECK(run_commit_unknown_negative(
        cert_dir, &environment, &clock, &execution, storage));
    CHECK(run_negative(
        cert_dir, "client.cert.pem", "client.key.pem", 1,
        &environment, &clock, &execution, ninlil_test_storage_ops(storage)));
    CHECK(run_negative(
        cert_dir, "client.bad-ku.cert.pem", "client.key.pem", 0,
        &environment, &clock, &execution, ninlil_test_storage_ops(storage)));
    CHECK(run_negative(
        cert_dir, "expired.cert.pem", "expired.key.pem", 0,
        &environment, &clock, &execution, ninlil_test_storage_ops(storage)));

    CHECK(ninlil_test_storage_live_handles(storage) == 0u);
    ninlil_test_storage_destroy(storage);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        (void)fprintf(stderr, "usage: %s CERT_DIR\n", argv[0]);
        return 2;
    }
    CHECK(test_loopback(argv[1]));
    CHECK(test_uncertain_boundary_and_reconnect(argv[1]));
    CHECK(test_rejected_wire_record(argv[1], 1u));
    CHECK(test_rejected_wire_record(argv[1], 2u));
    CHECK(test_rejected_wire_record(argv[1], 3u));
    CHECK(test_coalesced_rx_preserves_remainder(argv[1]));
    CHECK(test_clean_recreate_restores_epoch(argv[1]));
    CHECK(test_crash_restart_fenced(argv[1], 0));
    CHECK(test_crash_restart_fenced(argv[1], 1));
    CHECK(test_close_waits_for_retained_io(argv[1]));
    (void)puts("posix_tls_v1_loopback: PASS");
    return 0;
}
