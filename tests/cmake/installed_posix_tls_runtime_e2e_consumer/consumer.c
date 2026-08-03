#define _POSIX_C_SOURCE 200809L

/* Installed-SDK-only Runtime -> Fabric -> POSIX TLS -> peer -> Receipt E2E. */
#include <ninlil/fabric_v1.h>
#include <ninlil/posix_tls_v1.h>
#include <ninlil/runtime.h>
#include <ninlil_posix_sqlite_storage.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define E2E_TIMEOUT_MS UINT64_C(30000)

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "%s:%d requirement failed: %s\n",       \
                __FILE__, __LINE__, #condition);                             \
            return 0;                                                        \
        }                                                                    \
    } while (0)

typedef struct e2e_fixture {
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    uint64_t entropy_counter;
    uint64_t permit_sequence;
    uint64_t now_ms;
    uint8_t permit_tag;
} e2e_fixture_t;

typedef struct e2e_side {
    int is_server;
    uint32_t round;
    ninlil_posix_sqlite_storage_t *provider;
    const ninlil_storage_ops_t *storage;
    e2e_fixture_t fixture;
    void *fabric_workspace;
    ninlil_fabric_v1_t *fabric;
    const ninlil_bearer_ops_t *fabric_bearer;
    void *port_workspace;
    uint32_t port_workspace_bytes;
    ninlil_posix_tls_v1_t *port;
    ninlil_posix_tls_registration_v1_t *registration;
    ninlil_runtime_t *runtime;
    ninlil_service_t *service;
    uint32_t callback_count;
} e2e_side_t;

static const uint8_t E2E_EVIDENCE[] = "posix-tls-runtime-verified";

static void set_header(uint16_t *version, uint16_t *size, size_t value_size)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value_size;
}

static void set_id(ninlil_id128_t *id, uint8_t seed)
{
    uint32_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_bytes(uint8_t *bytes, size_t count, uint8_t value)
{
    size_t i;
    for (i = 0u; i < count; ++i) {
        bytes[i] = value;
    }
}

static int id_is_zero(const ninlil_id128_t *id)
{
    static const uint8_t zero[16] = {0};
    return memcmp(id->bytes, zero, sizeof(zero)) == 0;
}

static void set_digest(ninlil_digest256_t *digest, uint8_t seed)
{
    uint32_t i;
    memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    for (i = 0u; i < 32u; ++i) {
        digest->bytes[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static int sha256_parts(const void *a, size_t a_length,
    const void *b, size_t b_length, uint8_t out[32])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int length = 0u;
    int ok = ctx != NULL
        && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(ctx, a, a_length) == 1
        && (b_length == 0u || EVP_DigestUpdate(ctx, b, b_length) == 1)
        && EVP_DigestFinal_ex(ctx, out, &length) == 1 && length == 32u;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static void put_u16_be(uint8_t out[2], uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void put_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void put_u64_be(uint8_t out[8], uint64_t value)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        out[7u - i] = (uint8_t)(value >> (i * 8u));
    }
}

static int service_identity_digest(
    const ninlil_service_descriptor_t *descriptor, uint8_t out[32])
{
    static const char tag[] = "NINLIL-FABRIC-SERVICE-IDENTITY-V1";
    uint8_t canonical[256];
    size_t offset = 0u;
    const size_t n = descriptor->namespace_id.length;
    const size_t s = descriptor->service_id.length;
    const size_t schema = descriptor->schema_id.length;

    if (n == 0u || n > 63u || s == 0u || s > 63u
        || schema == 0u || schema > 63u) {
        return 0;
    }
    put_u16_be(canonical + offset, (uint16_t)n);
    offset += 2u;
    memcpy(canonical + offset, descriptor->namespace_id.data, n);
    offset += n;
    put_u16_be(canonical + offset, (uint16_t)s);
    offset += 2u;
    memcpy(canonical + offset, descriptor->service_id.data, s);
    offset += s;
    put_u16_be(canonical + offset, (uint16_t)schema);
    offset += 2u;
    memcpy(canonical + offset, descriptor->schema_id.data, schema);
    offset += schema;
    put_u64_be(canonical + offset, descriptor->descriptor_revision);
    offset += 8u;
    put_u16_be(canonical + offset, NINLIL_DIGEST_SHA256);
    offset += 2u;
    memcpy(canonical + offset, descriptor->descriptor_digest.bytes, 32u);
    offset += 32u;
    put_u16_be(canonical + offset, descriptor->schema_major);
    offset += 2u;
    put_u16_be(canonical + offset, descriptor->schema_minor_min);
    offset += 2u;
    put_u32_be(canonical + offset, descriptor->family);
    offset += 4u;
    return sha256_parts(tag, sizeof(tag) - 1u, canonical, offset, out);
}

static void *fixture_allocate(void *user, uint64_t size, uint32_t alignment)
{
    (void)user;
    if (size == 0u || size > (uint64_t)SIZE_MAX || alignment == 0u
        || (alignment & (alignment - 1u)) != 0u
        || alignment > (uint32_t)_Alignof(max_align_t)) {
        return NULL;
    }
    return malloc((size_t)size);
}

static void fixture_deallocate(
    void *user, void *pointer, uint64_t size, uint32_t alignment)
{
    (void)user;
    (void)size;
    (void)alignment;
    free(pointer);
}

static uint64_t fixture_context_id(void *user)
{
    (void)user;
    return 1u;
}

static ninlil_port_status_t fixture_now(
    void *user, ninlil_time_sample_t *out_sample)
{
    e2e_fixture_t *fixture = (e2e_fixture_t *)user;
    if (fixture == NULL || out_sample == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    memset(out_sample, 0, sizeof(*out_sample));
    set_header(&out_sample->abi_version, &out_sample->struct_size,
        sizeof(*out_sample));
    set_id(&out_sample->clock_epoch_id, 0xa0u);
    out_sample->now_ms = fixture->now_ms;
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static ninlil_port_status_t fixture_entropy(
    void *user, uint8_t *out, uint32_t length)
{
    e2e_fixture_t *fixture = (e2e_fixture_t *)user;
    uint32_t i;
    if (fixture == NULL || out == NULL || length == 0u) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    fixture->entropy_counter += 1u;
    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(1u
            + ((fixture->entropy_counter * 37u + i * 17u) % 251u));
    }
    return NINLIL_PORT_OK;
}

static ninlil_tx_gate_status_t fixture_tx_acquire(void *user,
    const ninlil_tx_request_t *request, const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    e2e_fixture_t *fixture = (e2e_fixture_t *)user;
    uint32_t i;
    if (fixture == NULL || request == NULL || now == NULL
        || out_permit == NULL || id_is_zero(&request->attempt_id)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || fixture->permit_sequence == UINT64_MAX
        || UINT64_MAX - now->now_ms < 60000u) {
        return NINLIL_TX_GATE_DENIED;
    }
    fixture->permit_sequence += 1u;
    memset(out_permit, 0, sizeof(*out_permit));
    set_header(&out_permit->abi_version, &out_permit->struct_size,
        sizeof(*out_permit));
    for (i = 0u; i < 8u; ++i) {
        out_permit->permit_id.bytes[i] =
            (uint8_t)(fixture->permit_tag + (uint8_t)i);
    }
    put_u64_be(out_permit->permit_id.bytes + 8u, fixture->permit_sequence);
    out_permit->attempt_id = request->attempt_id;
    out_permit->clock_epoch_id = now->clock_epoch_id;
    out_permit->expires_at_ms = now->now_ms + 60000u;
    return NINLIL_TX_GATE_OK;
}

static void fixture_tx_release_unused(
    void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t fixture_origin(void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    (void)user;
    if (request == NULL || out_decision == NULL
        || request->now.trust != NINLIL_CLOCK_TRUSTED
        || UINT64_MAX - request->now.now_ms < 600000u) {
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    memset(out_decision, 0, sizeof(*out_decision));
    set_header(&out_decision->abi_version, &out_decision->struct_size,
        sizeof(*out_decision));
    out_decision->allowed = 1u;
    out_decision->reason = NINLIL_REASON_NONE;
    out_decision->retry_guidance = NINLIL_RETRY_NEVER;
    set_id(&out_decision->provider_id, 0xd0u);
    out_decision->provider_revision = 1u;
    set_digest(&out_decision->decision_digest, 0xd1u);
    set_id(&out_decision->grant_id, 0xe0u);
    out_decision->grant_revision = 1u;
    out_decision->clock_epoch_id = request->now.clock_epoch_id;
    out_decision->evaluated_at_ms = request->now.now_ms;
    out_decision->expires_at_ms = request->now.now_ms + 600000u;
    out_decision->max_payload_bytes = 1024u;
    out_decision->max_active_spool_count = 32u;
    out_decision->max_active_spool_bytes = 32768u;
    out_decision->rate_window_ms = 10000u;
    out_decision->max_admissions_per_window = 20u;
    out_decision->max_attempts_per_retry_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    return NINLIL_ORIGIN_AUTH_OK;
}

static void fixture_init(e2e_fixture_t *fixture,
    const ninlil_storage_ops_t *storage, uint32_t round, uint8_t permit_tag)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->now_ms = 1000u;
    fixture->entropy_counter = (uint64_t)round * 1000u;
    fixture->permit_sequence = (uint64_t)round * 1000u;
    fixture->permit_tag = permit_tag;
    set_header(&fixture->allocator.abi_version,
        &fixture->allocator.struct_size, sizeof(fixture->allocator));
    fixture->allocator.user = fixture;
    fixture->allocator.allocate = fixture_allocate;
    fixture->allocator.deallocate = fixture_deallocate;
    set_header(&fixture->execution.abi_version,
        &fixture->execution.struct_size, sizeof(fixture->execution));
    fixture->execution.user = fixture;
    fixture->execution.current_context_id = fixture_context_id;
    set_header(&fixture->clock.abi_version,
        &fixture->clock.struct_size, sizeof(fixture->clock));
    fixture->clock.user = fixture;
    fixture->clock.now = fixture_now;
    set_header(&fixture->entropy.abi_version,
        &fixture->entropy.struct_size, sizeof(fixture->entropy));
    fixture->entropy.user = fixture;
    fixture->entropy.fill = fixture_entropy;
    set_header(&fixture->tx_gate.abi_version,
        &fixture->tx_gate.struct_size, sizeof(fixture->tx_gate));
    fixture->tx_gate.user = fixture;
    fixture->tx_gate.acquire = fixture_tx_acquire;
    fixture->tx_gate.release_unused = fixture_tx_release_unused;
    set_header(&fixture->origin.abi_version,
        &fixture->origin.struct_size, sizeof(fixture->origin));
    fixture->origin.user = fixture;
    fixture->origin.evaluate = fixture_origin;
    set_header(&fixture->platform.abi_version,
        &fixture->platform.struct_size, sizeof(fixture->platform));
    fixture->platform.allocator = &fixture->allocator;
    fixture->platform.execution = &fixture->execution;
    fixture->platform.clock = &fixture->clock;
    fixture->platform.entropy = &fixture->entropy;
    fixture->platform.storage = storage;
    fixture->platform.tx_gate = &fixture->tx_gate;
    fixture->platform.origin_authorization = &fixture->origin;
}

static ninlil_runtime_config_t runtime_config(int is_server)
{
    static const uint8_t client_namespace[] = "posix-tls-runtime-client";
    static const uint8_t server_namespace[] = "posix-tls-runtime-server";
    const uint8_t *storage_namespace =
        is_server ? server_namespace : client_namespace;
    const uint32_t namespace_length = is_server
        ? (uint32_t)(sizeof(server_namespace) - 1u)
        : (uint32_t)(sizeof(client_namespace) - 1u);
    const uint8_t runtime_seed = is_server ? 0x32u : 0x31u;
    ninlil_runtime_config_t config;

    memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = is_server ? NINLIL_ROLE_ENDPOINT : NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, runtime_seed);
    set_header(&config.local_identity.abi_version,
        &config.local_identity.struct_size, sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, (uint8_t)(runtime_seed + 0x10u));
    set_id(&config.local_identity.installation_id,
        (uint8_t)(runtime_seed + 0x20u));
    set_id(&config.local_identity.site_domain_id,
        (uint8_t)(runtime_seed + 0x30u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = storage_namespace;
    config.storage_namespace.length = namespace_length;
    set_header(&config.limits.abi_version, &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions = is_server ? 32u : 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes = is_server ? 0u : 32768u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 4u;
    config.limits.max_retained_terminal_transactions = 32u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_event_spool_count = is_server ? 32u : 0u;
    config.limits.max_event_spool_bytes = is_server ? 32768u : 0u;
    config.limits.max_result_cache_entries = 32u;
    config.limits.max_retained_dispositions = 32u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 60000u;
    config.result_cache_retention_ms = 60000u;
    config.observation_retention_ms = 60000u;
    return config;
}

static ninlil_service_descriptor_t service_descriptor(int is_server)
{
    static const uint8_t namespace_id[] = "org.ninlil.fabric.installed";
    static const uint8_t service_id[] = "verified-state";
    static const uint8_t schema_id[] = "verified-state-v1";
    ninlil_service_descriptor_t descriptor;

    memset(&descriptor, 0, sizeof(descriptor));
    set_header(&descriptor.abi_version, &descriptor.struct_size,
        sizeof(descriptor));
    descriptor.namespace_id.data = namespace_id;
    descriptor.namespace_id.length = sizeof(namespace_id) - 1u;
    descriptor.service_id.data = service_id;
    descriptor.service_id.length = sizeof(service_id) - 1u;
    descriptor.schema_id.data = schema_id;
    descriptor.schema_id.length = sizeof(schema_id) - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x41u);
    set_id(&descriptor.local_application_instance_id,
        is_server ? 0x81u : 0x70u);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
    descriptor.logical_payload_limit = 1024u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle = 8u;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = 60000u;
    descriptor.maximum_deadline_ms = 60000u;
    descriptor.maximum_evidence_grace_ms = 5000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 60000u;
    return descriptor;
}

static int install_policy(e2e_side_t *side,
    const ninlil_service_descriptor_t *descriptor)
{
    static const char owner_tag[] = "NINLIL-FABRIC-OWNER-TUPLE-V1";
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_path_policy_v1_t snapshot;
    ninlil_fabric_authority_binding_v1_t binding;
    ninlil_id128_t endpoint_runtime_id;
    ninlil_id128_t endpoint_application_id;
    uint8_t service_digest[32];

    set_id(&endpoint_runtime_id, 0x32u);
    set_id(&endpoint_application_id, 0x81u);
    CHECK(service_identity_digest(descriptor, service_digest));
    memset(&policy, 0, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    set_id(&policy.policy_id, 0x71u);
    policy.revision = 1u;
    memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = descriptor->family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    /* Verified Receipt needs evidence, not transport custody. */
    policy.required_capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_RESERVATION
        | NINLIL_FABRIC_CAP_EVIDENCE;
    policy.required_security_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    policy.maximum_latency_class = 10u;
    policy.maximum_cost_class = 10u;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.candidate_count = 1u;
    set_id(&policy.candidates[0].instance_id, 0x61u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;
    CHECK(ninlil_fabric_v1_policy_put(side->fabric, &policy)
        == NINLIL_FABRIC_OK);
    memset(&snapshot, 0, sizeof(snapshot));
    CHECK(ninlil_fabric_v1_policy_snapshot(side->fabric,
        &policy.policy_id, policy.revision, &snapshot) == NINLIL_FABRIC_OK);

    memset(&binding, 0, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    set_id(&binding.binding_id, 0x81u);
    memcpy(binding.service_identity_digest, service_digest, 32u);
    binding.family = descriptor->family;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    binding.endpoint_runtime_id = endpoint_runtime_id;
    binding.target_runtime_id = endpoint_runtime_id;
    binding.target_application_id = endpoint_application_id;
    binding.policy_id = policy.policy_id;
    binding.policy_revision = policy.revision;
    memcpy(binding.policy_digest,
        snapshot.canonical_digest_zero_on_input, 32u);
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    set_id(&binding.authority_id, 0x91u);
    binding.authority_term = 1u;
    binding.assignment_epoch = 1u;
    set_id(&binding.owner_scope_id, 0xa1u);
    fill_bytes(binding.owner_tuple_canonical,
        sizeof(binding.owner_tuple_canonical), 0xb1u);
    memcpy(binding.owner_tuple_canonical, endpoint_runtime_id.bytes, 16u);
    memcpy(binding.owner_tuple_canonical + 16u,
        endpoint_application_id.bytes, 16u);
    CHECK(sha256_parts(owner_tag, sizeof(owner_tag) - 1u,
        binding.owner_tuple_canonical, sizeof(binding.owner_tuple_canonical),
        binding.owner_tuple_digest));
    set_id(&binding.authority_clock_epoch_id, 0xa0u);
    binding.lease_expires_at_ms = 601000u;
    binding.assignment_revision = 1u;
    return ninlil_fabric_v1_authority_put(side->fabric, &binding)
        == NINLIL_FABRIC_OK;
}

static int make_path(char out[1024], const char *directory, const char *name)
{
    int written = snprintf(out, 1024u, "%s/%s", directory, name);
    return written > 0 && written < 1024;
}

static int certificate_spki_sha256(const char *path, uint8_t out[32])
{
    BIO *bio = BIO_new_file(path, "r");
    X509 *certificate = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *der = NULL;
    unsigned int digest_length = 0u;
    int der_length = 0;
    int ok = 0;

    if (bio != NULL) {
        certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }
    if (certificate != NULL) {
        key = X509_get_pubkey(certificate);
    }
    if (key != NULL) {
        der_length = i2d_PUBKEY(key, &der);
    }
    if (der_length > 0 && der != NULL
        && EVP_Digest(der, (size_t)der_length, out, &digest_length,
               EVP_sha256(), NULL) == 1
        && digest_length == 32u) {
        ok = 1;
    }
    OPENSSL_free(der);
    EVP_PKEY_free(key);
    X509_free(certificate);
    BIO_free(bio);
    return ok;
}

static void init_leaf(ninlil_posix_tls_leaf_expectation_v1_t *leaf,
    uint32_t role, const uint8_t spki[32])
{
    memset(leaf, 0, sizeof(*leaf));
    leaf->api_version = NINLIL_POSIX_TLS_API_VERSION;
    leaf->struct_size = (uint16_t)sizeof(*leaf);
    leaf->role = role;
    set_id(&leaf->runtime_id,
        role == NINLIL_POSIX_TLS_ROLE_CLIENT ? 0x31u : 0x32u);
    memcpy(leaf->leaf_spki_sha256, spki, 32u);
    fill_bytes(leaf->authority_id.bytes, 16u, 0xd0u);
    leaf->authority_id.bytes[15] = 0xdfu;
    leaf->authority_term = 7u;
    fill_bytes(leaf->authorized_attachment_binding_digest, 32u, 0xb1u);
    leaf->credential_generation = 1u;
    leaf->revocation_generation = 1u;
}

static int init_port_config(ninlil_posix_tls_config_v1_t *config,
    e2e_side_t *side, uint16_t port, const char *cert_dir,
    char ca_path[1024], char cert_path[1024], char key_path[1024])
{
    static const uint8_t client_namespace[] = "posix-tls-port-client";
    static const uint8_t server_namespace[] = "posix-tls-port-server";
    uint8_t client_spki[32];
    uint8_t server_spki[32];
    ninlil_posix_tls_leaf_expectation_v1_t client_leaf;
    ninlil_posix_tls_leaf_expectation_v1_t server_leaf;
    ninlil_fabric_link_descriptor_v1_t *descriptor;
    const uint32_t role = side->is_server
        ? NINLIL_POSIX_TLS_ROLE_SERVER : NINLIL_POSIX_TLS_ROLE_CLIENT;

    CHECK(make_path(ca_path, cert_dir, "ca.cert.pem"));
    CHECK(make_path(cert_path, cert_dir,
        side->is_server ? "server.cert.pem" : "client.cert.pem"));
    CHECK(make_path(key_path, cert_dir,
        side->is_server ? "server.key.pem" : "client.key.pem"));
    {
        char client_path[1024];
        char server_path[1024];
        CHECK(make_path(client_path, cert_dir, "client.cert.pem"));
        CHECK(make_path(server_path, cert_dir, "server.cert.pem"));
        CHECK(certificate_spki_sha256(client_path, client_spki));
        CHECK(certificate_spki_sha256(server_path, server_spki));
    }
    init_leaf(&client_leaf, NINLIL_POSIX_TLS_ROLE_CLIENT, client_spki);
    init_leaf(&server_leaf, NINLIL_POSIX_TLS_ROLE_SERVER, server_spki);

    memset(config, 0, sizeof(*config));
    config->api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->struct_size = (uint16_t)sizeof(*config);
    config->role = role;
    set_id(&config->instance_id, 0x61u);
    config->endpoint.api_version = NINLIL_POSIX_TLS_API_VERSION;
    config->endpoint.struct_size = (uint16_t)sizeof(config->endpoint);
    config->endpoint.address_kind = NINLIL_POSIX_TLS_ADDRESS_IPV4;
    config->endpoint.port = port;
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
    config->authorization.assignment_epoch = 11u;
    config->authorization.local_leaf = side->is_server
        ? server_leaf : client_leaf;
    config->authorization.peer_leaf = side->is_server
        ? client_leaf : server_leaf;
    set_id(&config->authorization.registry_epoch_id, 0xe1u);
    fill_bytes(config->authorization.credential_reference_digest, 32u, 0xacu);
    config->authorization.credential_revision = 1u;

    descriptor = &config->link_descriptor;
    descriptor->api_version = NINLIL_FABRIC_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    descriptor->instance_id = config->instance_id;
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_RESERVATION
        | NINLIL_FABRIC_CAP_EVIDENCE;
    descriptor->descriptor_revision = 1u;
    fill_bytes(descriptor->descriptor_digest, 32u,
        side->is_server ? 0x13u : 0x12u);
    set_id(&descriptor->security_profile_id, 0x21u);
    descriptor->security_capability_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    fill_bytes(descriptor->security_binding_digest, 32u, 0x22u);
    descriptor->attestation_epoch = 1u;
    set_id(&descriptor->attestation_clock_epoch_id, 0xa0u);
    descriptor->attestation_expires_at_ms = UINT64_MAX - 1u;
    fill_bytes(descriptor->attestation_digest, 32u, 0x23u);
    descriptor->authenticated_peer_runtime_id =
        config->authorization.peer_leaf.runtime_id;
    descriptor->attachment_authority_id =
        config->authorization.local_leaf.authority_id;
    memcpy(descriptor->attachment_binding_digest,
        config->authorization.local_leaf.authorized_attachment_binding_digest,
        32u);
    descriptor->maximum_packet_bytes = 1925u;
    descriptor->maximum_transfer_bytes = 1925u;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->reservation_capacity = 1u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    memcpy(descriptor->configuration_digest,
        config->authorization.credential_reference_digest, 32u);
    config->storage_namespace.data = side->is_server
        ? server_namespace : client_namespace;
    config->storage_namespace.length = side->is_server
        ? (uint32_t)(sizeof(server_namespace) - 1u)
        : (uint32_t)(sizeof(client_namespace) - 1u);
    config->storage = side->storage;
    config->clock = &side->fixture.clock;
    config->execution = &side->fixture.execution;
    return 1;
}

static ninlil_callback_action_t endpoint_delivery(void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    e2e_side_t *side = (e2e_side_t *)user;
    (void)token;
    if (side == NULL || delivery == NULL || out_result == NULL
        || delivery->payload.data == NULL || delivery->payload.length != 16u
        || delivery->payload.data[15] != (uint8_t)side->round
        || delivery->generation != side->round
        || delivery->required_evidence != NINLIL_EVIDENCE_VERIFIED) {
        return NINLIL_CALLBACK_DEFER;
    }
    side->callback_count += 1u;
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    out_result->evidence.data = E2E_EVIDENCE;
    out_result->evidence.length = sizeof(E2E_EVIDENCE) - 1u;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t endpoint_reconcile(void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

static int setup_side(e2e_side_t *side, int is_server, uint32_t round,
    const char *database_path, const char *cert_dir, uint16_t port)
{
    ninlil_posix_sqlite_storage_config_t storage_config;
    ninlil_fabric_config_v1_t fabric_config;
    ninlil_posix_tls_config_v1_t port_config;
    ninlil_runtime_config_t runtime;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_posix_tls_state_v1_t port_state;
    char ca_path[1024];
    char cert_path[1024];
    char key_path[1024];
    uint32_t bytes = 0u;
    uint32_t alignment = 0u;
    ninlil_fabric_status_t fabric_status;

    memset(side, 0, sizeof(*side));
    side->is_server = is_server;
    side->round = round;
    memset(&storage_config, 0, sizeof(storage_config));
    storage_config.database_path = database_path;
    storage_config.busy_timeout_ms = NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = 4u * 1024u * 1024u;
    storage_config.max_handles = 16u;
    storage_config.max_transactions = 16u;
    storage_config.max_iterators = 16u;
    side->provider = ninlil_posix_sqlite_storage_create(&storage_config);
    CHECK(side->provider != NULL);
    side->storage = ninlil_posix_sqlite_storage_ops(side->provider);
    CHECK(side->storage != NULL);
    fixture_init(&side->fixture, side->storage, round,
        is_server ? 0x51u : 0x31u);

    CHECK(ninlil_fabric_v1_workspace_required(
        NINLIL_FABRIC_PROFILE_1, &bytes, &alignment) == NINLIL_FABRIC_OK);
    CHECK(bytes == NINLIL_FABRIC_WORKSPACE_BYTES
        && alignment <= (uint32_t)_Alignof(max_align_t));
    side->fabric_workspace = malloc(bytes);
    CHECK(side->fabric_workspace != NULL
        && ((uintptr_t)side->fabric_workspace % alignment) == 0u);
    memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = side->storage;
    fabric_config.clock = &side->fixture.clock;
    fabric_config.execution = &side->fixture.execution;
    fabric_status = ninlil_fabric_v1_create(&fabric_config,
        side->fabric_workspace, bytes, &side->fabric);
    if (fabric_status != NINLIL_FABRIC_OK) {
        (void)fprintf(stderr, "fabric_create status=%u round=%u role=%s\n",
            (unsigned)fabric_status, (unsigned)round,
            is_server ? "server" : "client");
        return 0;
    }
    CHECK(ninlil_fabric_v1_bearer_ops(side->fabric, &side->fabric_bearer)
        == NINLIL_FABRIC_OK);
    side->fixture.platform.bearer = side->fabric_bearer;

    CHECK(init_port_config(&port_config, side, port, cert_dir,
        ca_path, cert_path, key_path));
    CHECK(ninlil_posix_tls_v1_workspace_required(&bytes, &alignment)
        == NINLIL_POSIX_TLS_OK);
    CHECK(bytes > 0u && alignment <= (uint32_t)_Alignof(max_align_t));
    side->port_workspace = malloc(bytes);
    side->port_workspace_bytes = bytes;
    CHECK(side->port_workspace != NULL
        && ((uintptr_t)side->port_workspace % alignment) == 0u);
    CHECK(ninlil_posix_tls_v1_create(&port_config, side->port_workspace,
        bytes, &side->port) == NINLIL_POSIX_TLS_OK);
    memset(&port_state, 0, sizeof(port_state));
    CHECK(ninlil_posix_tls_v1_state(side->port, &port_state)
        == NINLIL_POSIX_TLS_OK);
    CHECK(port_state.operational_state == NINLIL_POSIX_TLS_STATE_CREATED);
    CHECK(ninlil_posix_tls_v1_register_fabric(side->port, side->fabric,
        &side->registration) == NINLIL_POSIX_TLS_OK);

    descriptor = service_descriptor(is_server);
    CHECK(install_policy(side, &descriptor));
    runtime = runtime_config(is_server);
    CHECK(ninlil_runtime_create(&runtime, &side->fixture.platform,
        &side->runtime) == NINLIL_OK);
    memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size,
        sizeof(callbacks));
    if (is_server) {
        callbacks.user = side;
        callbacks.on_delivery = endpoint_delivery;
        callbacks.on_reconcile = endpoint_reconcile;
    }
    CHECK(ninlil_service_register(side->runtime, &descriptor,
        &callbacks, &side->service) == NINLIL_OK);
    return 1;
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0u;
    }
    return (uint64_t)now.tv_sec * 1000u
        + (uint64_t)now.tv_nsec / 1000000u;
}

static void idle_pause(void)
{
    const struct timespec pause = {0, 1000000L};
    (void)nanosleep(&pause, NULL);
}

static int drive_side(e2e_side_t *side)
{
    ninlil_step_budget_t budget;
    ninlil_step_result_t result;
    ninlil_posix_tls_status_t port_status;
    ninlil_status_t runtime_status;
    uint32_t work = 0u;

    port_status = ninlil_posix_tls_v1_step(side->port, 64u, &work);
    CHECK(port_status == NINLIL_POSIX_TLS_OK
        || port_status == NINLIL_POSIX_TLS_WOULD_BLOCK);
    memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 8u;
    budget.max_callbacks = 8u;
    budget.max_state_transitions = 16u;
    budget.max_bearer_sends = 8u;
    memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    runtime_status = ninlil_runtime_step(side->runtime, &budget, &result);
    if (runtime_status != NINLIL_OK) {
        (void)fprintf(stderr,
            "runtime_step status=%u health=%u reason=%u more=%u\n",
            (unsigned)runtime_status, (unsigned)result.health,
            (unsigned)result.degraded_reason, (unsigned)result.more_work);
        return 0;
    }
    CHECK(ninlil_fabric_v1_step(side->fabric, 64u, &work)
        == NINLIL_FABRIC_OK);
    port_status = ninlil_posix_tls_v1_step(side->port, 64u, &work);
    CHECK(port_status == NINLIL_POSIX_TLS_OK
        || port_status == NINLIL_POSIX_TLS_WOULD_BLOCK);
    return 1;
}

static int wait_for_port_state(e2e_side_t *side, uint32_t expected)
{
    const uint64_t start = monotonic_ms();
    CHECK(start != 0u);
    while (monotonic_ms() - start < E2E_TIMEOUT_MS) {
        ninlil_posix_tls_state_v1_t state;
        CHECK(drive_side(side));
        memset(&state, 0, sizeof(state));
        CHECK(ninlil_posix_tls_v1_state(side->port, &state)
            == NINLIL_POSIX_TLS_OK);
        if (state.operational_state == expected) {
            return 1;
        }
        CHECK(state.operational_state != NINLIL_POSIX_TLS_STATE_FENCED
            && state.operational_state != NINLIL_POSIX_TLS_STATE_UNAVAILABLE);
        idle_pause();
    }
    (void)fprintf(stderr, "timed out waiting for port state=%u\n",
        (unsigned)expected);
    return 0;
}

static int write_marker(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    int ok;
    if (file == NULL) {
        return 0;
    }
    ok = fputs(text, file) >= 0;
    if (fflush(file) != 0) {
        ok = 0;
    }
    if (fclose(file) != 0) {
        ok = 0;
    }
    return ok;
}

static int marker_exists(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    (void)fclose(file);
    return 1;
}

static void dump_transport_diagnostics(e2e_side_t *side)
{
    ninlil_posix_tls_state_v1_t port_state;
    ninlil_fabric_link_state_v1_t link_state;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_link_metrics_v1_t metrics;
    ninlil_id128_t instance_id;

    set_id(&instance_id, 0x61u);
    memset(&port_state, 0, sizeof(port_state));
    memset(&link_state, 0, sizeof(link_state));
    memset(&descriptor, 0, sizeof(descriptor));
    memset(&metrics, 0, sizeof(metrics));
    if (ninlil_posix_tls_v1_state(side->port, &port_state)
        == NINLIL_POSIX_TLS_OK) {
        (void)fprintf(stderr,
            "diag role=%s port_state=%u reason=%u epoch=%llu "
            "send=%llu receive=%llu reconnect=%u\n",
            side->is_server ? "server" : "client",
            (unsigned)port_state.operational_state,
            (unsigned)port_state.reason,
            (unsigned long long)port_state.availability_epoch,
            (unsigned long long)port_state.accepted_send_count,
            (unsigned long long)port_state.accepted_receive_count,
            (unsigned)port_state.reconnect_count);
    }
    if (ninlil_fabric_v1_link_snapshot(side->fabric, &instance_id,
        &descriptor, &link_state) == NINLIL_FABRIC_OK) {
        (void)fprintf(stderr,
            "diag role=%s link_available=%u link_epoch=%llu mtu=%u caps=%u\n",
            side->is_server ? "server" : "client",
            (unsigned)link_state.available,
            (unsigned long long)link_state.availability_epoch,
            (unsigned)descriptor.maximum_packet_bytes,
            (unsigned)descriptor.capability_flags);
    }
    if (ninlil_fabric_v1_metrics_snapshot(
        side->fabric, &instance_id, &metrics) == NINLIL_FABRIC_OK) {
        (void)fprintf(stderr,
            "diag role=%s fabric accepted=%llu block=%llu unavailable=%llu "
            "denied=%llu lost=%llu corrupt=%llu retained=%u queued=%u\n",
            side->is_server ? "server" : "client",
            (unsigned long long)metrics.accepted_count,
            (unsigned long long)metrics.would_block_count,
            (unsigned long long)metrics.unavailable_count,
            (unsigned long long)metrics.denied_count,
            (unsigned long long)metrics.lost_unknown_count,
            (unsigned long long)metrics.corrupt_count,
            (unsigned)metrics.retained_tokens,
            (unsigned)metrics.queued_items);
    }
}

static int shutdown_side(e2e_side_t *side)
{
    const uint64_t start = monotonic_ms();
    uint32_t unregister_started = 0u;
    uint32_t unregister_done = 0u;
    uint32_t close_done = 0u;
    uint32_t work = 0u;

    CHECK(start != 0u);
    CHECK(ninlil_runtime_destroy(side->runtime) == NINLIL_OK);
    side->runtime = NULL;
    CHECK(ninlil_posix_tls_v1_close_begin(side->port)
        == NINLIL_POSIX_TLS_OK);
    while (unregister_done == 0u
        && monotonic_ms() - start < E2E_TIMEOUT_MS) {
        ninlil_posix_tls_status_t status =
            ninlil_posix_tls_v1_step(side->port, 64u, &work);
        CHECK(status == NINLIL_POSIX_TLS_OK
            || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        CHECK(ninlil_fabric_v1_step(side->fabric, 64u, &work)
            == NINLIL_FABRIC_OK);
        if (unregister_started == 0u) {
            status = ninlil_posix_tls_v1_unregister_begin(
                side->port, side->registration);
            CHECK(status == NINLIL_POSIX_TLS_OK
                || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
            unregister_started = status == NINLIL_POSIX_TLS_OK;
        } else {
            status = ninlil_posix_tls_v1_unregister_poll(
                side->port, side->registration, &unregister_done);
            CHECK(status == NINLIL_POSIX_TLS_OK
                || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        }
        idle_pause();
    }
    CHECK(unregister_done == 1u);
    side->registration = NULL;
    while (close_done == 0u && monotonic_ms() - start < E2E_TIMEOUT_MS) {
        ninlil_posix_tls_status_t status =
            ninlil_posix_tls_v1_step(side->port, 64u, &work);
        CHECK(status == NINLIL_POSIX_TLS_OK
            || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        status = ninlil_posix_tls_v1_close_poll(side->port, &close_done);
        CHECK(status == NINLIL_POSIX_TLS_OK
            || status == NINLIL_POSIX_TLS_WOULD_BLOCK);
        idle_pause();
    }
    CHECK(close_done == 1u);
    CHECK(ninlil_posix_tls_v1_destroy(side->port) == NINLIL_POSIX_TLS_OK);
    side->port = NULL;
    free(side->port_workspace);
    side->port_workspace = NULL;

    CHECK(ninlil_fabric_v1_close_begin(side->fabric) == NINLIL_FABRIC_OK);
    close_done = 0u;
    while (close_done == 0u && monotonic_ms() - start < E2E_TIMEOUT_MS) {
        CHECK(ninlil_fabric_v1_step(side->fabric, 64u, &work)
            == NINLIL_FABRIC_OK);
        CHECK(ninlil_fabric_v1_close_poll(side->fabric, &close_done)
            == NINLIL_FABRIC_OK);
    }
    CHECK(close_done == 1u);
    CHECK(ninlil_fabric_v1_destroy(side->fabric) == NINLIL_FABRIC_OK);
    side->fabric = NULL;
    free(side->fabric_workspace);
    side->fabric_workspace = NULL;
    CHECK(ninlil_posix_sqlite_storage_live_handles(side->provider) == 0u);
    CHECK(ninlil_posix_sqlite_storage_live_transactions(side->provider) == 0u);
    CHECK(ninlil_posix_sqlite_storage_live_iterators(side->provider) == 0u);
    ninlil_posix_sqlite_storage_destroy(side->provider);
    side->provider = NULL;
    side->storage = NULL;
    return 1;
}

static int query_transaction(e2e_side_t *side,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *out_snapshot,
    ninlil_target_snapshot_t *out_target)
{
    memset(out_target, 0, sizeof(*out_target));
    set_header(&out_target->abi_version, &out_target->struct_size,
        sizeof(*out_target));
    memset(out_snapshot, 0, sizeof(*out_snapshot));
    set_header(&out_snapshot->abi_version, &out_snapshot->struct_size,
        sizeof(*out_snapshot));
    out_snapshot->targets = out_target;
    out_snapshot->target_capacity = 1u;
    return ninlil_transaction_query(
        side->runtime, transaction_id, out_snapshot) == NINLIL_OK;
}

static int run_server(e2e_side_t *side,
    const char *ready_path, const char *success_path, uint16_t configured_port)
{
    const uint64_t start = monotonic_ms();
    ninlil_posix_tls_state_v1_t state;

    CHECK(wait_for_port_state(side, NINLIL_POSIX_TLS_STATE_LISTENING));
    memset(&state, 0, sizeof(state));
    CHECK(ninlil_posix_tls_v1_state(side->port, &state)
        == NINLIL_POSIX_TLS_OK);
    CHECK(state.local_port == configured_port);
    CHECK(write_marker(ready_path, "listening\n"));
    CHECK(start != 0u);
    while (monotonic_ms() - start < E2E_TIMEOUT_MS) {
        CHECK(drive_side(side));
        CHECK(side->callback_count <= 1u);
        if (side->callback_count == 1u && marker_exists(success_path)) {
            CHECK(shutdown_side(side));
            (void)printf("role=server round=%u pid=%ld callback=1 "
                         "clean_close=1 PASS\n",
                (unsigned)side->round, (long)getpid());
            return 1;
        }
        idle_pause();
    }
    dump_transport_diagnostics(side);
    (void)fprintf(stderr, "server timed out waiting for callback/satisfaction\n");
    return 0;
}

static int run_client(e2e_side_t *side, const char *success_path)
{
    static const uint8_t payload_prefix[15] = {
        0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
        0x98u, 0xa9u, 0xbau, 0xcbu, 0xdcu, 0xedu, 0xfeu
    };
    const uint64_t start = monotonic_ms();
    ninlil_concrete_target_t target;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target_snapshot;
    uint8_t payload[16];
    char idempotency_key[64];
    int written;

    CHECK(wait_for_port_state(side, NINLIL_POSIX_TLS_STATE_ATTACHED));
    memcpy(payload, payload_prefix, sizeof(payload_prefix));
    payload[15] = (uint8_t)side->round;
    written = snprintf(idempotency_key, sizeof(idempotency_key),
        "posix-tls-runtime-round-%u", (unsigned)side->round);
    CHECK(written > 0 && (size_t)written < sizeof(idempotency_key));
    memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    set_id(&target.target_runtime_id, 0x32u);
    set_id(&target.target_application_instance_id, 0x81u);
    memset(&submission, 0, sizeof(submission));
    set_header(&submission.abi_version, &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_VERIFIED;
    submission.effect_deadline_ms = 60000u;
    submission.evidence_grace_ms = 5000u;
    submission.idempotency_key.data = (const uint8_t *)idempotency_key;
    submission.idempotency_key.length = (uint32_t)written;
    submission.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    CHECK(sha256_parts(payload, sizeof(payload), NULL, 0u,
        submission.content_digest.bytes));
    submission.generation = side->round;
    submission.payload.data = payload;
    submission.payload.length = sizeof(payload);
    memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    CHECK(ninlil_submit(side->service, &submission, &result) == NINLIL_OK);
    CHECK(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    CHECK(start != 0u);
    while (monotonic_ms() - start < E2E_TIMEOUT_MS) {
        CHECK(drive_side(side));
        CHECK(query_transaction(
            side, &result.transaction_id, &snapshot, &target_snapshot));
        if (snapshot.state == NINLIL_TXN_TERMINAL
            && snapshot.outcome == NINLIL_OUTCOME_SATISFIED
            && target_snapshot.latest_evidence >= NINLIL_EVIDENCE_VERIFIED) {
            CHECK(write_marker(success_path, "satisfied verified\n"));
            CHECK(shutdown_side(side));
            (void)printf("role=client round=%u pid=%ld satisfied=1 "
                         "verified=1 clean_close=1 PASS\n",
                (unsigned)side->round, (long)getpid());
            return 1;
        }
        idle_pause();
    }
    dump_transport_diagnostics(side);
    (void)fprintf(stderr,
        "diag transaction state=%u outcome=%u latest=%u target_state=%u "
        "target_outcome=%u target_latest=%u attempts=%llu\n",
        (unsigned)snapshot.state, (unsigned)snapshot.outcome,
        (unsigned)snapshot.latest_evidence,
        (unsigned)target_snapshot.state, (unsigned)target_snapshot.outcome,
        (unsigned)target_snapshot.latest_evidence,
        (unsigned long long)target_snapshot.cumulative_attempts);
    (void)fprintf(stderr, "client timed out waiting for verified Receipt\n");
    return 0;
}

static int parse_u16(const char *text, uint16_t *out)
{
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (text == end || end == NULL || *end != '\0' || value == 0u
        || value > 65535u) {
        return 0;
    }
    *out = (uint16_t)value;
    return 1;
}

static int parse_round(const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (text == end || end == NULL || *end != '\0'
        || (value != 1u && value != 2u)) {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

int main(int argc, char **argv)
{
    e2e_side_t side;
    uint16_t port = 0u;
    uint32_t round = 0u;
    int is_server;

    if (argc != 8 || argv[1] == NULL || argv[2] == NULL || argv[3] == NULL
        || argv[4] == NULL || argv[5] == NULL || argv[6] == NULL
        || argv[7] == NULL
        || (strcmp(argv[1], "server") != 0
            && strcmp(argv[1], "client") != 0)
        || !parse_u16(argv[4], &port) || !parse_round(argv[7], &round)) {
        (void)fprintf(stderr,
            "usage: consumer server|client DB CERT_DIR PORT READY SUCCESS 1|2\n");
        return 2;
    }
    is_server = strcmp(argv[1], "server") == 0;
    if (!setup_side(&side, is_server, round, argv[2], argv[3], port)) {
        return 1;
    }
    if (is_server) {
        return run_server(&side, argv[5], argv[6], port) ? 0 : 1;
    }
    if (!marker_exists(argv[5])) {
        (void)fprintf(stderr, "client started before server readiness\n");
        return 1;
    }
    return run_client(&side, argv[6]) ? 0 : 1;
}
