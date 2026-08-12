/* SPDX-License-Identifier: Apache-2.0 */
/*
 * V1-LAB unit 4: B3 logical capability layer — priority/deadline/retry,
 * bearer payload limits, logical payload/fragment, reservation, restart.
 */

#include "deterministic_entropy.h"
#include "domain_store_codec.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_transaction_codec.h"
#include "runtime_store_codec.h"
#include "typed_simulated_bearer.h"
#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
#include "mfdt_v1_runtime_owner.h"
#include "mfdt_v1_spine.h"
#endif

#include <ninlil/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t TEST_NAMESPACE[] = "v1-runtime-capability-test";
#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
static const uint8_t MFDT_TEST_NAMESPACE_B[] =
    "v1-runtime-capability-mfdt-b";
static const uint8_t MFDT_SIDECAR_NAMESPACE_DOMAIN[] =
    "NINLIL-MFDT-STORAGE-NAMESPACE-V1";
#endif
static const char NS_TEXT[] = "org.ninlil.examples";

typedef struct cap_env {
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_bearer_t *bearer_fixture;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime;
    ninlil_service_t *service;
    ninlil_concrete_target_t target;
    uint8_t *payload;
    uint32_t payload_capacity;
} cap_env_t;

typedef struct future_target_snapshot {
    ninlil_target_snapshot_t known;
    uint8_t future_tail[40];
} future_target_snapshot_t;

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
static int id_is_nonzero(const ninlil_id128_t *id)
{
    static const uint8_t zero[16] = {0u};

    return id != NULL
        && memcmp(id->bytes, zero, sizeof(id->bytes)) != 0;
}
#endif

static void set_digest(ninlil_digest256_t *digest, uint8_t value)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = value;
}

static int set_payload_content_digest(
    ninlil_digest256_t *digest,
    const uint8_t *payload,
    uint32_t length)
{
    ninlil_model_domain_digest_t actual;

    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    if (ninlil_model_domain_sha256(payload, length, &actual) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(digest->bytes, actual.bytes, sizeof(digest->bytes));
    return 1;
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static ninlil_origin_auth_status_t origin_allow(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)memset(decision, 0, sizeof(*decision));
    set_header(&decision->abi_version, &decision->struct_size, sizeof(*decision));
    decision->allowed = 1u;
    decision->max_payload_bytes = 32768u;
    decision->clock_epoch_id = request->now.clock_epoch_id;
    decision->evaluated_at_ms = request->now.now_ms;
    return NINLIL_ORIGIN_AUTH_OK;
}

static ninlil_runtime_config_t config_controller(uint32_t max_services)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x10u);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x20u);
    set_id(&config.local_identity.installation_id, 0x40u);
    set_id(&config.local_identity.site_domain_id, 0x60u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = TEST_NAMESPACE;
    config.storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    set_header(
        &config.limits.abi_version, &config.limits.struct_size, sizeof(config.limits));
    config.limits.max_services = max_services;
    config.limits.max_nonterminal_transactions = 32u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes = 65536u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 30u;
    config.limits.max_nonterminal_deliveries = 32u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.limits.max_result_cache_entries = 13u;
    config.limits.max_retained_dispositions = 14u;
    config.limits.max_ingress_per_step = 15u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 32u;
    config.limits.max_bearer_sends_per_step = 18u;
    config.limits.max_deferred_tokens = 12u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static int platform_init(cap_env_t *env)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_bearer_config_t bearer_config;

    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 4u;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = 1048576u;

    env->allocator = ninlil_test_allocator_create();
    env->execution = ninlil_test_execution_create(1u);
    env->clock = ninlil_test_clock_create();
    env->entropy = ninlil_test_entropy_create(0x4c4c4c4cu, 1u);
    env->storage_fixture = ninlil_test_storage_create(&storage_config);
    (void)memset(&bearer_config, 0, sizeof(bearer_config));
    bearer_config.max_entries_per_direction = 32u;
    bearer_config.max_bytes_per_direction = 65536u;
    bearer_config.max_permits = 32u;
    bearer_config.permit_issuer_id.bytes[0] = 0x80u;
    bearer_config.permit_issuer_id.bytes[15] = 0x01u;
    bearer_config.initial_clock_epoch_id.bytes[0] = 0xa0u;
    bearer_config.initial_clock_epoch_id.bytes[15] = 0x01u;
    env->bearer_fixture = ninlil_test_bearer_create(&bearer_config);
    env->payload = NULL;
    env->payload_capacity = 0u;
    if (env->allocator == NULL || env->execution == NULL || env->clock == NULL
        || env->entropy == NULL || env->storage_fixture == NULL
        || env->bearer_fixture == NULL) {
        return 0;
    }

    set_header(
        &env->origin.abi_version, &env->origin.struct_size, sizeof(env->origin));
    env->origin.evaluate = origin_allow;
    set_header(
        &env->platform.abi_version, &env->platform.struct_size, sizeof(env->platform));
    env->platform.allocator = ninlil_test_allocator_ops(env->allocator);
    env->platform.execution = ninlil_test_execution_ops(env->execution);
    env->platform.clock = ninlil_test_clock_ops(env->clock);
    env->platform.entropy = ninlil_test_entropy_ops(env->entropy);
    env->platform.storage = ninlil_test_storage_ops(env->storage_fixture);
    env->platform.bearer = ninlil_test_bearer_ops(env->bearer_fixture);
    env->platform.tx_gate = ninlil_test_bearer_tx_gate_ops(env->bearer_fixture);
    env->platform.origin_authorization = &env->origin;
    return 1;
}

static void platform_teardown(cap_env_t *env)
{
    if (env->runtime != NULL) {
        (void)ninlil_runtime_destroy(env->runtime);
        env->runtime = NULL;
    }
    if (env->payload != NULL) {
        free(env->payload);
        env->payload = NULL;
    }
    if (env->bearer_fixture != NULL) {
        ninlil_test_bearer_destroy(env->bearer_fixture);
        env->bearer_fixture = NULL;
    }
    if (env->storage_fixture != NULL) {
        ninlil_test_storage_destroy(env->storage_fixture);
        env->storage_fixture = NULL;
    }
    if (env->entropy != NULL) {
        ninlil_test_entropy_destroy(env->entropy);
        env->entropy = NULL;
    }
    if (env->clock != NULL) {
        ninlil_test_clock_destroy(env->clock);
        env->clock = NULL;
    }
    if (env->execution != NULL) {
        ninlil_test_execution_destroy(env->execution);
        env->execution = NULL;
    }
    if (env->allocator != NULL) {
        (void)ninlil_test_allocator_destroy(env->allocator);
        env->allocator = NULL;
    }
    (void)memset(env, 0, sizeof(*env));
}

static int env_create(cap_env_t *env)
{
    env->config = config_controller(4u);
    return ninlil_runtime_create(&env->config, &env->platform, &env->runtime)
        == NINLIL_OK;
}

static ninlil_service_descriptor_t desired_descriptor(uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)"absolute-state";
    descriptor.service_id.length = sizeof("absolute-state") - 1u;
    descriptor.schema_id.data = (const uint8_t *)"absolute-state";
    descriptor.schema_id.length = sizeof("absolute-state") - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x11u);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 1024u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 32u;
    descriptor.max_payload_bytes_per_window = 65536u;
    descriptor.minimum_deadline_ms = 100u;
    descriptor.maximum_deadline_ms = 60000u;
    descriptor.maximum_evidence_grace_ms = 1000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 50u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    return descriptor;
}

static int env_register(cap_env_t *env, uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor = desired_descriptor(app_tag);
    ninlil_service_callbacks_t callbacks;

    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    return ninlil_service_register(
               env->runtime, &descriptor, &callbacks, &env->service)
        == NINLIL_OK;
}

#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
static int env_register_mfdt(
    cap_env_t *env,
    uint8_t app_tag,
    uint32_t target_limit)
{
    ninlil_service_descriptor_t descriptor = desired_descriptor(app_tag);
    ninlil_service_callbacks_t callbacks;

    descriptor.logical_payload_limit = NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    descriptor.target_limit = target_limit;
    descriptor.max_payload_bytes_per_window = 262144u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    return ninlil_service_register(
               env->runtime, &descriptor, &callbacks, &env->service)
        == NINLIL_OK;
}

static ninlil_status_t configure_mfdt_owner_status(
    ninlil_runtime_t *runtime,
    uint32_t generation,
    uint64_t cookie)
{
    ninlil_rt_mfdt_v1_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.struct_size = (uint32_t)sizeof(config);
    config.enabled = 1u;
    config.session_generation = generation;
    config.session_cookie = cookie;
    return ninlil_rt_mfdt_v1_runtime_configure(runtime, &config);
}

static int configure_mfdt_owner(
    ninlil_runtime_t *runtime,
    uint32_t generation,
    uint64_t cookie)
{
    return configure_mfdt_owner_status(runtime, generation, cookie)
        == NINLIL_OK;
}

static int make_admitted_mfdt_session(
    ninlil_runtime_t *runtime,
    uint32_t generation,
    uint64_t cookie,
    uint8_t peer_tag,
    ninlil_mfdt_v1_session_t *out_session)
{
    ninlil_mfdt_v1_session_t initiator;
    ninlil_mfdt_v1_session_t responder;
    ninlil_id128_t peer_id;
    uint8_t offer_nonce[16];
    uint8_t responder_nonce[16];
    uint8_t offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    size_t offer_length = 0u;
    size_t accept_length = 0u;

    if (runtime == NULL || out_session == NULL) {
        return 0;
    }
    set_id(&peer_id, peer_tag);
    (void)memset(offer_nonce, 0x31, sizeof(offer_nonce));
    (void)memset(responder_nonce, 0x42, sizeof(responder_nonce));
    ninlil_mfdt_v1_session_init(
        &initiator, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_session_init(
        &responder, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    if (ninlil_mfdt_v1_session_bind(
            &initiator,
            2u,
            generation,
            cookie,
            1u,
            runtime->config.runtime_id.bytes,
            peer_id.bytes) != NINLIL_MFDT_V1_OK
        || ninlil_mfdt_v1_session_bind(
            &responder,
            2u,
            generation,
            cookie,
            1u,
            peer_id.bytes,
            runtime->config.runtime_id.bytes) != NINLIL_MFDT_V1_OK
        || ninlil_mfdt_v1_session_build_offer(
            &initiator,
            7u,
            offer_nonce,
            offer,
            sizeof(offer),
            &offer_length) != NINLIL_MFDT_V1_OK
        || ninlil_mfdt_v1_session_on_offer(
            &responder,
            offer,
            offer_length,
            responder_nonce,
            accept,
            sizeof(accept),
            &accept_length) != NINLIL_MFDT_V1_OK
        || ninlil_mfdt_v1_session_on_accept(
            &initiator, accept, accept_length) != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    *out_session = initiator;
    return 1;
}

static int make_admitted_mfdt_session_pair(
    const ninlil_runtime_t *initiator_runtime,
    const ninlil_runtime_t *responder_runtime,
    uint32_t generation,
    uint64_t cookie,
    ninlil_mfdt_v1_session_t *initiator_out,
    ninlil_mfdt_v1_session_t *responder_out)
{
    ninlil_mfdt_v1_session_t initiator;
    ninlil_mfdt_v1_session_t responder;
    uint8_t offer_nonce[16];
    uint8_t responder_nonce[16];
    uint8_t offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    size_t offer_length = 0u;
    size_t accept_length = 0u;

    if (initiator_runtime == NULL || responder_runtime == NULL ||
        initiator_out == NULL || responder_out == NULL) {
        return 0;
    }
    (void)memset(offer_nonce, 0x31, sizeof(offer_nonce));
    (void)memset(responder_nonce, 0x42, sizeof(responder_nonce));
    ninlil_mfdt_v1_session_init(
        &initiator, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_session_init(
        &responder, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    if (ninlil_mfdt_v1_session_bind(
            &initiator,
            2u,
            generation,
            cookie,
            1u,
            initiator_runtime->config.runtime_id.bytes,
            responder_runtime->config.runtime_id.bytes)
            != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_session_bind(
            &responder,
            2u,
            generation,
            cookie,
            1u,
            responder_runtime->config.runtime_id.bytes,
            initiator_runtime->config.runtime_id.bytes)
            != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_session_build_offer(
            &initiator,
            7u,
            offer_nonce,
            offer,
            sizeof(offer),
            &offer_length) != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_session_on_offer(
            &responder,
            offer,
            offer_length,
            responder_nonce,
            accept,
            sizeof(accept),
            &accept_length) != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_session_on_accept(
            &initiator, accept, accept_length) != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    *initiator_out = initiator;
    *responder_out = responder;
    return 1;
}

static int enable_mfdt_owner(ninlil_runtime_t *runtime, uint64_t cookie)
{
    ninlil_mfdt_v1_session_t session;

    return configure_mfdt_owner(runtime, 1u, cookie)
        && make_admitted_mfdt_session(
            runtime, 1u, cookie, 0x10u, &session)
        && ninlil_rt_mfdt_v1_runtime_bind_session(runtime, &session)
            == NINLIL_OK;
}

static void fill_target(cap_env_t *env);
static int ensure_payload(cap_env_t *env, uint32_t size);

static int prepare_mfdt_multi_env(
    cap_env_t *env,
    uint8_t application_tag,
    uint64_t cookie)
{
    (void)memset(env, 0, sizeof(*env));
    if (!platform_init(env)) {
        return 0;
    }
    env->config = config_controller(4u);
    env->config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env->config.limits.max_durable_outbox_payload_bytes = 262144u;
    env->config.limits.max_targets_per_transaction = 4u;
    set_id(&env->config.runtime_id, 0x30u);
    return ninlil_runtime_create(
               &env->config, &env->platform, &env->runtime) == NINLIL_OK &&
        configure_mfdt_owner(env->runtime, 1u, cookie) &&
        env_register_mfdt(env, application_tag, 4u);
}

static void fill_mfdt_roster_target(
    cap_env_t *env,
    ninlil_concrete_target_t *target,
    uint8_t runtime_tag,
    uint8_t application_tag)
{
    fill_target(env);
    *target = env->target;
    set_id(&target->target_runtime_id, runtime_tag);
    set_id(&target->target_application_instance_id, application_tag);
}

static ninlil_status_t submit_mfdt_roster(
    cap_env_t *env,
    const ninlil_concrete_target_t *targets,
    uint32_t target_count,
    const uint8_t *idempotency_key,
    uint32_t idempotency_length,
    ninlil_submission_result_t *out_result)
{
    ninlil_submission_t submission;

    if (!ensure_payload(env, 927u)) {
        return NINLIL_E_INTERNAL;
    }
    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = targets;
    submission.target_count = target_count;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = 5000u;
    submission.evidence_grace_ms = 1000u;
    submission.generation = 1u;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length = idempotency_length;
    submission.payload.data = env->payload;
    submission.payload.length = 927u;
    if (!set_payload_content_digest(
            &submission.content_digest, env->payload, 927u)) {
        return NINLIL_E_INTERNAL;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    return ninlil_submit(env->service, &submission, out_result);
}

static int mfdt_active_count_is(
    ninlil_runtime_t *runtime,
    uint32_t expected)
{
    ninlil_rt_mfdt_v1_runtime_snapshot_t snapshot;

    (void)memset(&snapshot, 0, sizeof(snapshot));
    snapshot.struct_size = (uint32_t)sizeof(snapshot);
    return ninlil_rt_mfdt_v1_runtime_snapshot(runtime, &snapshot)
            == NINLIL_OK
        && snapshot.active_count == expected;
}

static int mfdt_sidecar_matches_foundation(
    const cap_env_t *env,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *target_runtime_id,
    const ninlil_id128_t *attempt_id,
    uint32_t target_ordinal,
    const uint8_t expected_transfer_id[16])
{
    const ninlil_storage_ops_t *storage = env->platform.storage;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t read_txn = NULL;
    ninlil_bytes_view_t namespace_view;
    ninlil_bytes_view_t key_view;
    ninlil_mut_bytes_t value;
    uint8_t namespace_preimage[
        sizeof(MFDT_SIDECAR_NAMESPACE_DOMAIN) - 1u + 2u
        + sizeof(TEST_NAMESPACE) - 1u];
    uint8_t sidecar_namespace[36];
    uint8_t transfer_material[52];
    uint8_t transfer_digest[32];
    uint8_t key[20];
    uint8_t *record = NULL;
    uint8_t unpacked_transfer_id[16];
    const uint8_t *open_body = NULL;
    uint16_t open_length = 0u;
    uint32_t offset = 0u;
    int ok = 0;

    if (env == NULL || transaction_id == NULL || target_runtime_id == NULL
        || !id_is_nonzero(attempt_id) || expected_transfer_id == NULL
        || storage == NULL) {
        return 0;
    }
    (void)memcpy(
        namespace_preimage + offset,
        MFDT_SIDECAR_NAMESPACE_DOMAIN,
        sizeof(MFDT_SIDECAR_NAMESPACE_DOMAIN) - 1u);
    offset += (uint32_t)sizeof(MFDT_SIDECAR_NAMESPACE_DOMAIN) - 1u;
    ninlil_mfdt_v1_put_u16(
        namespace_preimage + offset,
        (uint16_t)(sizeof(TEST_NAMESPACE) - 1u));
    offset += 2u;
    (void)memcpy(
        namespace_preimage + offset,
        TEST_NAMESPACE,
        sizeof(TEST_NAMESPACE) - 1u);
    offset += (uint32_t)sizeof(TEST_NAMESPACE) - 1u;
    ninlil_mfdt_v1_sha256(
        namespace_preimage, offset, sidecar_namespace + 4u);
    (void)memcpy(sidecar_namespace, "NMF1", 4u);

    (void)memcpy(
        transfer_material, transaction_id->bytes, 16u);
    (void)memcpy(
        transfer_material + 16u,
        target_runtime_id->bytes,
        16u);
    transfer_material[32] = (uint8_t)(target_ordinal >> 24);
    transfer_material[33] = (uint8_t)(target_ordinal >> 16);
    transfer_material[34] = (uint8_t)(target_ordinal >> 8);
    transfer_material[35] = (uint8_t)target_ordinal;
    (void)memcpy(
        transfer_material + 36u, "ninlil-mfdt-v1id", 16u);
    ninlil_mfdt_v1_sha256(
        transfer_material, sizeof(transfer_material), transfer_digest);
    (void)memcpy(key, "NM3S", 4u);
    (void)memcpy(key + 4u, transfer_digest, 16u);

    record = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    if (record == NULL) {
        return 0;
    }
    namespace_view.data = sidecar_namespace;
    namespace_view.length = sizeof(sidecar_namespace);
    if (storage->open(
            storage->user,
            namespace_view,
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle) != NINLIL_STORAGE_OK
        || storage->begin(
               storage->user,
               handle,
               NINLIL_STORAGE_READ_ONLY,
               &read_txn) != NINLIL_STORAGE_OK) {
        goto done;
    }
    key_view.data = key;
    key_view.length = sizeof(key);
    value.data = record;
    value.capacity = NINLIL_MFDT_V1_ACTIVE_VALUE_MAX;
    value.length = 0u;
    if (storage->get(storage->user, read_txn, key_view, &value)
            != NINLIL_STORAGE_OK
        || ninlil_mfdt_v1_record_unpack(
               record,
               value.length,
               NULL,
               NULL,
               unpacked_transfer_id,
               NULL,
               NULL,
               &open_body,
               &open_length,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL,
               NULL) != NINLIL_MFDT_V1_OK) {
        goto done;
    }
    ok = open_length >= 250u
        && memcmp(unpacked_transfer_id, transfer_digest, 16u) == 0
        && memcmp(open_body, transfer_digest, 16u) == 0
        && memcmp(expected_transfer_id, transfer_digest, 16u) == 0
        && memcmp(
               open_body + 64u,
               transaction_id->bytes,
               16u) == 0
        && memcmp(open_body + 234u, attempt_id->bytes, 16u) == 0;

done:
    if (read_txn != NULL) {
        (void)storage->rollback(storage->user, read_txn);
    }
    if (handle != NULL) {
        storage->close(storage->user, handle);
    }
    free(record);
    return ok;
}

typedef struct mfdt_submit_fault {
    ninlil_test_storage_t *storage;
    const char *hook_name;
    ninlil_storage_status_t status;
    uint32_t commit_unknown_committed;
    uint32_t match_skip;
    uint32_t match_count;
    uint32_t fired;
    const char *second_hook_name;
    ninlil_storage_status_t second_status;
    uint32_t second_commit_unknown_committed;
    uint32_t second_match_skip;
    uint32_t second_match_count;
    uint32_t second_fired;
} mfdt_submit_fault_t;

typedef struct mfdt_entropy_fault {
    ninlil_test_entropy_t *entropy;
    ninlil_test_entropy_action_kind_t action;
    uint32_t partial_prefix_length;
    uint32_t remaining_count;
    uint32_t match_skip;
    uint32_t match_count;
    uint32_t fired;
} mfdt_entropy_fault_t;

typedef struct mfdt_collision_fault {
    ninlil_test_entropy_t *entropy;
    uint64_t first_target_counter;
    uint32_t target_hook_count;
    uint32_t fired;
} mfdt_collision_fault_t;

static int mfdt_script_commit_fault(
    mfdt_submit_fault_t *fault,
    ninlil_storage_status_t status,
    uint32_t commit_unknown_committed)
{
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return ninlil_test_storage_fault_enqueue(
            fault->storage,
            NINLIL_TEST_STORAGE_OP_COMMIT,
            status,
            1u,
            1,
            commit_unknown_committed != 0u);
    }
    return ninlil_test_storage_fault_next(
        fault->storage,
        NINLIL_TEST_STORAGE_OP_COMMIT,
        status);
}

static void mfdt_submit_fault_hook(void *user, const char *name)
{
    mfdt_submit_fault_t *fault = (mfdt_submit_fault_t *)user;

    if (fault == NULL || name == NULL) {
        return;
    }
    if (fault->fired == 0u && fault->hook_name != NULL
        && strcmp(name, fault->hook_name) == 0) {
        if (fault->match_count == fault->match_skip) {
            fault->fired = (uint32_t)mfdt_script_commit_fault(
                fault, fault->status, fault->commit_unknown_committed);
        }
        fault->match_count += 1u;
    }
    if (fault->second_fired == 0u && fault->second_hook_name != NULL
        && strcmp(name, fault->second_hook_name) == 0) {
        if (fault->second_match_count == fault->second_match_skip) {
            fault->second_fired = (uint32_t)mfdt_script_commit_fault(
                fault,
                fault->second_status,
                fault->second_commit_unknown_committed);
        }
        fault->second_match_count += 1u;
    }
}

static void mfdt_entropy_fault_hook(void *user, const char *name)
{
    mfdt_entropy_fault_t *fault = (mfdt_entropy_fault_t *)user;

    if (fault == NULL || name == NULL || fault->fired != 0u
        || strcmp(name, "admission.before_mfdt_attempt_draw") != 0) {
        return;
    }
    if (fault->match_count++ != fault->match_skip) {
        return;
    }
    fault->fired = 1u;
    (void)ninlil_test_entropy_script(
        fault->entropy,
        fault->action,
        fault->partial_prefix_length,
        fault->remaining_count);
}

static void mfdt_collision_fault_hook(void *user, const char *name)
{
    mfdt_collision_fault_t *fault = (mfdt_collision_fault_t *)user;

    if (fault == NULL || fault->entropy == NULL || name == NULL ||
        strcmp(name, "admission.before_mfdt_attempt_draw") != 0) {
        return;
    }
    if (fault->target_hook_count == 0u) {
        fault->first_target_counter =
            ninlil_test_entropy_counter(fault->entropy);
    } else if (fault->target_hook_count == 1u) {
        fault->fired = (uint32_t)ninlil_test_entropy_set_counter_for_test(
            fault->entropy, fault->first_target_counter, 0);
    }
    fault->target_hook_count += 1u;
}
#endif

static void fill_target(cap_env_t *env)
{
    (void)memset(&env->target, 0, sizeof(env->target));
    set_header(&env->target.abi_version, &env->target.struct_size, sizeof(env->target));
    set_id(&env->target.target_runtime_id, 0x10u);
    set_id(&env->target.target_application_instance_id, 0x81u);
    set_id(&env->target.device_id, 0x82u);
    set_id(&env->target.site_domain_id, 0x83u);
    env->target.binding_epoch = 1u;
    env->target.membership_epoch = 1u;
    env->target.flags = NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;
}

static int ensure_payload(cap_env_t *env, uint32_t size)
{
    if (env->payload_capacity >= size) {
        return 1;
    }
    if (env->payload != NULL) {
        free(env->payload);
        env->payload = NULL;
    }
    env->payload = (uint8_t *)malloc(size);
    if (env->payload == NULL) {
        return 0;
    }
    (void)memset(env->payload, 0xA5u, size);
    env->payload_capacity = size;
    return 1;
}

static ninlil_status_t submit_with_payload_status(
    cap_env_t *env,
    uint32_t payload_length,
    uint64_t effect_deadline_ms,
    uint8_t digest_tag,
    const uint8_t *idem_key,
    size_t idem_key_length,
    ninlil_submission_result_t *out_result)
{
    ninlil_submission_t submission;
    static const uint8_t default_idem[] = "cap-idem";

    if (!ensure_payload(env, payload_length)) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    fill_target(env);
    (void)memset(&submission, 0, sizeof(submission));
    set_header(&submission.abi_version, &submission.struct_size, sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &env->target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = effect_deadline_ms;
    submission.evidence_grace_ms = 1000u;
    submission.generation = 1u;
    submission.idempotency_key.data = idem_key != NULL ? idem_key : default_idem;
    submission.idempotency_key.length = idem_key != NULL
        ? idem_key_length
        : sizeof(default_idem) - 1u;
    submission.payload.data = env->payload;
    submission.payload.length = payload_length;
    (void)digest_tag;
    if (!set_payload_content_digest(
            &submission.content_digest, env->payload, payload_length)) {
        return NINLIL_E_INTERNAL;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    return ninlil_submit(env->service, &submission, out_result);
}

static int submit_with_payload(
    cap_env_t *env,
    uint32_t payload_length,
    uint64_t effect_deadline_ms,
    uint8_t digest_tag,
    const uint8_t *idem_key,
    size_t idem_key_length,
    ninlil_submission_result_t *out_result)
{
    ninlil_status_t status = submit_with_payload_status(
        env,
        payload_length,
        effect_deadline_ms,
        digest_tag,
        idem_key,
        idem_key_length,
        out_result);

    if (status != NINLIL_OK) {
        (void)fprintf(
            stderr,
            "submit failed: payload=%u status=%u\n",
            (unsigned)payload_length,
            (unsigned)status);
    }
    return status == NINLIL_OK;
}

static uint32_t count_storage_tx_markers(ninlil_test_storage_t *storage_fixture)
{
    return ninlil_test_storage_count_keys_with_prefix(
        storage_fixture,
        (ninlil_bytes_view_t){TEST_NAMESPACE, sizeof(TEST_NAMESPACE) - 1u},
        0x54u,
        0x58u);
}

static int raw_storage_mutate(
    ninlil_test_storage_t *storage_fixture,
    ninlil_bytes_view_t storage_namespace,
    ninlil_bytes_view_t key,
    const ninlil_bytes_view_t *value)
{
    const ninlil_storage_ops_t *storage =
        ninlil_test_storage_ops(storage_fixture);
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t status;

    if (storage->open(
            storage->user,
            storage_namespace,
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle)
        != NINLIL_STORAGE_OK) {
        return 0;
    }
    if (storage->begin(
            storage->user,
            handle,
            NINLIL_STORAGE_READ_WRITE,
            &txn)
        != NINLIL_STORAGE_OK) {
        (void)storage->close(storage->user, handle);
        return 0;
    }
    status = value == NULL
        ? storage->erase(storage->user, txn, key)
        : storage->put(storage->user, txn, key, *value);
    if (status != NINLIL_STORAGE_OK
        || storage->commit(
                storage->user, txn, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        if (status == NINLIL_STORAGE_OK) {
            (void)storage->rollback(storage->user, txn);
        }
        (void)storage->close(storage->user, handle);
        return 0;
    }
    (void)storage->close(storage->user, handle);
    return 1;
}

#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
static int derive_mfdt_sidecar_namespace(
    const cap_env_t *env,
    uint8_t out[36])
{
    uint8_t preimage[
        sizeof(MFDT_SIDECAR_NAMESPACE_DOMAIN) - 1u + 2u + 255u];
    uint32_t offset = 0u;

    if (env == NULL || out == NULL ||
        env->config.storage_namespace.data == NULL ||
        env->config.storage_namespace.length == 0u ||
        env->config.storage_namespace.length > 255u) {
        return 0;
    }
    (void)memcpy(
        preimage + offset,
        MFDT_SIDECAR_NAMESPACE_DOMAIN,
        sizeof(MFDT_SIDECAR_NAMESPACE_DOMAIN) - 1u);
    offset += (uint32_t)sizeof(MFDT_SIDECAR_NAMESPACE_DOMAIN) - 1u;
    ninlil_mfdt_v1_put_u16(
        preimage + offset,
        (uint16_t)env->config.storage_namespace.length);
    offset += 2u;
    (void)memcpy(
        preimage + offset,
        env->config.storage_namespace.data,
        env->config.storage_namespace.length);
    offset += env->config.storage_namespace.length;
    (void)memcpy(out, "NMF1", 4u);
    ninlil_mfdt_v1_sha256(preimage, offset, out + 4u);
    return 1;
}

static int raw_mfdt_row_present(
    const cap_env_t *env,
    const char magic[4],
    const uint8_t transfer_id[16])
{
    const ninlil_storage_ops_t *storage = env->platform.storage;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_mut_bytes_t value;
    uint8_t sidecar_namespace[36];
    uint8_t key[20];
    ninlil_storage_status_t status;
    int present = 0;

    if (storage == NULL ||
        !derive_mfdt_sidecar_namespace(env, sidecar_namespace)) {
        return 0;
    }
    (void)memcpy(key, magic, 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    if (storage->open(
            storage->user,
            (ninlil_bytes_view_t){
                sidecar_namespace, sizeof(sidecar_namespace)},
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle) != NINLIL_STORAGE_OK ||
        storage->begin(
            storage->user,
            handle,
            NINLIL_STORAGE_READ_ONLY,
            &transaction) != NINLIL_STORAGE_OK) {
        goto done;
    }
    value.data = NULL;
    value.capacity = 0u;
    value.length = 0u;
    status = storage->get(
        storage->user,
        transaction,
        (ninlil_bytes_view_t){key, sizeof(key)},
        &value);
    present = status == NINLIL_STORAGE_OK ||
        status == NINLIL_STORAGE_BUFFER_TOO_SMALL;

done:
    if (transaction != NULL) {
        (void)storage->rollback(storage->user, transaction);
    }
    if (handle != NULL) {
        storage->close(storage->user, handle);
    }
    return present;
}

static int raw_mfdt_erase_pair(
    cap_env_t *env,
    const uint8_t transfer_id[16])
{
    uint8_t sidecar_namespace[36];
    uint8_t key[20];

    if (env == NULL || transfer_id == NULL ||
        !derive_mfdt_sidecar_namespace(env, sidecar_namespace)) {
        return 0;
    }
    (void)memcpy(key + 4u, transfer_id, 16u);
    (void)memcpy(key, "NM3S", 4u);
    if (!raw_storage_mutate(
            env->storage_fixture,
            (ninlil_bytes_view_t){
                sidecar_namespace, sizeof(sidecar_namespace)},
            (ninlil_bytes_view_t){key, sizeof(key)},
            NULL)) {
        return 0;
    }
    (void)memcpy(key, "NRC1", 4u);
    return raw_storage_mutate(
        env->storage_fixture,
        (ninlil_bytes_view_t){sidecar_namespace, sizeof(sidecar_namespace)},
        (ninlil_bytes_view_t){key, sizeof(key)},
        NULL);
}

static int raw_mfdt_rekey_sender_pair_noncanonical(
    cap_env_t *env,
    const uint8_t old_transfer_id[16],
    const uint8_t new_transfer_id[16])
{
    const ninlil_storage_ops_t *storage = env != NULL
        ? env->platform.storage : NULL;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_mut_bytes_t value;
    ninlil_bytes_view_t replacement;
    const uint8_t *open_body = NULL;
    const uint8_t *entries = NULL;
    uint8_t sidecar_namespace[36];
    uint8_t key[20];
    uint8_t manifest_digest[32];
    uint8_t *values = NULL;
    uint8_t *active;
    uint8_t *nrc1;
    uint32_t active_length;
    uint16_t open_length = 0u;
    int ok = 0;

    if (storage == NULL || old_transfer_id == NULL || new_transfer_id == NULL ||
        memcmp(old_transfer_id, new_transfer_id, 16u) == 0 ||
        !derive_mfdt_sidecar_namespace(env, sidecar_namespace)) {
        return 0;
    }
    values = (uint8_t *)malloc(
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX +
        NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    if (values == NULL) {
        return 0;
    }
    active = values;
    nrc1 = values + NINLIL_MFDT_V1_ACTIVE_VALUE_MAX;
    (void)memcpy(key + 4u, old_transfer_id, 16u);
    if (storage->open(
            storage->user,
            (ninlil_bytes_view_t){
                sidecar_namespace, sizeof(sidecar_namespace)},
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle) != NINLIL_STORAGE_OK ||
        storage->begin(
            storage->user, handle, NINLIL_STORAGE_READ_ONLY,
            &transaction) != NINLIL_STORAGE_OK) {
        goto done;
    }
    (void)memcpy(key, "NM3S", 4u);
    value.data = active;
    value.capacity = NINLIL_MFDT_V1_ACTIVE_VALUE_MAX;
    value.length = 0u;
    if (storage->get(
            storage->user, transaction,
            (ninlil_bytes_view_t){key, sizeof(key)}, &value) !=
            NINLIL_STORAGE_OK) {
        goto done;
    }
    active_length = value.length;
    (void)memcpy(key, "NRC1", 4u);
    value.data = nrc1;
    value.capacity = NINLIL_MFDT_V1_NRC1_VALUE_BYTES;
    value.length = 0u;
    if (storage->get(
            storage->user, transaction,
            (ninlil_bytes_view_t){key, sizeof(key)}, &value) !=
            NINLIL_STORAGE_OK ||
        value.length != NINLIL_MFDT_V1_NRC1_VALUE_BYTES ||
        ninlil_mfdt_v1_record_unpack(
            active, active_length, NULL, NULL, NULL, NULL, NULL,
            &open_body, &open_length, &entries, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL) != NINLIL_MFDT_V1_OK ||
        memcmp(active + 16u, old_transfer_id, 16u) != 0 ||
        memcmp(nrc1, "NRC1", 4u) != 0 ||
        memcmp(nrc1 + 8u, old_transfer_id, 16u) != 0 ||
        open_length < NINLIL_MFDT_V1_OPEN_TEXT_OFFSET) {
        goto done;
    }
    (void)storage->rollback(storage->user, transaction);
    transaction = NULL;
    storage->close(storage->user, handle);
    handle = NULL;

    (void)memcpy(active + 16u, new_transfer_id, 16u);
    (void)memcpy((uint8_t *)open_body, new_transfer_id, 16u);
    ninlil_mfdt_v1_manifest_digest(
        open_body,
        open_body + NINLIL_MFDT_V1_OPEN_BASE_BYTES,
        open_body + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET,
        (uint16_t)(open_length - NINLIL_MFDT_V1_OPEN_TEXT_OFFSET),
        entries,
        ninlil_mfdt_v1_get_u16(open_body + 26u),
        manifest_digest);
    (void)memcpy(active + 36u, manifest_digest, 32u);
    (void)memcpy(
        (uint8_t *)open_body + NINLIL_MFDT_V1_OPEN_HEAD_BYTES,
        manifest_digest,
        32u);
    ninlil_mfdt_v1_put_u32(
        active + 304u, ninlil_mfdt_v1_crc32c(active, 304u));
    ninlil_mfdt_v1_put_u32(
        active + active_length - 4u,
        ninlil_mfdt_v1_crc32c(active, active_length - 4u));
    (void)memcpy(nrc1 + 8u, new_transfer_id, 16u);
    ninlil_mfdt_v1_put_u32(
        nrc1 + 36u, ninlil_mfdt_v1_crc32c(nrc1, 36u));
    ninlil_mfdt_v1_put_u32(
        nrc1 + NINLIL_MFDT_V1_NRC1_VALUE_BYTES - 4u,
        ninlil_mfdt_v1_crc32c(
            nrc1, NINLIL_MFDT_V1_NRC1_VALUE_BYTES - 4u));

    (void)memcpy(key, "NM3S", 4u);
    ok = raw_storage_mutate(
        env->storage_fixture,
        (ninlil_bytes_view_t){sidecar_namespace, sizeof(sidecar_namespace)},
        (ninlil_bytes_view_t){key, sizeof(key)}, NULL);
    (void)memcpy(key, "NRC1", 4u);
    ok = ok && raw_storage_mutate(
        env->storage_fixture,
        (ninlil_bytes_view_t){sidecar_namespace, sizeof(sidecar_namespace)},
        (ninlil_bytes_view_t){key, sizeof(key)}, NULL);
    (void)memcpy(key + 4u, new_transfer_id, 16u);
    (void)memcpy(key, "NM3S", 4u);
    replacement.data = active;
    replacement.length = active_length;
    ok = ok && raw_storage_mutate(
        env->storage_fixture,
        (ninlil_bytes_view_t){sidecar_namespace, sizeof(sidecar_namespace)},
        (ninlil_bytes_view_t){key, sizeof(key)}, &replacement);
    (void)memcpy(key, "NRC1", 4u);
    replacement.data = nrc1;
    replacement.length = NINLIL_MFDT_V1_NRC1_VALUE_BYTES;
    ok = ok && raw_storage_mutate(
        env->storage_fixture,
        (ninlil_bytes_view_t){sidecar_namespace, sizeof(sidecar_namespace)},
        (ninlil_bytes_view_t){key, sizeof(key)}, &replacement);

done:
    if (transaction != NULL) {
        (void)storage->rollback(storage->user, transaction);
    }
    if (handle != NULL) {
        storage->close(storage->user, handle);
    }
    free(values);
    return ok;
}

static int raw_mfdt_find_single_transfer(
    const cap_env_t *env,
    const char magic[4],
    uint8_t transfer_id_out[16])
{
    const ninlil_storage_ops_t *storage = env->platform.storage;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    uint8_t sidecar_namespace[36];
    uint8_t key_bytes[20];
    uint8_t *value_bytes = NULL;
    ninlil_storage_status_t status;
    int found = 0;

    if (storage == NULL || transfer_id_out == NULL ||
        !derive_mfdt_sidecar_namespace(env, sidecar_namespace)) {
        return 0;
    }
    value_bytes = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    if (value_bytes == NULL) {
        return 0;
    }
    if (storage->open(
            storage->user,
            (ninlil_bytes_view_t){
                sidecar_namespace, sizeof(sidecar_namespace)},
            NINLIL_STORAGE_SCHEMA_M1A,
            &handle) != NINLIL_STORAGE_OK ||
        storage->begin(
            storage->user,
            handle,
            NINLIL_STORAGE_READ_ONLY,
            &transaction) != NINLIL_STORAGE_OK ||
        storage->iter_open(
            storage->user,
            transaction,
            (ninlil_bytes_view_t){(const uint8_t *)magic, 4u},
            &iterator) != NINLIL_STORAGE_OK) {
        goto done;
    }
    key.data = key_bytes;
    key.capacity = sizeof(key_bytes);
    key.length = 0u;
    value.data = value_bytes;
    value.capacity = NINLIL_MFDT_V1_ACTIVE_VALUE_MAX;
    value.length = 0u;
    status = storage->iter_next(storage->user, iterator, &key, &value);
    if (status != NINLIL_STORAGE_OK || key.length != sizeof(key_bytes) ||
        memcmp(key_bytes, magic, 4u) != 0) {
        goto done;
    }
    (void)memcpy(transfer_id_out, key_bytes + 4u, 16u);
    key.length = 0u;
    value.length = 0u;
    status = storage->iter_next(storage->user, iterator, &key, &value);
    found = status == NINLIL_STORAGE_NOT_FOUND;

done:
    if (iterator != NULL) {
        storage->iter_close(storage->user, iterator);
    }
    if (transaction != NULL) {
        (void)storage->rollback(storage->user, transaction);
    }
    if (handle != NULL) {
        storage->close(storage->user, handle);
    }
    free(value_bytes);
    return found;
}
#endif

static int raw_erase_marker(
    cap_env_t *env,
    uint16_t prefix,
    const ninlil_id128_t *transaction_id)
{
    uint8_t key[18];

    key[0] = (uint8_t)(prefix >> 8);
    key[1] = (uint8_t)prefix;
    (void)memcpy(
        &key[2], transaction_id->bytes, sizeof(transaction_id->bytes));
    return raw_storage_mutate(
        env->storage_fixture,
        env->config.storage_namespace,
        (ninlil_bytes_view_t){key, sizeof(key)},
        NULL);
}

static int test_bearer_limit_table(void)
{
    REQUIRE(ninlil_rt_v1_bearer_payload_limit(NINLIL_RT_V1_BEARER_ROUTE_U6) == 926u);
    REQUIRE(ninlil_rt_v1_bearer_payload_limit(
                NINLIL_RT_V1_BEARER_ROUTE_SIMULATED)
        == 926u);
    REQUIRE(ninlil_rt_v1_bearer_admits_payload(
        NINLIL_RT_V1_BEARER_ROUTE_U6, 926u));
    REQUIRE(!ninlil_rt_v1_bearer_admits_payload(
        NINLIL_RT_V1_BEARER_ROUTE_U6, 927u));
    return 0;
}

static int test_logical_fragment_single(void)
{
    ninlil_rt_v1_logical_fragment_desc_t frag;

    REQUIRE(ninlil_rt_v1_build_logical_fragment_desc(512u, &frag) == NINLIL_OK);
    REQUIRE(frag.fragment_index == 0u);
    REQUIRE(frag.fragment_count == 1u);
    REQUIRE(frag.fragment_logical_bytes == 512u);
    return 0;
}

static int test_payload_max_minus_one_admitted(void)
{
    cap_env_t env;
    ninlil_submission_result_t result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x70u));
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(submit_with_payload(&env, 925u, 5000u, 0x21u, NULL, 0u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == 1u);
    platform_teardown(&env);
    return 0;
}

static int test_payload_max_admitted(void)
{
    cap_env_t env;
    ninlil_submission_result_t result;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x71u));
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(submit_with_payload(&env, 926u, 5000u, 0x22u, NULL, 0u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == 1u);
    platform_teardown(&env);
    return 0;
}

static int test_payload_max_plus_one_rejected(void)
{
#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
    /*
     * In the private-MFDT profile 927 bytes is intentionally admitted.
     * X_MFDT_RUNTIME_FAIL_CLOSED below owns that profile's positive and
     * fail-closed assertions.
     */
    return 0;
#else
    cap_env_t env;
    ninlil_submission_result_t result;
    uint32_t tx_before;
    uint32_t tx_after;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x72u));
    tx_before = count_storage_tx_markers(env.storage_fixture);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(submit_with_payload(&env, 927u, 5000u, 0x23u, NULL, 0u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_INVALID_PAYLOAD_LENGTH);
    tx_after = count_storage_tx_markers(env.storage_fixture);
    REQUIRE(tx_before == tx_after);
    platform_teardown(&env);
    return 0;
#endif
}

static int test_deadline_timeout_outcome(void)
{
    cap_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
  static const uint8_t idem_a[] = "deadline-idem-a";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x73u));
    (void)memset(&submit_result, 0, sizeof(submit_result));
    REQUIRE(submit_with_payload(
        &env, 16u, 200u, 0x24u, idem_a, sizeof(idem_a) - 1u, &submit_result));
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_clock_advance(env.clock, 500u));
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_state_transitions = 8u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    platform_teardown(&env);
    return 0;
}

static int test_priority_dispatch_order(void)
{
    cap_env_t env;
    ninlil_submission_result_t result_a;
    ninlil_submission_result_t result_b;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    static const uint8_t idem_a[] = "prio-idem-a";
    static const uint8_t idem_b[] = "prio-idem-b";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x74u));
    (void)memset(&result_a, 0, sizeof(result_a));
    REQUIRE(submit_with_payload(
        &env, 16u, 10000u, 0x25u, idem_a, sizeof(idem_a) - 1u, &result_a));
    REQUIRE(result_a.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    (void)memset(&result_b, 0, sizeof(result_b));
    REQUIRE(submit_with_payload(
        &env, 16u, 1000u, 0x26u, idem_b, sizeof(idem_b) - 1u, &result_b));
    REQUIRE(result_b.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_state_transitions = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(step_result.more_work != 0u);
    platform_teardown(&env);
    return 0;
}

static int test_restart_preserves_admission(void)
{
    cap_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_runtime_config_t saved_config;
    ninlil_platform_ops_t saved_platform;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x75u));
    (void)memset(&submit_result, 0, sizeof(submit_result));
    REQUIRE(submit_with_payload(&env, 926u, 5000u, 0x27u, NULL, 0u, &submit_result));
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    saved_config = env.config;
    saved_platform = env.platform;
    (void)ninlil_runtime_destroy(env.runtime);
    env.runtime = NULL;
    env.config = saved_config;
    env.platform = saved_platform;
    REQUIRE(env_create(&env));
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == 1u);
    platform_teardown(&env);
    return 0;
}

#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
static int step_runtime(
    cap_env_t *env,
    uint32_t max_bearer_sends,
    ninlil_step_result_t *out_result);
static ninlil_status_t step_runtime_status(
    cap_env_t *env,
    uint32_t max_bearer_sends,
    ninlil_step_result_t *out_result);

static int test_mfdt_runtime_waits_without_single_frame_fallback(void)
{
    static const uint8_t single_idem[] = "mfdt-negative-single-frame";
    static const uint8_t mfdt_idem[] = "mfdt-runtime-fail-closed";
    static const uint8_t lost_idem[] = "mfdt-runtime-lost-unknown";
    cap_env_t env;
    ninlil_submission_result_t submitted;
    ninlil_submission_result_t submitted_4k;
    ninlil_submission_result_t submitted_lost;
    ninlil_step_result_t step_result;
    ninlil_bearer_send_result_t raw_send_result;
    ninlil_bearer_message_t received;
    ninlil_bearer_handle_t peer = NULL;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_mfdt_v1_runtime_snapshot_t owner_snapshot;
    uint64_t send_calls;
    uint64_t acquire_calls;
    size_t trace_start;
    const ninlil_test_bearer_trace_record_t *first_send = NULL;
    const ninlil_test_bearer_trace_record_t *second_send = NULL;
    const ninlil_test_bearer_trace_record_t *retry_send = NULL;
    uint8_t wire_type = 0u;
    uint32_t wire_request_id = 0u;
    uint32_t wire_generation = 0u;
    uint64_t wire_cookie = 0u;
    const uint8_t *wire_body = NULL;
    uint16_t wire_body_length = 0u;
    size_t trace_index;
    uint32_t step_index;

    /*
     * Negative control: the fence is shape-specific. A maximum-size
     * single-frame transaction must still reach the ordinary bearer path.
    */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env_register(&env, 0xa1u));
    REQUIRE(submit_with_payload(
        &env,
        926u,
        5000u,
        0x61u,
        single_idem,
        sizeof(single_idem) - 1u,
        &submitted));
    REQUIRE(submitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->bearer_route
        != (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
    REQUIRE(transaction->payload_length == 926u);
    REQUIRE(transaction->inline_payload_length == 926u);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &env.target.target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);
    send_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    for (step_index = 0u; step_index < 6u; ++step_index) {
        REQUIRE(step_runtime(&env, 1u, &step_result));
        if (ninlil_test_bearer_call_count(
                env.bearer_fixture,
                NINLIL_TEST_BEARER_OP_SEND) > send_calls) {
            break;
        }
    }
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        > send_calls);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        > 0u);
    env.platform.bearer->close(
        env.platform.bearer->user, peer);
    peer = NULL;
    platform_teardown(&env);

    /*
     * Positive fence: logical content is in NM3S and admission has prepared
     * its one Application attempt. Repeated Runtime steps may report pending
     * work, but cannot create a second attempt or send an empty U6 APPLICATION.
    */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x4d464454)));
    REQUIRE(env_register_mfdt(&env, 0xa2u, 1u));
    REQUIRE(submit_with_payload(
        &env,
        927u,
        5000u,
        0x62u,
        mfdt_idem,
        sizeof(mfdt_idem) - 1u,
        &submitted));
    REQUIRE(submitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->bearer_route
        == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
    REQUIRE(transaction->payload_length == 927u);
    REQUIRE(transaction->inline_payload_length == 0u);
    REQUIRE(transaction->delivery_phase == NINLIL_RT_DELIVERY_QUEUED);
    REQUIRE(transaction->pending_dispatch == 1u);
    REQUIRE(transaction->attempt_prepared == 1u);
    REQUIRE(transaction->attempt_count == 1u);
    REQUIRE(transaction->attempt_in_cycle == 0u);
    REQUIRE(transaction->cumulative_attempts == 1u);
    REQUIRE(transaction->retry_budget
        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - 1u);
    REQUIRE(memcmp(
        transaction->attempt_id.bytes,
        transaction->attempt_ids[0].bytes,
        sizeof(transaction->attempt_id.bytes)) == 0);
    REQUIRE(transaction->attempt_target_indices[0] == 0u);
    REQUIRE(transaction->bound_targets[0].attempt_prepared == 1u);
    REQUIRE(transaction->bound_targets[0].attempt_in_cycle == 1u);
    REQUIRE(transaction->bound_targets[0].cumulative_attempts == 1u);
    REQUIRE(transaction->bound_targets[0].retry_budget
        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - 1u);
    REQUIRE(memcmp(
        transaction->attempt_id.bytes,
        transaction->bound_targets[0].active_attempt_id.bytes,
        sizeof(transaction->attempt_id.bytes)) == 0);
    REQUIRE(submit_with_payload(
        &env,
        4096u,
        5000u,
        0x63u,
        (const uint8_t *)"mfdt-runtime-4096",
        sizeof("mfdt-runtime-4096") - 1u,
        &submitted_4k));
    REQUIRE(submitted_4k.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submitted_4k.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->bearer_route
        == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
    REQUIRE(transaction->payload_length == 4096u);
    REQUIRE(transaction->inline_payload_length == 0u);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submitted.transaction_id);
    REQUIRE(transaction != NULL);
    (void)memset(&owner_snapshot, 0, sizeof(owner_snapshot));
    owner_snapshot.struct_size = (uint32_t)sizeof(owner_snapshot);
    REQUIRE(ninlil_rt_mfdt_v1_runtime_snapshot(
                env.runtime, &owner_snapshot) == NINLIL_OK);
    REQUIRE(owner_snapshot.active_count == 2u);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &env.target.target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);
    send_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquire_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    trace_start = ninlil_test_bearer_trace_count(env.bearer_fixture);

    /* A zero send budget neither consumes the Host outbox nor calls Bearer. */
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_result.more_work == 1u);
    REQUIRE(step_result.bearer_sends == 0u);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquire_calls);

    /* WOULD_BLOCK owns no frame: Runtime retains the exact NCL1 for retry. */
    (void)memset(&raw_send_result, 0, sizeof(raw_send_result));
    set_header(
        &raw_send_result.abi_version,
        &raw_send_result.struct_size,
        sizeof(raw_send_result));
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(
        env.bearer_fixture,
        NINLIL_BEARER_WOULD_BLOCK,
        &raw_send_result,
        1u));
    REQUIRE(step_runtime(&env, 1u, &step_result));
    REQUIRE(step_result.bearer_sends == 1u);
    REQUIRE(step_result.more_work == 1u);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls + 1u);

    /* Fairness sends the other active transfer before retrying this frame. */
    REQUIRE(step_runtime(&env, 1u, &step_result));
    REQUIRE(step_result.bearer_sends == 1u);
    REQUIRE(step_result.more_work == 1u);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls + 2u);
    for (trace_index = trace_start;
         trace_index < ninlil_test_bearer_trace_count(env.bearer_fixture);
         ++trace_index) {
        const ninlil_test_bearer_trace_record_t *trace =
            ninlil_test_bearer_trace_at(env.bearer_fixture, trace_index);

        if (trace == NULL
            || trace->operation != NINLIL_TEST_BEARER_OP_SEND) {
            continue;
        }
        if (first_send == NULL) {
            first_send = trace;
        } else if (second_send == NULL) {
            second_send = trace;
            break;
        }
    }
    REQUIRE(first_send != NULL && second_send != NULL);
    REQUIRE(first_send->bearer_status == NINLIL_BEARER_WOULD_BLOCK);
    REQUIRE(second_send->bearer_status == NINLIL_BEARER_OK);
    REQUIRE(memcmp(
        first_send->transaction_id.bytes,
        second_send->transaction_id.bytes,
        16u) != 0);
    REQUIRE(memcmp(
        first_send->attempt_id.bytes,
        second_send->attempt_id.bytes,
        16u) != 0);

    for (step_index = 0u; step_index < 8u && retry_send == NULL;
         ++step_index) {
        const size_t retry_start =
            ninlil_test_bearer_trace_count(env.bearer_fixture);

        REQUIRE(step_runtime(&env, 1u, &step_result));
        REQUIRE(step_result.more_work == 1u);
        for (trace_index = retry_start;
             trace_index < ninlil_test_bearer_trace_count(env.bearer_fixture);
             ++trace_index) {
            const ninlil_test_bearer_trace_record_t *trace =
                ninlil_test_bearer_trace_at(
                    env.bearer_fixture, trace_index);

            if (trace != NULL
                && trace->operation == NINLIL_TEST_BEARER_OP_SEND
                && memcmp(
                       trace->transaction_id.bytes,
                       first_send->transaction_id.bytes,
                       16u) == 0) {
                retry_send = trace;
                break;
            }
        }
    }
    REQUIRE(retry_send != NULL);
    REQUIRE(retry_send->bearer_status == NINLIL_BEARER_OK);
    REQUIRE(memcmp(
        first_send->attempt_id.bytes,
        retry_send->attempt_id.bytes,
        16u) == 0);
    REQUIRE(first_send->logical_bytes == retry_send->logical_bytes);

    (void)memset(&received, 0, sizeof(received));
    set_header(&received.abi_version, &received.struct_size, sizeof(received));
    REQUIRE(env.platform.bearer->receive_next(
                env.platform.bearer->user, peer, &received)
        == NINLIL_BEARER_OK);
    REQUIRE(received.kind == NINLIL_BEARER_MESSAGE_APPLICATION);
    REQUIRE(received.service.family == NINLIL_FAMILY_TRANSFER_RESERVED);
    REQUIRE(received.payload.data != NULL && received.payload.length > 0u);
    REQUIRE(ninlil_mfdt_v1_ncl1_decode(
        received.payload.data,
        received.payload.length,
        NINLIL_MFDT_V1_NCG1_DATA,
        &wire_type,
        &wire_request_id,
        &wire_generation,
        &wire_cookie,
        &wire_body,
        &wire_body_length) == NINLIL_MFDT_V1_OK);
    REQUIRE(wire_type == NINLIL_MFDT_V1_MSG_OPEN);
    REQUIRE(wire_request_id != 0u);
    REQUIRE(wire_generation == 1u);
    REQUIRE(wire_cookie == UINT64_C(0x4d464454));
    REQUIRE(wire_body != NULL && wire_body_length != 0u);
    env.platform.bearer->release_received(
        env.platform.bearer->user, peer, &received);

    /* A newly admitted transfer proves LOST_UNKNOWN is never retried. */
    REQUIRE(submit_with_payload(
        &env,
        4096u,
        5000u,
        0x64u,
        lost_idem,
        sizeof(lost_idem) - 1u,
        &submitted_lost));
    REQUIRE(submitted_lost.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    (void)memset(&raw_send_result, 0, sizeof(raw_send_result));
    set_header(
        &raw_send_result.abi_version,
        &raw_send_result.struct_size,
        sizeof(raw_send_result));
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(
        env.bearer_fixture,
        NINLIL_BEARER_LOST_UNKNOWN,
        &raw_send_result,
        1u));
    REQUIRE(step_runtime_status(&env, 1u, &step_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(step_result.bearer_sends == 1u);
    send_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    REQUIRE(step_runtime_status(&env, 1u, &step_result)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(step_result.bearer_sends == 0u);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &submitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->terminal == 0u);
    REQUIRE(transaction->pending_dispatch == 1u);
    REQUIRE(transaction->attempt_prepared == 1u);
    REQUIRE(transaction->attempt_count == 1u);
    REQUIRE(transaction->attempt_in_cycle == 0u);
    REQUIRE(transaction->cumulative_attempts == 1u);

    env.platform.bearer->close(
        env.platform.bearer->user, peer);
    peer = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env.runtime = NULL;
    env.service = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_session_binding_fail_closed(void)
{
    static const uint8_t idem_unbound[] = "mfdt-session-unbound";
    static const uint8_t idem_wrong_peer[] = "mfdt-session-wrong-peer";
    static const uint8_t idem_bound[] = "mfdt-session-bound";
    const uint64_t cookie = UINT64_C(0x6161616161616161);
    cap_env_t env;
    ninlil_mfdt_v1_session_t session;
    ninlil_submission_t submission;
    ninlil_submission_result_t result;
    ninlil_step_result_t step_result;
    ninlil_bearer_handle_t peer = NULL;
    ninlil_bearer_message_t received;
    uint64_t send_calls;
    uint64_t acquire_calls;
    uint64_t callback_calls;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(configure_mfdt_owner(env.runtime, 1u, cookie));
    REQUIRE(env_register_mfdt(&env, 0xa3u, 1u));
    send_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquire_calls = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    callback_calls = env.runtime->metrics.application_callback_invocations;

    /* Durable pre-arm is independent of a live carrier session. */
    REQUIRE(submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem_unbound,
        sizeof(idem_unbound) - 1u,
        &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(mfdt_active_count_is(env.runtime, 1u));
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquire_calls);
    REQUIRE(env.runtime->metrics.application_callback_invocations
        == callback_calls);

    REQUIRE(make_admitted_mfdt_session(
        env.runtime, 2u, cookie, 0x10u, &session));
    REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                env.runtime, &session) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(make_admitted_mfdt_session(
        env.runtime, 1u, cookie + 1u, 0x10u, &session));
    REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                env.runtime, &session) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(make_admitted_mfdt_session(
        env.runtime, 1u, cookie, 0x10u, &session));
    REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                env.runtime, &session) == NINLIL_OK);

    /* A different peer may be pre-armed, but gains no carrier activity. */
    REQUIRE(ensure_payload(&env, 927u));
    fill_target(&env);
    set_id(&env.target.target_runtime_id, 0x70u);
    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &env.target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = 5000u;
    submission.evidence_grace_ms = 1000u;
    submission.generation = 1u;
    submission.idempotency_key.data = idem_wrong_peer;
    submission.idempotency_key.length = sizeof(idem_wrong_peer) - 1u;
    submission.payload.data = env.payload;
    submission.payload.length = 927u;
    REQUIRE(set_payload_content_digest(
        &submission.content_digest, env.payload, 927u));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(mfdt_active_count_is(env.runtime, 2u));
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquire_calls);
    REQUIRE(env.runtime->metrics.application_callback_invocations
        == callback_calls);

    /* The same owner remains usable once the real admitted session matches. */
    REQUIRE(submit_with_payload(
        &env,
        927u,
        5000u,
        0u,
        idem_bound,
        sizeof(idem_bound) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &env.target.target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);
    REQUIRE(step_runtime(&env, 1u, &step_result));
    REQUIRE(step_result.bearer_sends == 1u);
    (void)memset(&received, 0, sizeof(received));
    set_header(&received.abi_version, &received.struct_size, sizeof(received));
    REQUIRE(env.platform.bearer->receive_next(
                env.platform.bearer->user, peer, &received)
        == NINLIL_BEARER_OK);
    REQUIRE(received.service.family == NINLIL_FAMILY_TRANSFER_RESERVED);
    REQUIRE(received.payload.data != NULL && received.payload.length != 0u);
    env.platform.bearer->release_received(
        env.platform.bearer->user, peer, &received);
    env.platform.bearer->close(
        env.platform.bearer->user, peer);
    peer = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_public_owner_boundaries_and_isolation(void)
{
    static const uint8_t idem_unconfigured[] = "mfdt-owner-off";
    static const uint8_t idem_927[] = "mfdt-owner-927";
    static const uint8_t idem_4096[] = "mfdt-owner-4096";
    static const uint8_t idem_32769[] = "mfdt-owner-32769";
    static const uint8_t idem_multi[] = "mfdt-owner-multi";
    cap_env_t env;
    ninlil_runtime_t *runtime_b = NULL;
    ninlil_runtime_config_t config_b;
    ninlil_submission_result_t result;
    ninlil_submission_t submission;
    ninlil_concrete_target_t targets[2];
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_id128_t transaction_927_id;
    ninlil_id128_t target_runtime_id;
    ninlil_id128_t attempt_927_id;
    uint8_t transfer_927_id[16];
    uint32_t tx_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    env.config.limits.max_targets_per_transaction = 2u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env_register_mfdt(&env, 0xb1u, 2u));

    config_b = env.config;
    config_b.storage_namespace.data = MFDT_TEST_NAMESPACE_B;
    config_b.storage_namespace.length = sizeof(MFDT_TEST_NAMESPACE_B) - 1u;
    set_id(&config_b.runtime_id, 0x50u);
    REQUIRE(ninlil_runtime_create(
                &config_b, &env.platform, &runtime_b) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        runtime_b, UINT64_C(0x4242424242424242)));
    REQUIRE(mfdt_active_count_is(runtime_b, 0u));

    /* Owner absent: 927 must stay on the ordinary 926-byte limit. */
    tx_before = count_storage_tx_markers(env.storage_fixture);
    REQUIRE(submit_with_payload(
        &env, 927u, 5000u, 0u,
        idem_unconfigured, sizeof(idem_unconfigured) - 1u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_INVALID_PAYLOAD_LENGTH);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);

    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x4141414141414141)));
    REQUIRE(submit_with_payload(
        &env, 927u, 5000u, 0u,
        idem_927, sizeof(idem_927) - 1u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->bearer_route
        == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
    REQUIRE(transaction->payload_length == 927u);
    REQUIRE(transaction->inline_payload_length == 0u);
    REQUIRE(transaction->attempt_prepared == 1u);
    REQUIRE(transaction->attempt_count == 1u);
    REQUIRE(id_is_nonzero(&transaction->attempt_id));
    REQUIRE(memcmp(
        transaction->attempt_id.bytes,
        transaction->attempt_ids[0].bytes,
        sizeof(transaction->attempt_id.bytes)) == 0);
    REQUIRE(transaction->attempt_target_indices[0] == 0u);
    REQUIRE(transaction->bound_targets[0].attempt_prepared == 1u);
    REQUIRE(memcmp(
        transaction->attempt_id.bytes,
        transaction->bound_targets[0].active_attempt_id.bytes,
        sizeof(transaction->attempt_id.bytes)) == 0);
    transaction_927_id = result.transaction_id;
    target_runtime_id = transaction->bound_targets[0].target.target_runtime_id;
    attempt_927_id = transaction->attempt_id;
    (void)memcpy(
        transfer_927_id,
        transaction->bound_targets[0].mfdt_transfer_id,
        sizeof(transfer_927_id));
    REQUIRE(mfdt_active_count_is(env.runtime, 1u));
    REQUIRE(mfdt_active_count_is(runtime_b, 0u));

    REQUIRE(submit_with_payload(
        &env, 4096u, 5000u, 0u,
        idem_4096, sizeof(idem_4096) - 1u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->bearer_route
        == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
    REQUIRE(transaction->payload_length == 4096u);
    REQUIRE(transaction->inline_payload_length == 0u);
    REQUIRE(mfdt_active_count_is(env.runtime, 2u));
    REQUIRE(mfdt_active_count_is(runtime_b, 0u));

    /* Above the MFDT maximum remains a clean semantic rejection. */
    tx_before = count_storage_tx_markers(env.storage_fixture);
    REQUIRE(submit_with_payload(
        &env, 32769u, 5000u, 0u,
        idem_32769, sizeof(idem_32769) - 1u, &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);
    REQUIRE(mfdt_active_count_is(env.runtime, 2u));

    /* This tranche supports one exact target only; never truncate the roster. */
    REQUIRE(ensure_payload(&env, 927u));
    fill_target(&env);
    targets[0] = env.target;
    targets[1] = env.target;
    set_id(&targets[1].target_application_instance_id, 0xd0u);
    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version, &submission.struct_size, sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = targets;
    submission.target_count = 2u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = 5000u;
    submission.evidence_grace_ms = 1000u;
    submission.idempotency_key.data = idem_multi;
    submission.idempotency_key.length = sizeof(idem_multi) - 1u;
    submission.generation = 1u;
    submission.payload.data = env.payload;
    submission.payload.length = 927u;
    REQUIRE(set_payload_content_digest(
        &submission.content_digest, env.payload, 927u));
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    tx_before = count_storage_tx_markers(env.storage_fixture);
    REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);
    REQUIRE(mfdt_active_count_is(env.runtime, 2u));

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(mfdt_sidecar_matches_foundation(
        &env,
        &transaction_927_id,
        &target_runtime_id,
        &attempt_927_id,
        0u,
        transfer_927_id));
    REQUIRE(ninlil_runtime_destroy(runtime_b) == NINLIL_OK);
    runtime_b = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_public_owner_commit_failures(void)
{
    static const uint8_t idem_prearm[] = "mfdt-prearm-failure";
    static const uint8_t idem_foundation[] = "mfdt-foundation-failure";
    static const uint8_t idem_foundation_cu[] = "mfdt-foundation-cu";
    static const uint8_t idem_cleanup_failure[] = "mfdt-cleanup-failure";
    static const uint8_t idem_cleanup_cu[] = "mfdt-cleanup-cu";
    cap_env_t env;
    mfdt_submit_fault_t fault;
    ninlil_submission_result_t result;
    ninlil_status_t status;
    uint32_t tx_before;
    uint64_t sequence_before;
    uint64_t commit_calls_before;
    uint64_t sends_before;
    uint64_t acquires_before;
    ninlil_model_resource_ledger_t ledger_before;

    /* Sidecar pre-arm failure: Foundation staging must roll back cleanly. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x5151515151515151)));
    REQUIRE(env_register_mfdt(&env, 0xc1u, 1u));
    (void)memset(&fault, 0, sizeof(fault));
    fault.storage = env.storage_fixture;
    fault.hook_name = "admission.before_mfdt_sender_open";
    fault.status = NINLIL_STORAGE_IO_ERROR;
    env.runtime->private_transition_hook = mfdt_submit_fault_hook;
    env.runtime->private_transition_hook_user = &fault;
    tx_before = count_storage_tx_markers(env.storage_fixture);
    status = submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem_prearm,
        sizeof(idem_prearm) - 1u,
        &result);
    REQUIRE(fault.fired == 1u);
    REQUIRE(status == NINLIL_E_STORAGE);
    REQUIRE(result.kind != NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);
    REQUIRE(env.runtime->transaction_count == 0u);
    REQUIRE(env.runtime->services[0].quota_inflight == 0u);
    REQUIRE(mfdt_active_count_is(env.runtime, 0u));
    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    platform_teardown(&env);

    /* Definite Foundation failure compare-erases the fresh sidecar arm. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x5252525252525252)));
    REQUIRE(env_register_mfdt(&env, 0xc2u, 1u));
    (void)memset(&fault, 0, sizeof(fault));
    fault.storage = env.storage_fixture;
    fault.hook_name = "admission.before_full_commit";
    fault.status = NINLIL_STORAGE_IO_ERROR;
    env.runtime->private_transition_hook = mfdt_submit_fault_hook;
    env.runtime->private_transition_hook_user = &fault;
    tx_before = count_storage_tx_markers(env.storage_fixture);
    sequence_before = env.runtime->transaction_sequence;
    ledger_before = env.runtime->resource_ledger;
    commit_calls_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    status = submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem_foundation,
        sizeof(idem_foundation) - 1u,
        &result);
    REQUIRE(fault.fired == 1u);
    REQUIRE(status == NINLIL_E_STORAGE);
    REQUIRE(result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);
    REQUIRE(env.runtime->transaction_sequence == sequence_before);
    REQUIRE(env.runtime->transaction_count == 0u);
    REQUIRE(env.runtime->nonterminal_transaction_count == 0u);
    REQUIRE(memcmp(
        &env.runtime->resource_ledger,
        &ledger_before,
        sizeof(ledger_before)) == 0);
    REQUIRE(env.runtime->services[0].quota_inflight == 0u);
    REQUIRE(env.runtime->services[0].quota_admissions == 0u);
    REQUIRE(env.runtime->services[0].quota_payload_bytes == 0u);
    REQUIRE(mfdt_active_count_is(env.runtime, 0u));
    REQUIRE(env.runtime->commit_unknown_fence == 0u);
    REQUIRE(ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls_before + 3u);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND) == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    REQUIRE(submit_with_payload_status(
        &env,
        100u,
        5000u,
        0u,
        (const uint8_t *)"ordinary-after-cleanup",
        sizeof("ordinary-after-cleanup") - 1u,
        &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    platform_teardown(&env);

    /* Foundation COMMIT_UNKNOWN retains the arm and performs no cleanup. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x5353535353535353)));
    REQUIRE(env_register_mfdt(&env, 0xc3u, 1u));
    (void)memset(&fault, 0, sizeof(fault));
    fault.storage = env.storage_fixture;
    fault.hook_name = "admission.before_full_commit";
    fault.status = NINLIL_STORAGE_COMMIT_UNKNOWN;
    env.runtime->private_transition_hook = mfdt_submit_fault_hook;
    env.runtime->private_transition_hook_user = &fault;
    tx_before = count_storage_tx_markers(env.storage_fixture);
    commit_calls_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    status = submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem_foundation_cu,
        sizeof(idem_foundation_cu) - 1u,
        &result);
    REQUIRE(fault.fired == 1u);
    REQUIRE(status == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(result.reason == NINLIL_REASON_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);
    REQUIRE(env.runtime->transaction_count == 0u);
    REQUIRE(env.runtime->services[0].quota_inflight == 0u);
    REQUIRE(mfdt_active_count_is(env.runtime, 1u));
    REQUIRE(env.runtime->commit_unknown_fence == 1u);
    REQUIRE(ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls_before + 2u);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND) == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env.runtime = NULL;
    platform_teardown(&env);

    /* Definite cleanup failure returns its status and fences the orphan arm. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x5454545454545454)));
    REQUIRE(env_register_mfdt(&env, 0xc4u, 1u));
    (void)memset(&fault, 0, sizeof(fault));
    fault.storage = env.storage_fixture;
    fault.hook_name = "admission.before_full_commit";
    fault.status = NINLIL_STORAGE_IO_ERROR;
    fault.second_hook_name = "admission.after_full_commit";
    fault.second_status = NINLIL_STORAGE_IO_ERROR;
    env.runtime->private_transition_hook = mfdt_submit_fault_hook;
    env.runtime->private_transition_hook_user = &fault;
    tx_before = count_storage_tx_markers(env.storage_fixture);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    status = submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem_cleanup_failure,
        sizeof(idem_cleanup_failure) - 1u,
        &result);
    REQUIRE(fault.fired == 1u && fault.second_fired == 1u);
    REQUIRE(status == NINLIL_E_STORAGE);
    REQUIRE(result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);
    REQUIRE(env.runtime->transaction_count == 0u);
    REQUIRE(env.runtime->services[0].quota_inflight == 0u);
    REQUIRE(mfdt_active_count_is(env.runtime, 1u));
    REQUIRE(env.runtime->commit_unknown_fence == 1u);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND) == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env.runtime = NULL;
    platform_teardown(&env);

    /* Cleanup COMMIT_UNKNOWN never reports a clean definite failure. */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x5555555555555555)));
    REQUIRE(env_register_mfdt(&env, 0xc5u, 1u));
    (void)memset(&fault, 0, sizeof(fault));
    fault.storage = env.storage_fixture;
    fault.hook_name = "admission.before_full_commit";
    fault.status = NINLIL_STORAGE_IO_ERROR;
    fault.second_hook_name = "admission.after_full_commit";
    fault.second_status = NINLIL_STORAGE_COMMIT_UNKNOWN;
    env.runtime->private_transition_hook = mfdt_submit_fault_hook;
    env.runtime->private_transition_hook_user = &fault;
    tx_before = count_storage_tx_markers(env.storage_fixture);
    commit_calls_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    status = submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem_cleanup_cu,
        sizeof(idem_cleanup_cu) - 1u,
        &result);
    REQUIRE(fault.fired == 1u);
    REQUIRE(fault.second_fired == 1u);
    REQUIRE(status == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(result.reason == NINLIL_REASON_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == tx_before);
    REQUIRE(env.runtime->transaction_count == 0u);
    REQUIRE(env.runtime->services[0].quota_inflight == 0u);
    REQUIRE(mfdt_active_count_is(env.runtime, 1u));
    REQUIRE(env.runtime->commit_unknown_fence == 1u);
    REQUIRE(ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls_before + 3u);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND) == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env.runtime = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_attempt_entropy_partial_then_success(void)
{
    static const uint8_t idem[] = "mfdt-attempt-partial-success";
    cap_env_t env;
    mfdt_entropy_fault_t fault;
    ninlil_submission_result_t result;
    ninlil_rt_transaction_slot_t *transaction;
    const ninlil_test_entropy_trace_record_t *partial_trace;
    const ninlil_test_entropy_trace_record_t *success_trace;
    uint64_t entropy_calls_before;
    size_t entropy_trace_before;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x5353535353535353)));
    REQUIRE(env_register_mfdt(&env, 0xc3u, 1u));

    (void)memset(&fault, 0, sizeof(fault));
    fault.entropy = env.entropy;
    fault.action = NINLIL_TEST_ENTROPY_ACTION_PARTIAL;
    fault.partial_prefix_length = 8u;
    fault.remaining_count = 1u;
    env.runtime->private_transition_hook = mfdt_entropy_fault_hook;
    env.runtime->private_transition_hook_user = &fault;
    entropy_calls_before = ninlil_test_entropy_call_count(env.entropy);
    entropy_trace_before = ninlil_test_entropy_trace_count(env.entropy);

    REQUIRE(submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem,
        sizeof(idem) - 1u,
        &result) == NINLIL_OK);
    REQUIRE(fault.fired == 1u);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy)
        == entropy_calls_before + 3u);
    REQUIRE(ninlil_test_entropy_trace_count(env.entropy)
        == entropy_trace_before + 3u);
    partial_trace = ninlil_test_entropy_trace_at(
        env.entropy, entropy_trace_before + 1u);
    success_trace = ninlil_test_entropy_trace_at(
        env.entropy, entropy_trace_before + 2u);
    REQUIRE(partial_trace != NULL);
    REQUIRE(partial_trace->action == NINLIL_TEST_ENTROPY_ACTION_PARTIAL);
    REQUIRE(partial_trace->status == NINLIL_PORT_TEMPORARY_FAILURE);
    REQUIRE(partial_trace->requested_length == 16u);
    REQUIRE(partial_trace->bytes_written == 8u);
    REQUIRE(success_trace != NULL);
    REQUIRE(success_trace->action == NINLIL_TEST_ENTROPY_ACTION_NONE);
    REQUIRE(success_trace->status == NINLIL_PORT_OK);
    REQUIRE(success_trace->requested_length == 16u);
    REQUIRE(success_trace->bytes_written == 16u);

    transaction = ninlil_rt_find_transaction(
        env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->attempt_prepared == 1u);
    REQUIRE(transaction->attempt_count == 1u);
    REQUIRE(id_is_nonzero(&transaction->attempt_id));
    REQUIRE(memcmp(
        transaction->attempt_id.bytes,
        transaction->bound_targets[0].active_attempt_id.bytes,
        sizeof(transaction->attempt_id.bytes)) == 0);
    REQUIRE(mfdt_active_count_is(env.runtime, 1u));

    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_attempt_entropy_four_draw_exhaustion(void)
{
    static const uint8_t idem[] = "mfdt-attempt-four-draw-exhaustion";
    cap_env_t env;
    mfdt_entropy_fault_t fault;
    ninlil_submission_result_t result;
    ninlil_status_t status;
    uint64_t entropy_calls_before;
    size_t entropy_trace_before;
    uint64_t commit_calls_before;
    uint64_t put_calls_before;
    uint64_t erase_calls_before;
    uint64_t send_calls_before;
    uint64_t acquire_calls_before;
    uint64_t callback_calls_before;
    uint64_t transaction_count_before;
    uint64_t nonterminal_count_before;
    uint64_t quota_inflight_before;
    uint32_t markers_before;
    uint32_t draw;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env.config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env.config.runtime_id, 0x30u);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    REQUIRE(enable_mfdt_owner(
        env.runtime, UINT64_C(0x5454545454545454)));
    REQUIRE(env_register_mfdt(&env, 0xc4u, 1u));

    (void)memset(&fault, 0, sizeof(fault));
    fault.entropy = env.entropy;
    fault.action = NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO;
    fault.remaining_count = 4u;
    env.runtime->private_transition_hook = mfdt_entropy_fault_hook;
    env.runtime->private_transition_hook_user = &fault;
    entropy_calls_before = ninlil_test_entropy_call_count(env.entropy);
    entropy_trace_before = ninlil_test_entropy_trace_count(env.entropy);
    markers_before = count_storage_tx_markers(env.storage_fixture);
    commit_calls_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    put_calls_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    erase_calls_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
    send_calls_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquire_calls_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    callback_calls_before =
        env.runtime->metrics.application_callback_invocations;
    transaction_count_before = env.runtime->transaction_count;
    nonterminal_count_before = env.runtime->nonterminal_transaction_count;
    quota_inflight_before = env.runtime->services[0].quota_inflight;

    status = submit_with_payload_status(
        &env,
        927u,
        5000u,
        0u,
        idem,
        sizeof(idem) - 1u,
        &result);
    REQUIRE(fault.fired == 1u);
    REQUIRE(status == NINLIL_E_ENTROPY);
    REQUIRE(result.kind != NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy)
        == entropy_calls_before + 5u);
    REQUIRE(ninlil_test_entropy_trace_count(env.entropy)
        == entropy_trace_before + 5u);
    for (draw = 0u; draw < 4u; ++draw) {
        const ninlil_test_entropy_trace_record_t *trace =
            ninlil_test_entropy_trace_at(
                env.entropy, entropy_trace_before + 1u + draw);

        REQUIRE(trace != NULL);
        REQUIRE(trace->action == NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO);
        REQUIRE(trace->status == NINLIL_PORT_OK);
        REQUIRE(trace->requested_length == 16u);
        REQUIRE(trace->bytes_written == 16u);
    }
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commit_calls_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == put_calls_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE)
        == erase_calls_before);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == markers_before);
    REQUIRE(env.runtime->transaction_count == transaction_count_before);
    REQUIRE(env.runtime->nonterminal_transaction_count
        == nonterminal_count_before);
    REQUIRE(env.runtime->services[0].quota_inflight
        == quota_inflight_before);
    REQUIRE(mfdt_active_count_is(env.runtime, 0u));
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == send_calls_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquire_calls_before);
    REQUIRE(env.runtime->metrics.application_callback_invocations
        == callback_calls_before);
    REQUIRE(env.runtime->commit_unknown_fence == 0u);

    env.runtime->private_transition_hook = NULL;
    env.runtime->private_transition_hook_user = NULL;
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_multi_target_admission_success(void)
{
    static const char *const keys[3] = {
        "mfdt-multi-two", "mfdt-multi-three", "mfdt-multi-four"
    };
    const uint64_t cookie = UINT64_C(0x7171717171717171);
    uint32_t target_count;

    for (target_count = 2u; target_count <= 4u; ++target_count) {
        cap_env_t env;
        ninlil_concrete_target_t targets[4];
        ninlil_id128_t canonical_runtime_ids[4];
        ninlil_id128_t attempt_ids[4];
        uint8_t transfer_ids[4][16];
        ninlil_submission_result_t result;
        ninlil_rt_transaction_slot_t *transaction;
        uint64_t entropy_before;
        uint64_t commits_before;
        uint64_t sends_before;
        uint64_t acquires_before;
        uint64_t callbacks_before;
        uint32_t markers_before;
        uint32_t index;

        REQUIRE(prepare_mfdt_multi_env(
            &env, (uint8_t)(0xe0u + target_count), cookie));
        for (index = 0u; index < target_count; ++index) {
            fill_mfdt_roster_target(
                &env,
                &targets[index],
                (uint8_t)(0x50u + (target_count - index) * 0x10u),
                (uint8_t)(0x80u + index));
        }
        entropy_before = ninlil_test_entropy_call_count(env.entropy);
        commits_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        sends_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
        acquires_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
        callbacks_before =
            env.runtime->metrics.application_callback_invocations;
        markers_before = count_storage_tx_markers(env.storage_fixture);

        REQUIRE(submit_mfdt_roster(
                    &env,
                    targets,
                    target_count,
                    (const uint8_t *)keys[target_count - 2u],
                    (uint32_t)strlen(keys[target_count - 2u]),
                    &result) == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        REQUIRE(ninlil_test_entropy_call_count(env.entropy)
            == entropy_before + 1u + target_count);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commits_before + target_count + 1u);
        REQUIRE(count_storage_tx_markers(env.storage_fixture)
            == markers_before + 1u);
        REQUIRE(mfdt_active_count_is(env.runtime, target_count));
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
            == acquires_before);
        REQUIRE(env.runtime->metrics.application_callback_invocations
            == callbacks_before);

        transaction = ninlil_rt_find_transaction(
            env.runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->bearer_route
            == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
        REQUIRE(transaction->bound_target_count == target_count);
        REQUIRE(transaction->attempt_count == target_count);
        REQUIRE(transaction->cumulative_attempts == target_count);
        REQUIRE(transaction->active_target_index == 0u);
        REQUIRE(memcmp(
            transaction->attempt_id.bytes,
            transaction->bound_targets[0].active_attempt_id.bytes,
            16u) == 0);
        for (index = 0u; index < target_count; ++index) {
            uint32_t prior;

            REQUIRE(transaction->bound_targets[index].target
                .target_runtime_id.bytes[0]
                == (uint8_t)(0x60u + index * 0x10u));
            REQUIRE(transaction->attempt_target_indices[index] == index);
            REQUIRE(transaction->bound_targets[index].attempt_prepared == 1u);
            REQUIRE(transaction->bound_targets[index].mfdt_target_ordinal
                == index);
            REQUIRE(memcmp(
                transaction->attempt_ids[index].bytes,
                transaction->bound_targets[index].active_attempt_id.bytes,
                16u) == 0);
            for (prior = 0u; prior < index; ++prior) {
                REQUIRE(memcmp(
                    transaction->attempt_ids[prior].bytes,
                    transaction->attempt_ids[index].bytes,
                    16u) != 0);
            }
            canonical_runtime_ids[index] =
                transaction->bound_targets[index].target.target_runtime_id;
            attempt_ids[index] =
                transaction->bound_targets[index].active_attempt_id;
            (void)memcpy(
                transfer_ids[index],
                transaction->bound_targets[index].mfdt_transfer_id,
                16u);
        }
        REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
        env.runtime = NULL;
        env.service = NULL;
        for (index = 0u; index < target_count; ++index) {
            REQUIRE(mfdt_sidecar_matches_foundation(
                &env,
                &result.transaction_id,
                &canonical_runtime_ids[index],
                &attempt_ids[index],
                index,
                transfer_ids[index]));
        }
        platform_teardown(&env);
    }
    return 0;
}

static int test_mfdt_duplicate_runtime_rejected_before_entropy(void)
{
    static const uint8_t key[] = "mfdt-duplicate-runtime";
    cap_env_t env;
    ninlil_concrete_target_t targets[2];
    ninlil_submission_result_t result;
    uint64_t entropy_before;
    uint64_t commits_before;
    uint64_t puts_before;
    uint64_t erases_before;
    uint64_t sends_before;
    uint64_t acquires_before;
    uint64_t callbacks_before;

    REQUIRE(prepare_mfdt_multi_env(
        &env, 0xe5u, UINT64_C(0x7272727272727272)));
    fill_mfdt_roster_target(&env, &targets[0], 0x60u, 0x81u);
    fill_mfdt_roster_target(&env, &targets[1], 0x60u, 0x82u);
    entropy_before = ninlil_test_entropy_call_count(env.entropy);
    commits_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    puts_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    erases_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    callbacks_before = env.runtime->metrics.application_callback_invocations;

    REQUIRE(submit_mfdt_roster(
                &env,
                targets,
                2u,
                key,
                sizeof(key) - 1u,
                &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_TARGET_COUNT_UNSUPPORTED);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy) == entropy_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commits_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == puts_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE)
        == erases_before);
    REQUIRE(mfdt_active_count_is(env.runtime, 0u));
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    REQUIRE(env.runtime->metrics.application_callback_invocations
        == callbacks_before);
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_multi_target_candidate_collision_and_exhaustion(void)
{
    static const uint8_t collision_key[] = "mfdt-multi-collision";
    static const uint8_t exhaustion_key[] = "mfdt-multi-exhaustion";
    const uint64_t cookie = UINT64_C(0x7373737373737373);
    cap_env_t env;
    ninlil_concrete_target_t targets[2];
    ninlil_submission_result_t result;
    ninlil_rt_transaction_slot_t *transaction;
    mfdt_collision_fault_t collision;
    mfdt_entropy_fault_t exhaustion;
    uint64_t entropy_before;
    uint64_t commits_before;
    uint64_t sends_before;
    uint64_t acquires_before;
    uint64_t callbacks_before;
    uint32_t markers_before;

    REQUIRE(prepare_mfdt_multi_env(&env, 0xe6u, cookie));
    fill_mfdt_roster_target(&env, &targets[0], 0x70u, 0x81u);
    fill_mfdt_roster_target(&env, &targets[1], 0x60u, 0x82u);
    (void)memset(&collision, 0, sizeof(collision));
    collision.entropy = env.entropy;
    env.runtime->private_transition_hook = mfdt_collision_fault_hook;
    env.runtime->private_transition_hook_user = &collision;
    entropy_before = ninlil_test_entropy_call_count(env.entropy);
    REQUIRE(submit_mfdt_roster(
                &env,
                targets,
                2u,
                collision_key,
                sizeof(collision_key) - 1u,
                &result) == NINLIL_OK);
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(collision.fired == 1u);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy)
        == entropy_before + 4u);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL && transaction->attempt_count == 2u);
    REQUIRE(memcmp(
        transaction->attempt_ids[0].bytes,
        transaction->attempt_ids[1].bytes,
        16u) != 0);
    platform_teardown(&env);

    REQUIRE(prepare_mfdt_multi_env(&env, 0xe7u, cookie));
    fill_mfdt_roster_target(&env, &targets[0], 0x60u, 0x81u);
    fill_mfdt_roster_target(&env, &targets[1], 0x70u, 0x82u);
    (void)memset(&exhaustion, 0, sizeof(exhaustion));
    exhaustion.entropy = env.entropy;
    exhaustion.action = NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO;
    exhaustion.remaining_count = 4u;
    exhaustion.match_skip = 1u;
    env.runtime->private_transition_hook = mfdt_entropy_fault_hook;
    env.runtime->private_transition_hook_user = &exhaustion;
    entropy_before = ninlil_test_entropy_call_count(env.entropy);
    commits_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    callbacks_before = env.runtime->metrics.application_callback_invocations;
    markers_before = count_storage_tx_markers(env.storage_fixture);
    REQUIRE(submit_mfdt_roster(
                &env,
                targets,
                2u,
                exhaustion_key,
                sizeof(exhaustion_key) - 1u,
                &result) == NINLIL_E_ENTROPY);
    REQUIRE(exhaustion.fired == 1u);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy)
        == entropy_before + 6u);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commits_before + 2u);
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == markers_before);
    REQUIRE(mfdt_active_count_is(env.runtime, 0u));
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    REQUIRE(env.runtime->metrics.application_callback_invocations
        == callbacks_before);
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_multi_target_arm_and_foundation_cuts(void)
{
    static const char *const keys[5] = {
        "mfdt-first-arm-cu", "mfdt-arm-io", "mfdt-arm-cu",
        "mfdt-foundation-io", "mfdt-foundation-cu"
    };
    static const ninlil_status_t expected_status[5] = {
        NINLIL_E_STORAGE_COMMIT_UNKNOWN,
        NINLIL_E_STORAGE,
        NINLIL_E_STORAGE_COMMIT_UNKNOWN,
        NINLIL_E_STORAGE,
        NINLIL_E_STORAGE_COMMIT_UNKNOWN
    };
    static const uint32_t expected_active[5] = {0u, 0u, 1u, 0u, 3u};
    static const uint64_t expected_commits[5] = {1u, 3u, 2u, 7u, 4u};
    static const uint64_t expected_entropy[5] = {2u, 3u, 3u, 4u, 4u};
    const uint64_t cookie = UINT64_C(0x7474747474747474);
    uint32_t variant;

    for (variant = 0u; variant < 5u; ++variant) {
        cap_env_t env;
        ninlil_concrete_target_t targets[3];
        ninlil_submission_result_t result;
        mfdt_submit_fault_t fault;
        uint64_t commits_before;
        uint64_t entropy_before;
        uint64_t sends_before;
        uint64_t acquires_before;
        uint64_t callbacks_before;
        uint32_t markers_before;
        uint32_t index;

        REQUIRE(prepare_mfdt_multi_env(
            &env, (uint8_t)(0xe8u + variant), cookie));
        for (index = 0u; index < 3u; ++index) {
            fill_mfdt_roster_target(
                &env,
                &targets[index],
                (uint8_t)(0x60u + index * 0x10u),
                (uint8_t)(0x81u + index));
        }
        (void)memset(&fault, 0, sizeof(fault));
        fault.storage = env.storage_fixture;
        if (variant < 3u) {
            fault.hook_name = "admission.before_mfdt_sender_open";
            fault.match_skip = variant == 0u ? 0u : 1u;
        } else {
            fault.hook_name = "admission.before_full_commit";
        }
        fault.status = (variant == 0u || variant == 2u || variant == 4u)
            ? NINLIL_STORAGE_COMMIT_UNKNOWN
            : NINLIL_STORAGE_IO_ERROR;
        env.runtime->private_transition_hook = mfdt_submit_fault_hook;
        env.runtime->private_transition_hook_user = &fault;
        commits_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        entropy_before = ninlil_test_entropy_call_count(env.entropy);
        sends_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
        acquires_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
        callbacks_before =
            env.runtime->metrics.application_callback_invocations;
        markers_before = count_storage_tx_markers(env.storage_fixture);

        REQUIRE(submit_mfdt_roster(
                    &env,
                    targets,
                    3u,
                    (const uint8_t *)keys[variant],
                    (uint32_t)strlen(keys[variant]),
                    &result) == expected_status[variant]);
        REQUIRE(fault.fired == 1u);
        REQUIRE(count_storage_tx_markers(env.storage_fixture)
            == markers_before);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commits_before + expected_commits[variant]);
        REQUIRE(ninlil_test_entropy_call_count(env.entropy)
            == entropy_before + expected_entropy[variant]);
        REQUIRE(mfdt_active_count_is(
            env.runtime, expected_active[variant]));
        REQUIRE(env.runtime->commit_unknown_fence
            == ((variant == 0u || variant == 2u || variant == 4u)
                ? 1u : 0u));
        if (expected_status[variant] == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
            REQUIRE(result.kind == NINLIL_SUBMISSION_INVALID);
            REQUIRE(result.reason == NINLIL_REASON_STORAGE_COMMIT_UNKNOWN);
            REQUIRE(result.retry_guidance == NINLIL_RETRY_SAME_AFTER);
        }
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
            == acquires_before);
        REQUIRE(env.runtime->metrics.application_callback_invocations
            == callbacks_before);
        env.runtime->private_transition_hook = NULL;
        env.runtime->private_transition_hook_user = NULL;
        if (env.runtime->commit_unknown_fence != 0u) {
            (void)ninlil_runtime_destroy(env.runtime);
            env.runtime = NULL;
            env.service = NULL;
        }
        platform_teardown(&env);
    }
    return 0;
}

static int test_mfdt_multi_target_cleanup_failure_cuts(void)
{
    static const char *const keys[2] = {
        "mfdt-cleanup-io", "mfdt-cleanup-cu"
    };
    const uint64_t cookie = UINT64_C(0x7575757575757575);
    uint32_t variant;

    for (variant = 0u; variant < 2u; ++variant) {
        cap_env_t env;
        ninlil_concrete_target_t targets[2];
        ninlil_submission_result_t result;
        mfdt_submit_fault_t fault;
        uint64_t commits_before;
        uint64_t entropy_before;
        uint64_t sends_before;
        uint64_t acquires_before;
        uint64_t callbacks_before;
        uint32_t markers_before;

        REQUIRE(prepare_mfdt_multi_env(
            &env, (uint8_t)(0xecu + variant), cookie));
        fill_mfdt_roster_target(&env, &targets[0], 0x60u, 0x81u);
        fill_mfdt_roster_target(&env, &targets[1], 0x70u, 0x82u);
        (void)memset(&fault, 0, sizeof(fault));
        fault.storage = env.storage_fixture;
        fault.hook_name = "admission.before_full_commit";
        fault.status = NINLIL_STORAGE_IO_ERROR;
        fault.second_hook_name = "admission.after_full_commit";
        fault.second_status = variant == 0u
            ? NINLIL_STORAGE_IO_ERROR
            : NINLIL_STORAGE_COMMIT_UNKNOWN;
        env.runtime->private_transition_hook = mfdt_submit_fault_hook;
        env.runtime->private_transition_hook_user = &fault;
        commits_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        entropy_before = ninlil_test_entropy_call_count(env.entropy);
        sends_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
        acquires_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
        callbacks_before =
            env.runtime->metrics.application_callback_invocations;
        markers_before = count_storage_tx_markers(env.storage_fixture);

        REQUIRE(submit_mfdt_roster(
                    &env,
                    targets,
                    2u,
                    (const uint8_t *)keys[variant],
                    (uint32_t)strlen(keys[variant]),
                    &result)
            == (variant == 0u
                    ? NINLIL_E_STORAGE
                    : NINLIL_E_STORAGE_COMMIT_UNKNOWN));
        REQUIRE(fault.fired == 1u && fault.second_fired == 1u);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commits_before + 4u);
        REQUIRE(ninlil_test_entropy_call_count(env.entropy)
            == entropy_before + 3u);
        REQUIRE(count_storage_tx_markers(env.storage_fixture)
            == markers_before);
        REQUIRE(mfdt_active_count_is(env.runtime, 2u));
        REQUIRE(env.runtime->commit_unknown_fence == 1u);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
            == acquires_before);
        REQUIRE(env.runtime->metrics.application_callback_invocations
            == callbacks_before);
        env.runtime->private_transition_hook = NULL;
        env.runtime->private_transition_hook_user = NULL;
        (void)ninlil_runtime_destroy(env.runtime);
        env.runtime = NULL;
        env.service = NULL;
        platform_teardown(&env);
    }
    return 0;
}

typedef struct mfdt_restart_identity {
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    uint8_t transfer_id[16];
} mfdt_restart_identity_t;

static int copy_mfdt_open_body(
    const ninlil_bearer_message_t *message,
    uint8_t out[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint16_t *length_out)
{
    const uint8_t *body = NULL;
    uint8_t type = 0u;
    uint32_t request_id = 0u;
    uint32_t generation = 0u;
    uint64_t cookie = 0u;
    uint16_t body_length = 0u;

    if (message == NULL || out == NULL || length_out == NULL ||
        ninlil_mfdt_v1_ncl1_decode(
            message->payload.data,
            message->payload.length,
            NINLIL_MFDT_V1_NCG1_DATA,
            &type,
            &request_id,
            &generation,
            &cookie,
            &body,
            &body_length) != NINLIL_MFDT_V1_OK ||
        type != NINLIL_MFDT_V1_MSG_OPEN || body == NULL ||
        body_length > NINLIL_MFDT_V1_OPEN_BODY_MAX) {
        return 0;
    }
    (void)request_id;
    (void)generation;
    (void)cookie;
    (void)memcpy(out, body, body_length);
    *length_out = body_length;
    return 1;
}

static int prepare_mfdt_restart_env(
    cap_env_t *env,
    uint8_t application_tag,
    uint64_t cookie)
{
    (void)memset(env, 0, sizeof(*env));
    if (!platform_init(env)) {
        return 0;
    }
    env->config = config_controller(4u);
    env->config.limits.max_logical_payload_bytes =
        NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    env->config.limits.max_durable_outbox_payload_bytes = 262144u;
    set_id(&env->config.runtime_id, 0x30u);
    return ninlil_runtime_create(
               &env->config, &env->platform, &env->runtime) == NINLIL_OK &&
        enable_mfdt_owner(env->runtime, cookie) &&
        env_register_mfdt(env, application_tag, 1u);
}

static int run_mfdt_exact_cold_restart_case(
    uint8_t transfer_count,
    int compare_open)
{
    static const char *const idempotency_keys[4] = {
        "mfdt-cold-exact-1",
        "mfdt-cold-exact-2",
        "mfdt-cold-exact-3",
        "mfdt-cold-exact-4"
    };
    const uint64_t cookie = UINT64_C(0x6262626262626262);
    cap_env_t env;
    mfdt_restart_identity_t identities[4];
    ninlil_submission_result_t result;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_mfdt_v1_session_t session;
    ninlil_step_result_t step_result;
    ninlil_bearer_message_t received;
    ninlil_bearer_handle_t peer = NULL;
    uint8_t open_before[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t open_after[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_before_length = 0u;
    uint16_t open_after_length = 0u;
    uint64_t entropy_before;
    uint64_t sends_before;
    uint64_t acquires_before;
    uint8_t index;

    REQUIRE(transfer_count == 1u || transfer_count == 4u);
    REQUIRE(prepare_mfdt_restart_env(&env, 0xd1u, cookie));
    (void)memset(identities, 0, sizeof(identities));
    for (index = 0u; index < transfer_count; ++index) {
        REQUIRE(submit_with_payload(
            &env,
            index == 0u ? 927u : 927u + index,
            5000u,
            0u,
            (const uint8_t *)idempotency_keys[index],
            strlen(idempotency_keys[index]),
            &result));
        REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        identities[index].transaction_id = result.transaction_id;
        identities[index].attempt_id = transaction->attempt_id;
        (void)memcpy(
            identities[index].transfer_id,
            transaction->bound_targets[0].mfdt_transfer_id,
            16u);
    }
    REQUIRE(mfdt_active_count_is(env.runtime, transfer_count));

    if (compare_open != 0) {
        REQUIRE(env.platform.bearer->open(
                    env.platform.bearer->user,
                    &env.target.target_runtime_id,
                    NINLIL_ROLE_ENDPOINT,
                    &peer) == NINLIL_BEARER_OK);
        REQUIRE(step_runtime(&env, 1u, &step_result));
        REQUIRE(step_result.bearer_sends == 1u);
        (void)memset(&received, 0, sizeof(received));
        set_header(
            &received.abi_version,
            &received.struct_size,
            sizeof(received));
        REQUIRE(env.platform.bearer->receive_next(
                    env.platform.bearer->user,
                    peer,
                    &received) == NINLIL_BEARER_OK);
        REQUIRE(received.kind == NINLIL_BEARER_MESSAGE_APPLICATION);
        REQUIRE(received.service.family == NINLIL_FAMILY_TRANSFER_RESERVED);
        REQUIRE(copy_mfdt_open_body(
            &received, open_before, &open_before_length));
        env.platform.bearer->release_received(
            env.platform.bearer->user, peer, &received);
        env.platform.bearer->close(env.platform.bearer->user, peer);
        peer = NULL;
    }

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);

    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    entropy_before = ninlil_test_entropy_call_count(env.entropy);
    REQUIRE(configure_mfdt_owner(env.runtime, 1u, cookie));
    REQUIRE(mfdt_active_count_is(env.runtime, transfer_count));
    REQUIRE(ninlil_test_entropy_call_count(env.entropy) == entropy_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    REQUIRE(env.runtime->metrics.application_callback_invocations == 0u);
    for (index = 0u; index < transfer_count; ++index) {
        transaction = ninlil_rt_find_transaction(
            env.runtime, &identities[index].transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(memcmp(
            transaction->attempt_id.bytes,
            identities[index].attempt_id.bytes,
            16u) == 0);
        REQUIRE(memcmp(
            transaction->bound_targets[0].mfdt_transfer_id,
            identities[index].transfer_id,
            16u) == 0);
        REQUIRE(transaction->attempt_count == 1u);
        REQUIRE(transaction->attempt_prepared == 1u);
    }

    if (compare_open != 0) {
        REQUIRE(make_admitted_mfdt_session(
            env.runtime, 1u, cookie, 0x10u, &session));
        REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                    env.runtime, &session) == NINLIL_OK);
        REQUIRE(env.platform.bearer->open(
                    env.platform.bearer->user,
                    &env.target.target_runtime_id,
                    NINLIL_ROLE_ENDPOINT,
                    &peer) == NINLIL_BEARER_OK);
        REQUIRE(step_runtime(&env, 1u, &step_result));
        REQUIRE(step_result.bearer_sends == 1u);
        (void)memset(&received, 0, sizeof(received));
        set_header(
            &received.abi_version,
            &received.struct_size,
            sizeof(received));
        REQUIRE(env.platform.bearer->receive_next(
                    env.platform.bearer->user,
                    peer,
                    &received) == NINLIL_BEARER_OK);
        REQUIRE(copy_mfdt_open_body(
            &received, open_after, &open_after_length));
        REQUIRE(open_after_length == open_before_length);
        REQUIRE(memcmp(
            open_after, open_before, open_before_length) == 0);
        env.platform.bearer->release_received(
            env.platform.bearer->user, peer, &received);
        env.platform.bearer->close(env.platform.bearer->user, peer);
        peer = NULL;
    }
    platform_teardown(&env);
    return 0;
}

static int test_mfdt_exact_one_cold_restart_reconciliation(void)
{
    REQUIRE(run_mfdt_exact_cold_restart_case(1u, 1) == 0);
    REQUIRE(run_mfdt_exact_cold_restart_case(4u, 0) == 0);
    return 0;
}

static int seed_mfdt_multi_restart(
    cap_env_t *env,
    uint64_t cookie,
    uint8_t application_tag,
    const uint8_t *key,
    uint32_t key_length,
    uint32_t target_count,
    ninlil_submission_result_t *out_result)
{
    ninlil_concrete_target_t targets[4];
    uint32_t index;

    if (!prepare_mfdt_multi_env(env, application_tag, cookie)) {
        return 0;
    }
    for (index = 0u; index < target_count; ++index) {
        fill_mfdt_roster_target(
            env,
            &targets[index],
            (uint8_t)(0x60u + index * 0x10u),
            (uint8_t)(0x81u + index));
    }
    return submit_mfdt_roster(
               env,
               targets,
               target_count,
               key,
               key_length,
               out_result) == NINLIL_OK &&
        out_result->kind == NINLIL_SUBMISSION_ADMITTED_READY;
}

static int test_mfdt_multi_target_cold_restart_reconciliation(void)
{
    static const uint8_t exact_key[] = "mfdt-multi-cold-exact";
    static const char *const variant_keys[4] = {
        "mfdt-multi-cold-missing",
        "mfdt-multi-cold-mismatch",
        "mfdt-multi-cold-extra",
        "mfdt-multi-cold-noncanonical-transfer"
    };
    const uint64_t cookie = UINT64_C(0x7676767676767676);
    cap_env_t env;
    ninlil_submission_result_t result;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_id128_t attempts[4];
    uint8_t transfers[4][16];
    uint8_t noncanonical_transfer[16];
    uint64_t entropy_before;
    uint64_t commits_before;
    uint64_t puts_before;
    uint64_t erases_before;
    uint64_t sends_before;
    uint64_t acquires_before;
    uint32_t index;
    uint32_t variant;

    REQUIRE(seed_mfdt_multi_restart(
        &env,
        cookie,
        0xeeu,
        exact_key,
        sizeof(exact_key) - 1u,
        4u,
        &result));
    transaction = ninlil_rt_find_transaction(
        env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL);
    for (index = 0u; index < 4u; ++index) {
        attempts[index] = transaction->bound_targets[index].active_attempt_id;
        (void)memcpy(
            transfers[index],
            transaction->bound_targets[index].mfdt_transfer_id,
            16u);
    }
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    entropy_before = ninlil_test_entropy_call_count(env.entropy);
    commits_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
    puts_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
    erases_before = ninlil_test_storage_call_count(
        env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    REQUIRE(configure_mfdt_owner(env.runtime, 1u, cookie));
    REQUIRE(mfdt_active_count_is(env.runtime, 4u));
    REQUIRE(ninlil_test_entropy_call_count(env.entropy) == entropy_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
        == commits_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
        == puts_before);
    REQUIRE(ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE)
        == erases_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    REQUIRE(env.runtime->metrics.application_callback_invocations == 0u);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL && transaction->attempt_count == 4u);
    for (index = 0u; index < 4u; ++index) {
        REQUIRE(memcmp(
            transaction->bound_targets[index].active_attempt_id.bytes,
            attempts[index].bytes,
            16u) == 0);
        REQUIRE(memcmp(
            transaction->bound_targets[index].mfdt_transfer_id,
            transfers[index],
            16u) == 0);
    }
    platform_teardown(&env);

    for (variant = 0u; variant < 4u; ++variant) {
        REQUIRE(seed_mfdt_multi_restart(
            &env,
            cookie,
            (uint8_t)(0xf0u + variant),
            (const uint8_t *)variant_keys[variant],
            (uint32_t)strlen(variant_keys[variant]),
            3u,
            &result));
        transaction = ninlil_rt_find_transaction(
            env.runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        for (index = 0u; index < 3u; ++index) {
            (void)memcpy(
                transfers[index],
                transaction->bound_targets[index].mfdt_transfer_id,
                16u);
        }
        REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
        env.runtime = NULL;
        env.service = NULL;
        if (variant == 0u) {
            REQUIRE(raw_mfdt_erase_pair(&env, transfers[1]));
        } else if (variant == 3u) {
            (void)memcpy(
                noncanonical_transfer, transfers[1], 16u);
            noncanonical_transfer[0] ^= 0x80u;
            for (index = 0u; index < 3u; ++index) {
                REQUIRE(memcmp(
                    noncanonical_transfer, transfers[index], 16u) != 0);
            }
            REQUIRE(raw_mfdt_rekey_sender_pair_noncanonical(
                &env, transfers[1], noncanonical_transfer));
        }
        REQUIRE(ninlil_runtime_create(
                    &env.config, &env.platform, &env.runtime) == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        if (variant == 1u) {
            transaction->bound_targets[1].active_attempt_id.bytes[0] ^= 1u;
            transaction->attempt_ids[1] =
                transaction->bound_targets[1].active_attempt_id;
        } else if (variant == 2u) {
            transaction->bound_target_count = 2u;
            transaction->attempt_count = 2u;
            transaction->cumulative_attempts = 2u;
        } else if (variant == 3u) {
            (void)memcpy(
                transaction->bound_targets[1].mfdt_transfer_id,
                noncanonical_transfer,
                16u);
        }
        commits_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        puts_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        erases_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
        entropy_before = ninlil_test_entropy_call_count(env.entropy);
        sends_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
        acquires_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
        REQUIRE(configure_mfdt_owner_status(env.runtime, 1u, cookie)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(env.runtime->commit_unknown_fence == 1u);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commits_before);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
            == puts_before);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE)
            == erases_before);
        REQUIRE(ninlil_test_entropy_call_count(env.entropy)
            == entropy_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
            == acquires_before);
        REQUIRE(env.runtime->metrics.application_callback_invocations == 0u);
        REQUIRE(raw_mfdt_row_present(&env, "NM3S", transfers[0]));
        REQUIRE(raw_mfdt_row_present(&env, "NRC1", transfers[0]));
        platform_teardown(&env);
    }
    return 0;
}

static int seed_mfdt_fresh_orphan(
    cap_env_t *env,
    uint64_t cookie,
    uint8_t transfer_id_out[16])
{
    static const uint8_t idem[] = "mfdt-cold-orphan";
    mfdt_submit_fault_t fault;
    ninlil_submission_result_t result;

    REQUIRE(prepare_mfdt_restart_env(env, 0xd2u, cookie));
    (void)memset(&fault, 0, sizeof(fault));
    fault.storage = env->storage_fixture;
    fault.hook_name = "admission.before_full_commit";
    fault.status = NINLIL_STORAGE_COMMIT_UNKNOWN;
    fault.commit_unknown_committed = 0u;
    env->runtime->private_transition_hook = mfdt_submit_fault_hook;
    env->runtime->private_transition_hook_user = &fault;
    REQUIRE(submit_with_payload_status(
        env,
        927u,
        5000u,
        0u,
        idem,
        sizeof(idem) - 1u,
        &result) == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(fault.fired == 1u);
    REQUIRE(count_storage_tx_markers(env->storage_fixture) == 0u);
    REQUIRE(mfdt_active_count_is(env->runtime, 1u));
    env->runtime->private_transition_hook = NULL;
    env->runtime->private_transition_hook_user = NULL;
    REQUIRE(ninlil_runtime_destroy(env->runtime)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    env->runtime = NULL;
    env->service = NULL;
    REQUIRE(raw_mfdt_find_single_transfer(
        env, "NM3S", transfer_id_out));
    REQUIRE(raw_mfdt_row_present(env, "NRC1", transfer_id_out));
    return 0;
}

static int test_mfdt_cold_restart_orphan_cleanup(void)
{
    static const struct {
        ninlil_storage_status_t storage_status;
        ninlil_status_t expected_status;
    } failures[] = {
        {NINLIL_STORAGE_IO_ERROR, NINLIL_E_STORAGE},
        {NINLIL_STORAGE_COMMIT_UNKNOWN,
         NINLIL_E_STORAGE_COMMIT_UNKNOWN}
    };
    const uint64_t cookie = UINT64_C(0x6363636363636363);
    cap_env_t env;
    uint8_t transfer_id[16];
    uint64_t entropy_before;
    uint64_t sends_before;
    uint64_t acquires_before;
    uint32_t failure_index;

    REQUIRE(seed_mfdt_fresh_orphan(&env, cookie, transfer_id) == 0);
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    acquires_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime) == NINLIL_OK);
    entropy_before = ninlil_test_entropy_call_count(env.entropy);
    REQUIRE(configure_mfdt_owner(env.runtime, 1u, cookie));
    REQUIRE(mfdt_active_count_is(env.runtime, 0u));
    REQUIRE(env.runtime->metrics.application_callback_invocations == 0u);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(!raw_mfdt_row_present(&env, "NM3S", transfer_id));
    REQUIRE(!raw_mfdt_row_present(&env, "NRC1", transfer_id));
    REQUIRE(count_storage_tx_markers(env.storage_fixture) == 0u);
    REQUIRE(ninlil_test_entropy_call_count(env.entropy) == entropy_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
        == sends_before);
    REQUIRE(ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
        == acquires_before);
    platform_teardown(&env);

    for (failure_index = 0u;
         failure_index < sizeof(failures) / sizeof(failures[0]);
         ++failure_index) {
        REQUIRE(seed_mfdt_fresh_orphan(&env, cookie, transfer_id) == 0);
        REQUIRE(ninlil_runtime_create(
                    &env.config, &env.platform, &env.runtime) == NINLIL_OK);
        if (failures[failure_index].storage_status
            == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            REQUIRE(ninlil_test_storage_fault_enqueue(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                0));
        } else {
            REQUIRE(ninlil_test_storage_fault_next(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                failures[failure_index].storage_status));
        }
        entropy_before = ninlil_test_entropy_call_count(env.entropy);
        sends_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
        acquires_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
        REQUIRE(configure_mfdt_owner_status(env.runtime, 1u, cookie)
            == failures[failure_index].expected_status);
        REQUIRE(env.runtime->commit_unknown_fence == 1u);
        REQUIRE(raw_mfdt_row_present(&env, "NM3S", transfer_id));
        REQUIRE(raw_mfdt_row_present(&env, "NRC1", transfer_id));
        REQUIRE(count_storage_tx_markers(env.storage_fixture) == 0u);
        REQUIRE(ninlil_test_entropy_call_count(env.entropy)
            == entropy_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
            == acquires_before);
        REQUIRE(env.runtime->metrics.application_callback_invocations == 0u);
        platform_teardown(&env);
    }
    return 0;
}

static int test_mfdt_cold_restart_mismatch_and_terminal_fence(void)
{
    static const uint8_t *const idempotency_keys[3] = {
        (const uint8_t *)"mfdt-cold-mismatch",
        (const uint8_t *)"mfdt-cold-terminal",
        (const uint8_t *)"mfdt-cold-non-mfdt"
    };
    const uint64_t cookie = UINT64_C(0x6464646464646464);
    cap_env_t env;
    ninlil_submission_result_t result;
    ninlil_rt_transaction_slot_t *transaction;
    uint8_t transfer_id[16];
    uint64_t commits_before;
    uint64_t puts_before;
    uint64_t erases_before;
    uint64_t sends_before;
    uint64_t acquires_before;
    uint32_t variant;

    for (variant = 0u; variant < 3u; ++variant) {
        REQUIRE(prepare_mfdt_restart_env(&env, 0xd3u, cookie));
        REQUIRE(submit_with_payload(
            &env,
            927u,
            5000u,
            0u,
            idempotency_keys[variant],
            strlen((const char *)idempotency_keys[variant]),
            &result));
        transaction = ninlil_rt_find_transaction(
            env.runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        (void)memcpy(
            transfer_id,
            transaction->bound_targets[0].mfdt_transfer_id,
            sizeof(transfer_id));
        REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
        env.runtime = NULL;
        env.service = NULL;
        REQUIRE(ninlil_runtime_create(
                    &env.config, &env.platform, &env.runtime) == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        if (variant == 0u) {
            transaction->content_digest.bytes[0] ^= 0x01u;
        } else if (variant == 1u) {
            transaction->terminal = 1u;
        } else {
            transaction->bearer_route =
                (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_SIMULATED;
        }
        commits_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        puts_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        erases_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
        sends_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
        acquires_before = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE);
        REQUIRE(configure_mfdt_owner_status(env.runtime, 1u, cookie)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(env.runtime->commit_unknown_fence == 1u);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commits_before);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
            == puts_before);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE)
            == erases_before);
        REQUIRE(raw_mfdt_row_present(&env, "NM3S", transfer_id));
        REQUIRE(raw_mfdt_row_present(&env, "NRC1", transfer_id));
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_before);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_TX_ACQUIRE)
            == acquires_before);
        REQUIRE(env.runtime->metrics.application_callback_invocations == 0u);
        platform_teardown(&env);
    }
    return 0;
}

typedef struct mfdt_handoff_capture {
    const uint8_t *expected_payload;
    uint32_t expected_length;
    ninlil_id128_t expected_transaction_id;
    ninlil_id128_t expected_attempt_id;
    ninlil_id128_t expected_event_id;
    ninlil_digest256_t expected_digest;
    ninlil_party_t expected_source;
    ninlil_concrete_target_t expected_target;
    ninlil_service_identity_t expected_service;
    ninlil_id128_t expected_deadline_clock_epoch_id;
    uint64_t expected_generation;
    uint64_t expected_effect_deadline_ms;
    uint64_t expected_evidence_grace_ms;
    ninlil_evidence_stage_t expected_required_evidence;
    ninlil_delivery_token_t token;
    uint32_t calls;
    uint32_t exact;
    uint32_t defer;
} mfdt_handoff_capture_t;

static const uint8_t MFDT_HANDOFF_EVIDENCE[] = {
    0x61u, 0x70u, 0x70u, 0x6cu, 0x69u,
    0x65u, 0x64u, 0x3au, 0x6fu, 0x6bu
};

static int test_mfdt_application_evidence_digest_kat(void)
{
    static const uint8_t publication_token[16] = {
        0xeeu, 0x1du, 0xa9u, 0xfcu, 0x8bu, 0x61u, 0x4eu, 0x47u,
        0x80u, 0xa4u, 0xb8u, 0x21u, 0x4du, 0x93u, 0xd4u, 0xa9u
    };
    static const uint8_t expected_digest[32] = {
        0x11u, 0x11u, 0x89u, 0x98u, 0x1bu, 0x33u, 0x7du, 0x4bu,
        0xd8u, 0x2eu, 0x94u, 0xafu, 0xb1u, 0x5eu, 0x89u, 0xe6u,
        0xb5u, 0xacu, 0x6eu, 0x07u, 0xffu, 0xd7u, 0x29u, 0x20u,
        0x8eu, 0xd9u, 0x9bu, 0x9au, 0x01u, 0x5fu, 0xb0u, 0xb3u
    };
    ninlil_id128_t origin_transaction_id;
    ninlil_id128_t original_attempt_id;
    ninlil_bytes_view_t evidence;
    uint8_t digest[32];

    set_id(&origin_transaction_id, 0x5du);
    set_id(&original_attempt_id, 0x6du);
    evidence.data = MFDT_HANDOFF_EVIDENCE;
    evidence.length = sizeof(MFDT_HANDOFF_EVIDENCE);
    REQUIRE(ninlil_rt_mfdt_v1_application_evidence_digest(
                publication_token,
                &origin_transaction_id,
                &original_attempt_id,
                3u,
                NINLIL_EVIDENCE_APPLIED,
                evidence,
                digest) == NINLIL_OK);
    REQUIRE(memcmp(digest, expected_digest, sizeof(digest)) == 0);
    return 0;
}

static int mfdt_text_id_equal(
    const ninlil_text_id_t *left,
    const ninlil_text_id_t *right)
{
    return left->length == right->length &&
        memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int mfdt_receipt_is_exact(
    const ninlil_bearer_message_t *receipt,
    const mfdt_handoff_capture_t *capture)
{
    return receipt != NULL && capture != NULL &&
        receipt->kind == NINLIL_BEARER_MESSAGE_RECEIPT &&
        memcmp(
            receipt->transaction_id.bytes,
            capture->expected_transaction_id.bytes,
            16u) == 0 &&
        memcmp(
            receipt->attempt_id.bytes,
            capture->expected_attempt_id.bytes,
            16u) == 0 &&
        memcmp(
            receipt->event_id.bytes,
            capture->expected_event_id.bytes,
            16u) == 0 &&
        memcmp(
            &receipt->content_digest,
            &capture->expected_digest,
            sizeof(receipt->content_digest)) == 0 &&
        receipt->generation == capture->expected_generation &&
        memcmp(
            receipt->deadline_clock_epoch_id.bytes,
            capture->expected_deadline_clock_epoch_id.bytes,
            16u) == 0 &&
        receipt->absolute_effect_deadline_ms ==
            capture->expected_effect_deadline_ms &&
        receipt->evidence_grace_ms ==
            capture->expected_evidence_grace_ms &&
        receipt->required_evidence ==
            capture->expected_required_evidence &&
        receipt->receipt_stage == NINLIL_EVIDENCE_APPLIED &&
        receipt->evidence.length == sizeof(MFDT_HANDOFF_EVIDENCE) &&
        receipt->evidence.data != NULL &&
        memcmp(
            receipt->evidence.data,
            MFDT_HANDOFF_EVIDENCE,
            sizeof(MFDT_HANDOFF_EVIDENCE)) == 0 &&
        receipt->payload.length == 0u && receipt->payload.data == NULL &&
        receipt->service.family == capture->expected_service.family &&
        receipt->service.schema_major ==
            capture->expected_service.schema_major &&
        receipt->service.schema_minor ==
            capture->expected_service.schema_minor &&
        receipt->service.descriptor_revision ==
            capture->expected_service.descriptor_revision &&
        memcmp(
            &receipt->service.descriptor_digest,
            &capture->expected_service.descriptor_digest,
            sizeof(receipt->service.descriptor_digest)) == 0 &&
        mfdt_text_id_equal(
            &receipt->service.namespace_id,
            &capture->expected_service.namespace_id) &&
        mfdt_text_id_equal(
            &receipt->service.service_id,
            &capture->expected_service.service_id) &&
        mfdt_text_id_equal(
            &receipt->service.schema_id,
            &capture->expected_service.schema_id) &&
        memcmp(
            receipt->source.runtime_id.bytes,
            capture->expected_target.target_runtime_id.bytes,
            16u) == 0 &&
        memcmp(
            receipt->source.application_instance_id.bytes,
            capture->expected_target.target_application_instance_id.bytes,
            16u) == 0 &&
        memcmp(
            &receipt->source.local_identity.device_id,
            &capture->expected_target.device_id,
            sizeof(receipt->source.local_identity.device_id)) == 0 &&
        memcmp(
            &receipt->source.local_identity.installation_id,
            &capture->expected_target.installation_id,
            sizeof(receipt->source.local_identity.installation_id)) == 0 &&
        memcmp(
            &receipt->source.local_identity.site_domain_id,
            &capture->expected_target.site_domain_id,
            sizeof(receipt->source.local_identity.site_domain_id)) == 0 &&
        receipt->source.local_identity.binding_epoch ==
            capture->expected_target.binding_epoch &&
        receipt->source.local_identity.membership_epoch ==
            capture->expected_target.membership_epoch &&
        receipt->source.local_identity.flags ==
            capture->expected_target.flags &&
        memcmp(
            receipt->target.target_runtime_id.bytes,
            capture->expected_source.runtime_id.bytes,
            16u) == 0 &&
        memcmp(
            receipt->target.target_application_instance_id.bytes,
            capture->expected_source.application_instance_id.bytes,
            16u) == 0 &&
        memcmp(
            &receipt->target.device_id,
            &capture->expected_source.local_identity.device_id,
            sizeof(receipt->target.device_id)) == 0 &&
        memcmp(
            &receipt->target.installation_id,
            &capture->expected_source.local_identity.installation_id,
            sizeof(receipt->target.installation_id)) == 0 &&
        memcmp(
            &receipt->target.site_domain_id,
            &capture->expected_source.local_identity.site_domain_id,
            sizeof(receipt->target.site_domain_id)) == 0 &&
        receipt->target.binding_epoch ==
            capture->expected_source.local_identity.binding_epoch &&
        receipt->target.membership_epoch ==
            capture->expected_source.local_identity.membership_epoch &&
        receipt->target.flags ==
            capture->expected_source.local_identity.flags;
}

static ninlil_callback_action_t mfdt_handoff_callback(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    mfdt_handoff_capture_t *capture = (mfdt_handoff_capture_t *)user;

    if (capture == NULL) {
        return NINLIL_CALLBACK_FATAL;
    }
    capture->calls += 1u;
    if (token == NULL || delivery == NULL || out_sync_result == NULL) {
        capture->exact = 0u;
        return NINLIL_CALLBACK_FATAL;
    }
    capture->token = *token;
    if (memcmp(
            token->context_id.bytes,
            capture->expected_transaction_id.bytes,
            16u) != 0 ||
        memcmp(
            delivery->transaction_id.bytes,
            capture->expected_transaction_id.bytes,
            16u) != 0 ||
        memcmp(
            delivery->attempt_id.bytes,
            capture->expected_attempt_id.bytes,
            16u) != 0 ||
        delivery->payload.data == NULL ||
        delivery->payload.length != capture->expected_length ||
        memcmp(
            delivery->payload.data,
            capture->expected_payload,
            capture->expected_length) != 0 ||
        memcmp(
            &delivery->content_digest,
            &capture->expected_digest,
            sizeof(delivery->content_digest)) != 0 ||
        token->generation != delivery->delivery_count) {
        capture->exact = 0u;
    }
    if (capture->defer != 0u) {
        return NINLIL_CALLBACK_DEFER;
    }
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    out_sync_result->evidence.data = MFDT_HANDOFF_EVIDENCE;
    out_sync_result->evidence.length = sizeof(MFDT_HANDOFF_EVIDENCE);
    return NINLIL_CALLBACK_COMPLETE;
}

typedef enum mfdt_handoff_mismatch_kind {
    MFDT_HANDOFF_MISMATCH_IDENTITY = 0,
    MFDT_HANDOFF_MISMATCH_DIGEST = 1,
    MFDT_HANDOFF_MISMATCH_LENGTH = 2,
    MFDT_HANDOFF_MISMATCH_ROUTE = 3,
    MFDT_HANDOFF_MISMATCH_TRANSFER = 4,
    MFDT_HANDOFF_MISMATCH_ORDINAL = 5,
    MFDT_HANDOFF_MISMATCH_STATE = 6,
    MFDT_HANDOFF_MISMATCH_EVIDENCE_DIGEST = 7
} mfdt_handoff_mismatch_kind_t;

static void mutate_mfdt_handoff_foundation(
    ninlil_rt_transaction_slot_t *transaction,
    mfdt_handoff_mismatch_kind_t kind)
{
    switch (kind) {
    case MFDT_HANDOFF_MISMATCH_IDENTITY:
        transaction->source.runtime_id.bytes[0] ^= 0x01u;
        break;
    case MFDT_HANDOFF_MISMATCH_DIGEST:
        transaction->content_digest.bytes[0] ^= 0x01u;
        break;
    case MFDT_HANDOFF_MISMATCH_LENGTH:
        transaction->payload_length ^= 1u;
        break;
    case MFDT_HANDOFF_MISMATCH_ROUTE:
        transaction->bearer_route =
            (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_SIMULATED;
        break;
    case MFDT_HANDOFF_MISMATCH_TRANSFER:
        transaction->bound_targets[0].mfdt_transfer_id[0] ^= 0x01u;
        break;
    case MFDT_HANDOFF_MISMATCH_ORDINAL:
        transaction->bound_targets[0].mfdt_target_ordinal = 1u;
        break;
    case MFDT_HANDOFF_MISMATCH_STATE:
        transaction->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
        break;
    case MFDT_HANDOFF_MISMATCH_EVIDENCE_DIGEST:
        transaction->application_evidence[0] ^= 0x01u;
        break;
    }
}

static int test_mfdt_cold_restart_receiver_handoff(void)
{
    static const struct {
        uint32_t payload_length;
        const uint8_t *idempotency_key;
        uint32_t defer;
    } cases[] = {
        {927u, (const uint8_t *)"mfdt-ready-927", 0u},
        {4096u, (const uint8_t *)"mfdt-ready-4096", 1u},
        {32768u, (const uint8_t *)"mfdt-ready-32768", 0u}
    };
    const uint64_t cookie = UINT64_C(0x6565656565656565);
    uint32_t case_index;

    for (case_index = 0u;
         case_index < sizeof(cases) / sizeof(cases[0]);
         ++case_index) {
        cap_env_t env;
        cap_env_t receiver_env;
        mfdt_handoff_capture_t capture;
        ninlil_runtime_config_t receiver_config;
        ninlil_runtime_t *receiver_runtime = NULL;
        ninlil_mfdt_v1_session_t sender_session;
        ninlil_mfdt_v1_session_t receiver_session;
        ninlil_submission_t submission;
        ninlil_submission_result_t result;
        ninlil_service_descriptor_t descriptor;
        ninlil_service_callbacks_t callbacks;
        ninlil_service_t *receiver_service = NULL;
        ninlil_application_result_t deferred_result;
        ninlil_rt_transaction_slot_t *transaction;
        ninlil_time_sample_t resumed_time;
        ninlil_step_budget_t callback_budget;
        ninlil_step_result_t step_result;
        const uint8_t *published = NULL;
        uint8_t publication_token[16];
        uint8_t transfer_id[16];
        uint8_t zero_payload[NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES];
        uint32_t published_length = 0u;
        uint64_t acceptance_generation = 0u;
        uint64_t commits_before;
        uint64_t puts_before;
        uint64_t erases_before;
        uint64_t sends_at_ready;
        uint32_t rebind_cu_observed = 0u;
        uint32_t rebind_cu_scripted = 0u;
        uint32_t rebind_fault_observed = 0u;
        uint32_t rebind_fault_scripted = 0u;
        uint32_t step_index;
        ninlil_status_t publication_status = NINLIL_E_WOULD_BLOCK;

        (void)memset(&env, 0, sizeof(env));
        REQUIRE(platform_init(&env));
        env.config = config_controller(4u);
        env.config.limits.max_logical_payload_bytes =
            NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
        env.config.limits.max_durable_outbox_payload_bytes = 262144u;
        set_id(&env.config.runtime_id, 0x30u);
        REQUIRE(ninlil_runtime_create(
                    &env.config, &env.platform, &env.runtime) == NINLIL_OK);
        REQUIRE(configure_mfdt_owner(env.runtime, 1u, cookie));
        REQUIRE(env_register_mfdt(&env, 0xd4u, 1u));

        receiver_config = env.config;
        receiver_config.role = NINLIL_ROLE_ENDPOINT;
        receiver_config.limits.max_durable_outbox_payload_bytes = 0u;
        receiver_config.storage_namespace.data = MFDT_TEST_NAMESPACE_B;
        receiver_config.storage_namespace.length =
            sizeof(MFDT_TEST_NAMESPACE_B) - 1u;
        set_id(&receiver_config.runtime_id, 0x50u);
        REQUIRE(ninlil_runtime_create(
                    &receiver_config,
                    &env.platform,
                    &receiver_runtime) == NINLIL_OK);
        REQUIRE(configure_mfdt_owner(receiver_runtime, 1u, cookie));
        REQUIRE(make_admitted_mfdt_session_pair(
            env.runtime,
            receiver_runtime,
            1u,
            cookie,
            &sender_session,
            &receiver_session));
        REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                    env.runtime, &sender_session) == NINLIL_OK);
        REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                    receiver_runtime, &receiver_session) == NINLIL_OK);

        REQUIRE(ensure_payload(&env, cases[case_index].payload_length));
        fill_target(&env);
        set_id(&env.target.target_runtime_id, 0x50u);
        env.target.device_id = receiver_config.local_identity.device_id;
        env.target.installation_id =
            receiver_config.local_identity.installation_id;
        env.target.site_domain_id =
            receiver_config.local_identity.site_domain_id;
        env.target.binding_epoch =
            receiver_config.local_identity.binding_epoch;
        env.target.membership_epoch =
            receiver_config.local_identity.membership_epoch;
        env.target.flags = receiver_config.local_identity.flags;
        (void)memset(&submission, 0, sizeof(submission));
        set_header(
            &submission.abi_version,
            &submission.struct_size,
            sizeof(submission));
        submission.schema_major = 1u;
        submission.targets = &env.target;
        submission.target_count = 1u;
        submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
        submission.effect_deadline_ms = 60000u;
        submission.evidence_grace_ms = 1000u;
        submission.generation = 1u;
        submission.idempotency_key.data = cases[case_index].idempotency_key;
        submission.idempotency_key.length =
            strlen((const char *)cases[case_index].idempotency_key);
        submission.payload.data = env.payload;
        submission.payload.length = cases[case_index].payload_length;
        REQUIRE(set_payload_content_digest(
            &submission.content_digest,
            env.payload,
            cases[case_index].payload_length));
        (void)memset(&result, 0, sizeof(result));
        set_header(
            &result.abi_version, &result.struct_size, sizeof(result));
        REQUIRE(ninlil_submit(env.service, &submission, &result) == NINLIL_OK);
        REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
        transaction = ninlil_rt_find_transaction(
            env.runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        (void)memcpy(
            transfer_id,
            transaction->bound_targets[0].mfdt_transfer_id,
            sizeof(transfer_id));
        (void)memset(&capture, 0, sizeof(capture));
        capture.expected_payload = env.payload;
        capture.expected_length = cases[case_index].payload_length;
        capture.expected_transaction_id = result.transaction_id;
        capture.expected_attempt_id = transaction->attempt_id;
        capture.expected_event_id = transaction->event_id;
        capture.expected_digest = submission.content_digest;
        capture.expected_source = transaction->source;
        capture.expected_target = env.target;
        capture.expected_service = transaction->service;
        capture.expected_deadline_clock_epoch_id =
            transaction->deadline_clock_epoch_id;
        capture.expected_generation = transaction->generation;
        capture.expected_effect_deadline_ms =
            transaction->effect_deadline_ms;
        capture.expected_evidence_grace_ms =
            transaction->evidence_grace_ms;
        capture.expected_required_evidence =
            transaction->required_evidence;
        capture.exact = 1u;
        capture.defer = cases[case_index].defer;

        REQUIRE(step_runtime(&env, 1u, &step_result));
        REQUIRE(step_result.bearer_sends == 1u);
        receiver_env = env;
        receiver_env.config = receiver_config;
        receiver_env.runtime = receiver_runtime;
        receiver_env.service = NULL;
        REQUIRE(step_runtime(&receiver_env, 0u, &step_result));
        REQUIRE(step_result.ingress_processed == 1u);
        REQUIRE(mfdt_active_count_is(receiver_runtime, 1u));
        REQUIRE(ninlil_rt_find_transaction(
            receiver_runtime, &result.transaction_id) == NULL);
        REQUIRE(step_runtime(&receiver_env, 1u, &step_result));
        REQUIRE(step_result.bearer_sends == 1u);
        REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
        receiver_runtime = NULL;
        receiver_env.runtime = NULL;
        REQUIRE(raw_mfdt_row_present(&receiver_env, "NM3R", transfer_id));
        REQUIRE(raw_mfdt_row_present(&receiver_env, "NRC1", transfer_id));
        REQUIRE(ninlil_runtime_create(
                    &receiver_config,
                    &env.platform,
                    &receiver_runtime) == NINLIL_OK);
        receiver_env.runtime = receiver_runtime;
        commits_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
        puts_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
        erases_before = ninlil_test_storage_call_count(
            env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
        REQUIRE(configure_mfdt_owner_status(receiver_runtime, 1u, cookie)
            == NINLIL_OK);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT)
            == commits_before);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT)
            == puts_before);
        REQUIRE(ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE)
            == erases_before);
        REQUIRE(ninlil_rt_find_transaction(
            receiver_runtime, &result.transaction_id) == NULL);
        REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                    receiver_runtime, &receiver_session) == NINLIL_OK);

        for (step_index = 0u; step_index < 512u; ++step_index) {
            REQUIRE(step_runtime(&env, 1u, &step_result));
            if (case_index == 0u && rebind_fault_scripted == 0u &&
                step_result.bearer_sends == 1u) {
                REQUIRE(ninlil_test_storage_fault_next(
                    env.storage_fixture,
                    NINLIL_TEST_STORAGE_OP_COMMIT,
                    NINLIL_STORAGE_IO_ERROR));
                rebind_fault_scripted = 1u;
            } else if (case_index == 0u &&
                rebind_fault_observed != 0u &&
                rebind_cu_scripted == 0u &&
                step_result.bearer_sends == 1u) {
                REQUIRE(ninlil_test_storage_fault_enqueue(
                    env.storage_fixture,
                    NINLIL_TEST_STORAGE_OP_COMMIT,
                    NINLIL_STORAGE_COMMIT_UNKNOWN,
                    1u,
                    1,
                    0));
                rebind_cu_scripted = 1u;
            }
            if (case_index == 0u && rebind_fault_scripted != 0u &&
                rebind_fault_observed == 0u) {
                REQUIRE(step_runtime_status(
                            &receiver_env, 1u, &step_result)
                    == NINLIL_E_STORAGE);
                rebind_fault_observed = 1u;
                REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
                (void)memset(&resumed_time, 0, sizeof(resumed_time));
                REQUIRE(env.platform.clock->now(
                            env.platform.clock->user, &resumed_time)
                    == NINLIL_PORT_OK);
                REQUIRE(ninlil_test_bearer_set_time(
                    env.bearer_fixture,
                    resumed_time.clock_epoch_id,
                    resumed_time.now_ms));
                continue;
            }
            if (case_index == 0u && rebind_cu_scripted != 0u &&
                rebind_cu_observed == 0u) {
                uint64_t commits_after_cu;
                uint64_t puts_after_cu;
                uint64_t erases_after_cu;
                uint64_t sends_after_cu;

                REQUIRE(step_runtime_status(
                            &receiver_env, 1u, &step_result)
                    == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
                rebind_cu_observed = 1u;
                REQUIRE(receiver_runtime->commit_unknown_fence == 1u);
                REQUIRE(receiver_runtime->metrics
                            .application_callback_invocations == 0u);
                commits_after_cu = ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
                puts_after_cu = ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
                erases_after_cu = ninlil_test_storage_call_count(
                    env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
                sends_after_cu = ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
                REQUIRE(step_runtime_status(
                            &receiver_env, 1u, &step_result)
                    == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
                REQUIRE(ninlil_test_storage_call_count(
                            env.storage_fixture,
                            NINLIL_TEST_STORAGE_OP_COMMIT)
                    == commits_after_cu);
                REQUIRE(ninlil_test_storage_call_count(
                            env.storage_fixture,
                            NINLIL_TEST_STORAGE_OP_PUT)
                    == puts_after_cu);
                REQUIRE(ninlil_test_storage_call_count(
                            env.storage_fixture,
                            NINLIL_TEST_STORAGE_OP_ERASE)
                    == erases_after_cu);
                REQUIRE(ninlil_test_bearer_call_count(
                            env.bearer_fixture,
                            NINLIL_TEST_BEARER_OP_SEND)
                    == sends_after_cu);
                REQUIRE(ninlil_runtime_destroy(receiver_runtime)
                    == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
                receiver_runtime = NULL;
                receiver_env.runtime = NULL;
                REQUIRE(ninlil_runtime_create(
                            &receiver_config,
                            &env.platform,
                            &receiver_runtime) == NINLIL_OK);
                receiver_env.runtime = receiver_runtime;
                REQUIRE(configure_mfdt_owner_status(
                            receiver_runtime, 1u, cookie) == NINLIL_OK);
                REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                            receiver_runtime,
                            &receiver_session) == NINLIL_OK);
                REQUIRE(ninlil_test_clock_advance(env.clock, 5001u));
                (void)memset(&resumed_time, 0, sizeof(resumed_time));
                REQUIRE(env.platform.clock->now(
                            env.platform.clock->user, &resumed_time)
                    == NINLIL_PORT_OK);
                REQUIRE(ninlil_test_bearer_set_time(
                    env.bearer_fixture,
                    resumed_time.clock_epoch_id,
                    resumed_time.now_ms));
                continue;
            }
            REQUIRE(step_runtime(&receiver_env, 1u, &step_result));
            publication_status =
                ninlil_rt_mfdt_v1_runtime_receiver_publication_view(
                    receiver_runtime,
                    transfer_id,
                    &published,
                    &published_length,
                    publication_token,
                    &acceptance_generation);
            if (publication_status == NINLIL_OK) {
                break;
            }
            REQUIRE(publication_status == NINLIL_E_WOULD_BLOCK ||
                publication_status == NINLIL_E_NOT_FOUND);
        }
        REQUIRE(case_index != 0u ||
            (rebind_fault_observed != 0u && rebind_cu_observed != 0u));
        REQUIRE(publication_status == NINLIL_OK);
        REQUIRE(published != NULL);
        REQUIRE(published_length == cases[case_index].payload_length);
        REQUIRE(memcmp(
            published, env.payload, cases[case_index].payload_length) == 0);
        REQUIRE(acceptance_generation != 0u);
        REQUIRE(ninlil_rt_find_transaction(
            receiver_runtime, &result.transaction_id) == NULL);
        REQUIRE(receiver_runtime->metrics.application_callback_invocations
            == 0u);

        descriptor = desired_descriptor(0x81u);
        descriptor.logical_payload_limit =
            NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
        descriptor.max_payload_bytes_per_window = 262144u;
        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version,
            &callbacks.struct_size,
            sizeof(callbacks));
        callbacks.user = &capture;
        callbacks.on_delivery = mfdt_handoff_callback;
        callbacks.on_reconcile = NULL;
        descriptor.apply_contract = NINLIL_APPLY_IDEMPOTENT;
        REQUIRE(ninlil_service_register(
                    receiver_runtime,
                    &descriptor,
                    &callbacks,
                    &receiver_service) == NINLIL_OK);
        REQUIRE(receiver_service != NULL);
        sends_at_ready = ninlil_test_bearer_call_count(
            env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
        (void)memset(&callback_budget, 0, sizeof(callback_budget));
        set_header(
            &callback_budget.abi_version,
            &callback_budget.struct_size,
            sizeof(callback_budget));
        callback_budget.max_callbacks = 1u;
        callback_budget.max_state_transitions = 1u;
        if (case_index == 2u) {
            uint64_t commits_after_cu;
            uint64_t puts_after_cu;
            uint64_t erases_after_cu;
            uint64_t sends_after_cu;

            REQUIRE(ninlil_test_storage_fault_next(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_IO_ERROR));
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            REQUIRE(ninlil_runtime_step(
                        receiver_runtime,
                        &callback_budget,
                        &step_result) == NINLIL_E_STORAGE);
            REQUIRE(ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id) == NULL);
            REQUIRE(capture.calls == 0u);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == sends_at_ready);

            REQUIRE(ninlil_test_storage_fault_enqueue(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                1));
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            REQUIRE(ninlil_runtime_step(
                        receiver_runtime,
                        &callback_budget,
                        &step_result)
                == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            REQUIRE(receiver_runtime->commit_unknown_fence == 1u);
            REQUIRE(ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id) == NULL);
            REQUIRE(capture.calls == 0u);
            commits_after_cu = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
            puts_after_cu = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
            erases_after_cu = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
            sends_after_cu = ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
            REQUIRE(step_runtime_status(
                        &receiver_env, 1u, &step_result)
                == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_COMMIT) == commits_after_cu);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_PUT) == puts_after_cu);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_ERASE) == erases_after_cu);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == sends_after_cu);
            REQUIRE(ninlil_runtime_destroy(receiver_runtime)
                == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            receiver_runtime = NULL;
            receiver_env.runtime = NULL;
            REQUIRE(ninlil_runtime_create(
                        &receiver_config,
                        &env.platform,
                        &receiver_runtime) == NINLIL_OK);
            receiver_env.runtime = receiver_runtime;
            transaction = ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id);
            REQUIRE(transaction != NULL);
            REQUIRE(transaction->evidence_recorded == 0u);
            REQUIRE(configure_mfdt_owner_status(
                        receiver_runtime, 1u, cookie) == NINLIL_OK);
            REQUIRE(ninlil_rt_mfdt_v1_runtime_bind_session(
                        receiver_runtime,
                        &receiver_session) == NINLIL_OK);
            receiver_service = NULL;
            REQUIRE(ninlil_service_register(
                        receiver_runtime,
                        &descriptor,
                        &callbacks,
                        &receiver_service) == NINLIL_OK);
            REQUIRE(receiver_service != NULL);
            REQUIRE(capture.calls == 0u);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == sends_at_ready);
        }
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    receiver_runtime, &callback_budget, &step_result)
            == NINLIL_OK);
        REQUIRE(capture.calls == 0u);
        transaction = ninlil_rt_find_transaction(
            receiver_runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->origin_admission == 0u);
        REQUIRE(transaction->payload_length == cases[case_index].payload_length);
        REQUIRE(transaction->inline_payload_length == 0u);
        (void)memset(zero_payload, 0, sizeof(zero_payload));
        REQUIRE(memcmp(
            transaction->owned_payload,
            zero_payload,
            sizeof(zero_payload)) == 0);
        REQUIRE(transaction->bearer_route ==
            (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
        REQUIRE(transaction->bound_target_count == 1u);
        REQUIRE(transaction->bound_targets[0].mfdt_target_ordinal == 0u);
        REQUIRE(memcmp(
            transaction->bound_targets[0].mfdt_transfer_id,
            transfer_id,
            16u) == 0);

        callback_budget.max_state_transitions = 8u;
        for (step_index = 0u; step_index < 4u && capture.calls == 0u;
             ++step_index) {
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            REQUIRE(ninlil_runtime_step(
                        receiver_runtime, &callback_budget, &step_result)
                == NINLIL_OK);
        }
        REQUIRE(capture.calls == 1u);
        REQUIRE(capture.exact == 1u);
        REQUIRE(memcmp(
            capture.token.context_id.bytes,
            result.transaction_id.bytes,
            16u) == 0);
        REQUIRE(memcmp(
            capture.token.context_id.bytes,
            publication_token,
            16u) != 0);
        if (cases[case_index].defer != 0u) {
            ninlil_delivery_token_t stable_token = capture.token;
            uint64_t sends_before_restart;
            uint32_t callbacks_before_restart;

            transaction = ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id);
            REQUIRE(transaction != NULL);
            REQUIRE(transaction->deferred_wait != 0u);
            REQUIRE(transaction->evidence_recorded == 0u);
            for (step_index = 0u; step_index < 2u; ++step_index) {
                (void)memset(&step_result, 0, sizeof(step_result));
                set_header(
                    &step_result.abi_version,
                    &step_result.struct_size,
                    sizeof(step_result));
                REQUIRE(ninlil_runtime_step(
                            receiver_runtime,
                            &callback_budget,
                            &step_result) == NINLIL_OK);
            }
            REQUIRE(capture.calls == 1u);
            REQUIRE(memcmp(
                &stable_token, &capture.token, sizeof(stable_token)) == 0);
            callbacks_before_restart = capture.calls;
            sends_before_restart = ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
            REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
            receiver_runtime = NULL;
            receiver_env.runtime = NULL;
            REQUIRE(raw_mfdt_row_present(
                &receiver_env, "NM3R", transfer_id));
            REQUIRE(raw_mfdt_row_present(
                &receiver_env, "NRC1", transfer_id));
            REQUIRE(ninlil_runtime_create(
                        &receiver_config,
                        &env.platform,
                        &receiver_runtime) == NINLIL_OK);
            receiver_env.runtime = receiver_runtime;
            transaction = ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id);
            REQUIRE(transaction != NULL);
            REQUIRE(memcmp(
                transaction->transaction_id.bytes,
                stable_token.context_id.bytes,
                sizeof(transaction->transaction_id.bytes)) == 0);
            REQUIRE(transaction->token_generation == stable_token.generation);
            REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_EXPIRED);
            REQUIRE(transaction->delivery_phase ==
                NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
            REQUIRE(transaction->reason == NINLIL_REASON_OUTCOME_UNKNOWN);
            REQUIRE(transaction->application_result_reason ==
                NINLIL_REASON_OUTCOME_UNKNOWN);
            REQUIRE(transaction->application_effect_certainty ==
                NINLIL_EFFECT_CERTAINTY_POSSIBLE);
            REQUIRE(transaction->deferred_wait == 0u);
            REQUIRE(transaction->evidence_recorded == 0u);
            REQUIRE(transaction->receipt_pending == 0u);
            REQUIRE(transaction->reverse_receipt_closed == 0u);
            (void)memset(&deferred_result, 0, sizeof(deferred_result));
            set_header(
                &deferred_result.abi_version,
                &deferred_result.struct_size,
                sizeof(deferred_result));
            deferred_result.kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
            deferred_result.evidence_stage = NINLIL_EVIDENCE_APPLIED;
            REQUIRE(ninlil_delivery_complete(
                        receiver_runtime,
                        &stable_token,
                        &deferred_result) == NINLIL_E_INVALID_STATE);
            REQUIRE(configure_mfdt_owner_status(
                        receiver_runtime, 1u, cookie) == NINLIL_OK);
            published = NULL;
            published_length = 0u;
            REQUIRE(ninlil_rt_mfdt_v1_runtime_borrow_receiver_payload(
                        receiver_runtime,
                        transfer_id,
                        0u,
                        &result.transaction_id,
                        &published,
                        &published_length) == NINLIL_OK);
            REQUIRE(published != NULL);
            REQUIRE(published_length == cases[case_index].payload_length);
            REQUIRE(memcmp(
                published,
                env.payload,
                cases[case_index].payload_length) == 0);
            receiver_service = NULL;
            REQUIRE(ninlil_service_register(
                        receiver_runtime,
                        &descriptor,
                        &callbacks,
                        &receiver_service) == NINLIL_OK);
            REQUIRE(receiver_service != NULL);
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            REQUIRE(ninlil_runtime_step(
                        receiver_runtime,
                        &callback_budget,
                        &step_result) == NINLIL_OK);
            REQUIRE(step_result.callbacks_invoked == 0u);
            REQUIRE(step_result.bearer_sends == 0u);
            REQUIRE(capture.calls == callbacks_before_restart);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == sends_before_restart);
            transaction = ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id);
            REQUIRE(transaction != NULL);
            REQUIRE(transaction->token_state == NINLIL_RT_TOKEN_EXPIRED);
            REQUIRE(transaction->delivery_phase ==
                NINLIL_RT_DELIVERY_RECOVERY_REQUIRED);
            REQUIRE(transaction->evidence_recorded == 0u);
            REQUIRE(transaction->terminal == 0u);
            REQUIRE(transaction->outcome_recorded == 0u);
            REQUIRE(transaction->receipt_pending == 0u);
            REQUIRE(transaction->reverse_receipt_closed == 0u);
            REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
            receiver_runtime = NULL;
            receiver_env.runtime = NULL;
            platform_teardown(&env);
            continue;
        }
        transaction = ninlil_rt_find_transaction(
            receiver_runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->evidence_recorded != 0u);
        REQUIRE(transaction->latest_evidence == NINLIL_EVIDENCE_APPLIED);
        REQUIRE(transaction->terminal == 0u);
        REQUIRE(transaction->outcome_recorded == 0u);
        REQUIRE(transaction->reverse_receipt_closed == 0u);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_at_ready);

        if (case_index == 2u) {
            uint32_t handoff_complete = 0u;
            uint64_t commits_after_handoff_cu;
            uint64_t puts_after_handoff_cu;
            uint64_t erases_after_handoff_cu;
            uint64_t sends_after_handoff_cu;

            REQUIRE(ninlil_rt_mfdt_v1_runtime_receiver_handoff_complete(
                        receiver_runtime,
                        transfer_id,
                        0u,
                        &result.transaction_id,
                        &handoff_complete) == NINLIL_OK);
            REQUIRE(handoff_complete == 0u);
            REQUIRE(ninlil_test_storage_fault_next(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_IO_ERROR));
            REQUIRE(step_runtime_status(
                        &receiver_env, 0u, &step_result) ==
                NINLIL_E_STORAGE);
            REQUIRE(step_result.state_transitions == 0u);
            REQUIRE(step_result.callbacks_invoked == 0u);
            REQUIRE(step_result.bearer_sends == 0u);
            REQUIRE(capture.calls == 1u);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == sends_at_ready);
            REQUIRE(ninlil_rt_mfdt_v1_runtime_receiver_handoff_complete(
                        receiver_runtime,
                        transfer_id,
                        0u,
                        &result.transaction_id,
                        &handoff_complete) == NINLIL_OK);
            REQUIRE(handoff_complete == 0u);
            transaction = ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id);
            REQUIRE(transaction != NULL);
            REQUIRE(transaction->evidence_recorded != 0u);
            REQUIRE(transaction->receipt_pending == 0u);
            REQUIRE(transaction->reverse_receipt_closed == 0u);

            REQUIRE(ninlil_test_storage_fault_enqueue(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                1));
            REQUIRE(step_runtime_status(
                        &receiver_env, 0u, &step_result) ==
                NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            REQUIRE(step_result.state_transitions == 0u);
            REQUIRE(step_result.callbacks_invoked == 0u);
            REQUIRE(step_result.bearer_sends == 0u);
            REQUIRE(receiver_runtime->commit_unknown_fence == 1u);
            REQUIRE(capture.calls == 1u);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == sends_at_ready);
            commits_after_handoff_cu = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
            puts_after_handoff_cu = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
            erases_after_handoff_cu = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
            sends_after_handoff_cu = ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
            REQUIRE(step_runtime_status(
                        &receiver_env, 0u, &step_result) ==
                NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_COMMIT) ==
                commits_after_handoff_cu);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_PUT) == puts_after_handoff_cu);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_ERASE) ==
                erases_after_handoff_cu);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == sends_after_handoff_cu);
            REQUIRE(ninlil_runtime_destroy(receiver_runtime) ==
                NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            receiver_runtime = NULL;
            receiver_env.runtime = NULL;
            REQUIRE(raw_mfdt_row_present(
                &receiver_env, "NM3R", transfer_id));
            REQUIRE(ninlil_runtime_create(
                        &receiver_config,
                        &env.platform,
                        &receiver_runtime) == NINLIL_OK);
            receiver_env.runtime = receiver_runtime;
            REQUIRE(configure_mfdt_owner_status(
                        receiver_runtime, 1u, cookie) == NINLIL_OK);
            REQUIRE(mfdt_active_count_is(receiver_runtime, 1u));
            handoff_complete = 0u;
            REQUIRE(ninlil_rt_mfdt_v1_runtime_receiver_handoff_complete(
                        receiver_runtime,
                        transfer_id,
                        0u,
                        &result.transaction_id,
                        &handoff_complete) == NINLIL_OK);
            REQUIRE(handoff_complete == 1u);
            receiver_service = NULL;
            REQUIRE(ninlil_service_register(
                        receiver_runtime,
                        &descriptor,
                        &callbacks,
                        &receiver_service) == NINLIL_OK);
            REQUIRE(receiver_service != NULL);
        }

        for (step_index = 0u; step_index < 3u; ++step_index) {
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            REQUIRE(ninlil_runtime_step(
                        receiver_runtime, &callback_budget, &step_result)
                == NINLIL_OK);
        }
        REQUIRE(capture.calls == 1u);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_at_ready);

        REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
        receiver_runtime = NULL;
        receiver_env.runtime = NULL;
        REQUIRE(ninlil_runtime_create(
                    &receiver_config,
                    &env.platform,
                    &receiver_runtime) == NINLIL_OK);
        receiver_env.runtime = receiver_runtime;
        REQUIRE(configure_mfdt_owner_status(receiver_runtime, 1u, cookie)
            == NINLIL_OK);
        transaction = ninlil_rt_find_transaction(
            receiver_runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->evidence_recorded != 0u);
        receiver_service = NULL;
        REQUIRE(ninlil_service_register(
                    receiver_runtime,
                    &descriptor,
                    &callbacks,
                    &receiver_service) == NINLIL_OK);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    receiver_runtime, &callback_budget, &step_result)
            == NINLIL_OK);
        REQUIRE(capture.calls == 1u);
        REQUIRE(ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND)
            == sends_at_ready);
        if (case_index == 2u) {
            static const mfdt_handoff_mismatch_kind_t mismatch_cases[] = {
                MFDT_HANDOFF_MISMATCH_IDENTITY,
                MFDT_HANDOFF_MISMATCH_DIGEST,
                MFDT_HANDOFF_MISMATCH_LENGTH,
                MFDT_HANDOFF_MISMATCH_ROUTE,
                MFDT_HANDOFF_MISMATCH_TRANSFER,
                MFDT_HANDOFF_MISMATCH_ORDINAL,
                MFDT_HANDOFF_MISMATCH_STATE,
                MFDT_HANDOFF_MISMATCH_EVIDENCE_DIGEST
            };
            uint32_t mismatch_index;

            REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
            receiver_runtime = NULL;
            receiver_env.runtime = NULL;
            for (mismatch_index = 0u;
                 mismatch_index < sizeof(mismatch_cases) /
                         sizeof(mismatch_cases[0]);
                 ++mismatch_index) {
                uint64_t sends_before_mismatch;

                REQUIRE(ninlil_runtime_create(
                            &receiver_config,
                            &env.platform,
                            &receiver_runtime) == NINLIL_OK);
                receiver_env.runtime = receiver_runtime;
                transaction = ninlil_rt_find_transaction(
                    receiver_runtime, &result.transaction_id);
                REQUIRE(transaction != NULL);
                REQUIRE(transaction->receipt_pending == 0u);
                REQUIRE(transaction->reverse_receipt_closed == 0u);
                mutate_mfdt_handoff_foundation(
                    transaction, mismatch_cases[mismatch_index]);
                sends_before_mismatch = ninlil_test_bearer_call_count(
                    env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
                REQUIRE(configure_mfdt_owner_status(
                            receiver_runtime, 1u, cookie)
                    == NINLIL_E_STORAGE_CORRUPT);
                REQUIRE(receiver_runtime->commit_unknown_fence == 1u);
                REQUIRE(receiver_runtime->metrics
                            .application_callback_invocations == 0u);
                REQUIRE(capture.calls == 1u);
                REQUIRE(transaction->receipt_pending == 0u);
                REQUIRE(transaction->reverse_receipt_closed == 0u);
                REQUIRE(ninlil_test_bearer_call_count(
                            env.bearer_fixture,
                            NINLIL_TEST_BEARER_OP_SEND)
                    == sends_before_mismatch);
                REQUIRE(step_runtime_status(
                            &receiver_env, 1u, &step_result)
                    == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
                REQUIRE(step_result.callbacks_invoked == 0u);
                REQUIRE(step_result.bearer_sends == 0u);
                REQUIRE(capture.calls == 1u);
                REQUIRE(ninlil_test_bearer_call_count(
                            env.bearer_fixture,
                            NINLIL_TEST_BEARER_OP_SEND)
                    == sends_before_mismatch);
                REQUIRE(ninlil_runtime_destroy(receiver_runtime)
                    == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
                receiver_runtime = NULL;
                receiver_env.runtime = NULL;
            }
        }
        if (receiver_runtime == NULL) {
            REQUIRE(ninlil_runtime_create(
                        &receiver_config,
                        &env.platform,
                        &receiver_runtime) == NINLIL_OK);
            receiver_env.runtime = receiver_runtime;
            REQUIRE(configure_mfdt_owner_status(
                        receiver_runtime, 1u, cookie) == NINLIL_OK);
            receiver_service = NULL;
            REQUIRE(ninlil_service_register(
                        receiver_runtime,
                        &descriptor,
                        &callbacks,
                        &receiver_service) == NINLIL_OK);
        }
        for (step_index = 0u; step_index < 64u; ++step_index) {
            ninlil_bearer_message_t drained;
            ninlil_bearer_status_t receive_status;

            (void)memset(&drained, 0, sizeof(drained));
            receive_status = env.platform.bearer->receive_next(
                env.platform.bearer->user,
                env.runtime->bearer,
                &drained);
            if (receive_status == NINLIL_BEARER_EMPTY) {
                break;
            }
            REQUIRE(receive_status == NINLIL_BEARER_OK);
            env.platform.bearer->release_received(
                env.platform.bearer->user,
                env.runtime->bearer,
                &drained);
        }
        REQUIRE(step_index < 64u);
        callback_budget.max_bearer_sends = 1u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        REQUIRE(ninlil_runtime_step(
                    receiver_runtime, &callback_budget, &step_result)
            == NINLIL_OK);
        REQUIRE(step_result.callbacks_invoked == 0u);
        REQUIRE(step_result.bearer_sends == 1u);
        REQUIRE(capture.calls == 1u);
        transaction = ninlil_rt_find_transaction(
            receiver_runtime, &result.transaction_id);
        REQUIRE(transaction != NULL);
        REQUIRE(transaction->terminal == 1u);
        REQUIRE(transaction->outcome_recorded == 1u);
        REQUIRE(transaction->outcome == NINLIL_OUTCOME_SATISFIED);
        REQUIRE(transaction->reason ==
            NINLIL_REASON_REQUIRED_EVIDENCE_MET);
        REQUIRE(transaction->reverse_receipt_closed == 1u);
        REQUIRE(transaction->ingress_pending == 0u);
        REQUIRE(transaction->bound_targets[0].mfdt_target_ordinal == 0u);
        REQUIRE(mfdt_active_count_is(receiver_runtime, 1u));
        {
            ninlil_bearer_message_t receipt;

            (void)memset(&receipt, 0, sizeof(receipt));
            REQUIRE(env.platform.bearer->receive_next(
                        env.platform.bearer->user,
                        env.runtime->bearer,
                        &receipt) == NINLIL_BEARER_OK);
            REQUIRE(mfdt_receipt_is_exact(&receipt, &capture));
            env.platform.bearer->release_received(
                env.platform.bearer->user,
                env.runtime->bearer,
                &receipt);
        }

        /* Receipt closure is durable while MFDT content remains retained. */
        REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
        receiver_runtime = NULL;
        receiver_env.runtime = NULL;
        REQUIRE(raw_mfdt_row_present(&receiver_env, "NM3R", transfer_id));
        REQUIRE(ninlil_runtime_create(
                    &receiver_config,
                    &env.platform,
                    &receiver_runtime) == NINLIL_OK);
        receiver_env.runtime = receiver_runtime;
        REQUIRE(configure_mfdt_owner_status(
                    receiver_runtime, 1u, cookie) == NINLIL_OK);
        REQUIRE(mfdt_active_count_is(receiver_runtime, 1u));
        callback_budget.max_bearer_sends = 0u;
        if (case_index == 2u) {
            uint64_t terminal_commits;
            uint64_t terminal_puts;
            uint64_t terminal_erases;

            terminal_commits = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
            terminal_puts = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
            terminal_erases = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
            REQUIRE(step_runtime_status(
                        &receiver_env, 0u, &step_result) == NINLIL_OK);
            REQUIRE(step_result.more_work == 1u);
            REQUIRE(step_result.state_transitions == 0u);
            REQUIRE(step_result.callbacks_invoked == 0u);
            REQUIRE(step_result.bearer_sends == 0u);
            REQUIRE(mfdt_active_count_is(receiver_runtime, 1u));
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_COMMIT) == terminal_commits);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_PUT) == terminal_puts);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_ERASE) == terminal_erases);
            REQUIRE(ninlil_test_clock_advance(env.clock, 1u));
            REQUIRE(ninlil_test_storage_fault_next(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_IO_ERROR));
            REQUIRE(step_runtime_status(
                        &receiver_env, 0u, &step_result) ==
                NINLIL_E_STORAGE);
            REQUIRE(step_result.state_transitions == 0u);
            REQUIRE(step_result.callbacks_invoked == 0u);
            REQUIRE(step_result.bearer_sends == 0u);
            REQUIRE(mfdt_active_count_is(receiver_runtime, 1u));
            REQUIRE(ninlil_test_storage_fault_enqueue(
                env.storage_fixture,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN,
                1u,
                1,
                1));
            REQUIRE(step_runtime_status(
                        &receiver_env, 0u, &step_result) ==
                NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            REQUIRE(step_result.state_transitions == 0u);
            REQUIRE(step_result.callbacks_invoked == 0u);
            REQUIRE(step_result.bearer_sends == 0u);
            REQUIRE(receiver_runtime->commit_unknown_fence == 1u);
            REQUIRE(ninlil_runtime_destroy(receiver_runtime) ==
                NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        } else {
            REQUIRE(ninlil_runtime_step(
                        receiver_runtime,
                        &callback_budget,
                        &step_result) == NINLIL_OK);
            REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
        }
        receiver_runtime = NULL;
        receiver_env.runtime = NULL;
        REQUIRE(!raw_mfdt_row_present(
            &receiver_env, "NM3R", transfer_id));
        REQUIRE(raw_mfdt_row_present(&receiver_env, "NM30", transfer_id));
        REQUIRE(raw_mfdt_row_present(&receiver_env, "NRC1", transfer_id));

        if (case_index == 2u) {
            static const uint8_t terminal_digest_material[] =
                "retained-terminal-correlation-mismatch";
            uint8_t mismatched_digest[32];
            uint64_t terminal_commits;
            uint64_t terminal_puts;
            uint64_t terminal_erases;
            uint64_t terminal_sends;

            REQUIRE(ninlil_runtime_create(
                        &receiver_config,
                        &env.platform,
                        &receiver_runtime) == NINLIL_OK);
            receiver_env.runtime = receiver_runtime;
            transaction = ninlil_rt_find_transaction(
                receiver_runtime, &result.transaction_id);
            REQUIRE(transaction != NULL);
            ninlil_mfdt_v1_sha256(
                terminal_digest_material,
                sizeof(terminal_digest_material) - 1u,
                mismatched_digest);
            REQUIRE(memcmp(
                        mismatched_digest,
                        transaction->content_digest.bytes,
                        sizeof(mismatched_digest)) != 0);
            (void)memcpy(
                transaction->content_digest.bytes,
                mismatched_digest,
                sizeof(mismatched_digest));
            terminal_commits = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_COMMIT);
            terminal_puts = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_PUT);
            terminal_erases = ninlil_test_storage_call_count(
                env.storage_fixture, NINLIL_TEST_STORAGE_OP_ERASE);
            terminal_sends = ninlil_test_bearer_call_count(
                env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
            REQUIRE(configure_mfdt_owner_status(
                        receiver_runtime, 1u, cookie) ==
                NINLIL_E_STORAGE_CORRUPT);
            REQUIRE(receiver_runtime->commit_unknown_fence == 1u);
            REQUIRE(capture.calls == 1u);
            REQUIRE(transaction->receipt_pending == 0u);
            REQUIRE(transaction->reverse_receipt_closed == 1u);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_COMMIT) == terminal_commits);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_PUT) == terminal_puts);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_ERASE) == terminal_erases);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == terminal_sends);
            REQUIRE(step_runtime_status(
                        &receiver_env, 0u, &step_result) ==
                NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            REQUIRE(step_result.callbacks_invoked == 0u);
            REQUIRE(step_result.bearer_sends == 0u);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_COMMIT) == terminal_commits);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_PUT) == terminal_puts);
            REQUIRE(ninlil_test_storage_call_count(
                        env.storage_fixture,
                        NINLIL_TEST_STORAGE_OP_ERASE) == terminal_erases);
            REQUIRE(ninlil_test_bearer_call_count(
                        env.bearer_fixture,
                        NINLIL_TEST_BEARER_OP_SEND) == terminal_sends);
            REQUIRE(ninlil_runtime_destroy(receiver_runtime) ==
                NINLIL_E_STORAGE_COMMIT_UNKNOWN);
            receiver_runtime = NULL;
            receiver_env.runtime = NULL;
        }

        /* Retained terminal + exact Foundation closure is a cold no-op. */
        REQUIRE(ninlil_runtime_create(
                    &receiver_config,
                    &env.platform,
                    &receiver_runtime) == NINLIL_OK);
        receiver_env.runtime = receiver_runtime;
        REQUIRE(configure_mfdt_owner_status(
                    receiver_runtime, 1u, cookie) == NINLIL_OK);
        REQUIRE(mfdt_active_count_is(receiver_runtime, 0u));
        REQUIRE(ninlil_runtime_step(
                    receiver_runtime,
                    &callback_budget,
                    &step_result) == NINLIL_OK);
        REQUIRE(step_result.callbacks_invoked == 0u);
        REQUIRE(step_result.bearer_sends == 0u);
        REQUIRE(ninlil_runtime_destroy(receiver_runtime) == NINLIL_OK);
        receiver_runtime = NULL;
        receiver_env.runtime = NULL;
        platform_teardown(&env);
    }
    return 0;
}
#endif

static int test_simulated_bearer_loss_injection(void)
{
    cap_env_t env;
    ninlil_id128_t runtime_id;
    ninlil_bearer_handle_t handle = NULL;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    set_id(&runtime_id, 0x10u);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &runtime_id,
                NINLIL_ROLE_CONTROLLER,
                &handle)
        == NINLIL_BEARER_OK);
    REQUIRE(ninlil_test_bearer_set_path_up(env.bearer_fixture, &runtime_id, 0));
    ninlil_bearer_send_result_t raw_result;

    (void)memset(&raw_result, 0, sizeof(raw_result));
    set_header(
        &raw_result.abi_version, &raw_result.struct_size, sizeof(raw_result));
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(
        env.bearer_fixture, NINLIL_BEARER_WOULD_BLOCK, &raw_result, 1u));
    REQUIRE(ninlil_test_bearer_set_path_up(env.bearer_fixture, &runtime_id, 1));
    (void)env.platform.bearer->close(env.platform.bearer->user, handle);
    platform_teardown(&env);
    return 0;
}

static int test_retry_budget_exhaustion(void)
{
    cap_env_t env;
    ninlil_submission_result_t submit_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    static const uint8_t idem_retry[] = "retry-idem";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x76u));
    (void)memset(&submit_result, 0, sizeof(submit_result));
    REQUIRE(submit_with_payload(
        &env, 16u, 100u, 0x28u, idem_retry, sizeof(idem_retry) - 1u, &submit_result));
    REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_test_clock_advance(env.clock, 200u));
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_state_transitions = 32u;
    (void)memset(&step_result, 0, sizeof(step_result));
    set_header(
        &step_result.abi_version,
        &step_result.struct_size,
        sizeof(step_result));
    REQUIRE(ninlil_runtime_step(env.runtime, &budget, &step_result) == NINLIL_OK);
    platform_teardown(&env);
    return 0;
}

static int test_retry_and_dedup_profile_boundaries(void)
{
    cap_env_t env;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service = NULL;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));

    descriptor = desired_descriptor(0x8au);
    descriptor.required_dedup_window_ms =
        env.config.result_cache_retention_ms;
    /*
     * TRACE-INV010-RETRY-BOUNDARY
     * The profile's exact attempt limit is accepted; limit+1 is rejected.
     */
    REQUIRE(descriptor.max_attempts_per_target_per_cycle
        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &service)
        == NINLIL_OK);
    REQUIRE(service != NULL);

    descriptor = desired_descriptor(0x8bu);
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE + 1u;
    service = NULL;
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &service)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(service == NULL);

    /*
     * TRACE-INV010-DEDUP-BOUNDARY
     * The retained result-cache window is the exact supported dedup bound;
     * requesting one millisecond beyond that bound is rejected.
     */
    descriptor = desired_descriptor(0x8cu);
    descriptor.required_dedup_window_ms =
        env.config.result_cache_retention_ms + 1u;
    service = NULL;
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &service)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(service == NULL);

    platform_teardown(&env);
    return 0;
}

static int test_public_runtime_role_environment_matrix(void)
{
    static const ninlil_role_t roles[] = {
        NINLIL_ROLE_CONTROLLER,
        NINLIL_ROLE_ENDPOINT,
        NINLIL_ROLE_CELL_AGENT
    };
    static const ninlil_environment_t environments[] = {
        NINLIL_ENV_TEST,
        NINLIL_ENV_LAB,
        NINLIL_ENV_FIELD,
        NINLIL_ENV_PRODUCTION
    };
    uint32_t role_index;
    uint32_t environment_index;

    for (role_index = 0u;
         role_index < sizeof(roles) / sizeof(roles[0]);
         ++role_index) {
        for (environment_index = 0u;
             environment_index
                < sizeof(environments) / sizeof(environments[0]);
             ++environment_index) {
            cap_env_t env;
            ninlil_service_descriptor_t descriptor;
            ninlil_service_callbacks_t callbacks;
            ninlil_service_t *service = NULL;
            ninlil_status_t create_status;

            (void)memset(&env, 0, sizeof(env));
            REQUIRE(platform_init(&env));
            env.config = config_controller(4u);
            env.config.role = roles[role_index];
            env.config.environment = environments[environment_index];
            if (env.config.role != NINLIL_ROLE_CONTROLLER) {
                env.config.limits.max_durable_outbox_payload_bytes = 0u;
            }
            if (env.config.role == NINLIL_ROLE_ENDPOINT) {
                env.config.limits.max_event_spool_count = 4u;
                env.config.limits.max_event_spool_bytes = 32768u;
            }
            create_status = ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime);
            if (create_status != NINLIL_OK) {
                (void)fprintf(stderr,
                    "role/environment create failed: role=%u env=%u status=%u\n",
                    (unsigned)roles[role_index],
                    (unsigned)environments[environment_index],
                    (unsigned)create_status);
            }
            REQUIRE(create_status == NINLIL_OK);
            if (env.config.role == NINLIL_ROLE_CELL_AGENT) {
                descriptor = desired_descriptor(0x9au);
                (void)memset(&callbacks, 0, sizeof(callbacks));
                set_header(
                    &callbacks.abi_version,
                    &callbacks.struct_size,
                    sizeof(callbacks));
                REQUIRE(ninlil_service_register(
                            env.runtime,
                            &descriptor,
                            &callbacks,
                            &service)
                    == NINLIL_E_UNSUPPORTED);
                REQUIRE(service == NULL);
            }
            platform_teardown(&env);
        }
    }
    return 0;
}

static void fill_exact_target(
    ninlil_concrete_target_t *target,
    uint8_t runtime_tag,
    uint8_t application_tag)
{
    (void)memset(target, 0, sizeof(*target));
    set_header(
        &target->abi_version, &target->struct_size, sizeof(*target));
    set_id(&target->target_runtime_id, runtime_tag);
    set_id(&target->target_application_instance_id, application_tag);
}

static int submit_exact_roster(
    cap_env_t *env,
    const ninlil_concrete_target_t *targets,
    uint32_t target_count,
    const uint8_t *idempotency_key,
    uint32_t idempotency_length,
    ninlil_submission_result_t *out_result)
{
    static const uint8_t payload[] = {0x31u, 0x32u, 0x33u};
    ninlil_submission_t submission;

    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = targets;
    submission.target_count = target_count;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = 5000u;
    submission.evidence_grace_ms = 1000u;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length = idempotency_length;
    submission.generation = 1u;
    submission.payload.data = payload;
    submission.payload.length = sizeof(payload);
    if (!set_payload_content_digest(
            &submission.content_digest, payload, sizeof(payload))) {
        return 0;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    return ninlil_submit(env->service, &submission, out_result)
        == NINLIL_OK;
}

static void fill_step_budget(
    ninlil_step_budget_t *budget,
    uint32_t max_bearer_sends)
{
    (void)memset(budget, 0, sizeof(*budget));
    set_header(&budget->abi_version, &budget->struct_size, sizeof(*budget));
    budget->max_ingress_messages = 4u;
    budget->max_callbacks = 0u;
    budget->max_state_transitions = 16u;
    budget->max_bearer_sends = max_bearer_sends;
}

static ninlil_status_t step_runtime_status(
    cap_env_t *env,
    uint32_t max_bearer_sends,
    ninlil_step_result_t *out_result);

static int step_runtime(
    cap_env_t *env,
    uint32_t max_bearer_sends,
    ninlil_step_result_t *out_result)
{
    ninlil_status_t status = step_runtime_status(
        env, max_bearer_sends, out_result);

    if (status != NINLIL_OK) {
        (void)fprintf(stderr,
            "runtime step failed: status=%u sends=%u ingress=%u "
            "transitions=%u health=%u reason=%u\n",
            (unsigned)status,
            (unsigned)max_bearer_sends,
            (unsigned)out_result->ingress_processed,
            (unsigned)out_result->state_transitions,
            (unsigned)out_result->health,
            (unsigned)out_result->degraded_reason);
    }
    return status == NINLIL_OK;
}

static ninlil_status_t step_runtime_status(
    cap_env_t *env,
    uint32_t max_bearer_sends,
    ninlil_step_result_t *out_result)
{
    ninlil_step_budget_t budget;

    fill_step_budget(&budget, max_bearer_sends);
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    return ninlil_runtime_step(env->runtime, &budget, out_result);
}

static void make_receipt_from_application(
    const ninlil_bearer_message_t *application,
    ninlil_bearer_message_t *receipt)
{
    (void)memset(receipt, 0, sizeof(*receipt));
    set_header(
        &receipt->abi_version, &receipt->struct_size, sizeof(*receipt));
    receipt->kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    receipt->transaction_id = application->transaction_id;
    receipt->attempt_id = application->attempt_id;
    receipt->event_id = application->event_id;
    receipt->service = application->service;
    receipt->content_digest = application->content_digest;
    receipt->generation = application->generation;
    receipt->deadline_clock_epoch_id =
        application->deadline_clock_epoch_id;
    receipt->absolute_effect_deadline_ms =
        application->absolute_effect_deadline_ms;
    receipt->evidence_grace_ms = application->evidence_grace_ms;
    receipt->required_evidence = application->required_evidence;
    receipt->receipt_stage = application->required_evidence;
    receipt->retry_guidance = NINLIL_RETRY_NEVER;

    set_header(
        &receipt->source.abi_version,
        &receipt->source.struct_size,
        sizeof(receipt->source));
    receipt->source.runtime_id =
        application->target.target_runtime_id;
    receipt->source.application_instance_id =
        application->target.target_application_instance_id;
    set_header(
        &receipt->source.local_identity.abi_version,
        &receipt->source.local_identity.struct_size,
        sizeof(receipt->source.local_identity));
    receipt->source.local_identity.device_id =
        application->target.device_id;
    receipt->source.local_identity.installation_id =
        application->target.installation_id;
    receipt->source.local_identity.site_domain_id =
        application->target.site_domain_id;
    receipt->source.local_identity.binding_epoch =
        application->target.binding_epoch;
    receipt->source.local_identity.membership_epoch =
        application->target.membership_epoch;
    receipt->source.local_identity.flags = application->target.flags;

    set_header(
        &receipt->target.abi_version,
        &receipt->target.struct_size,
        sizeof(receipt->target));
    receipt->target.target_runtime_id =
        application->source.runtime_id;
    receipt->target.target_application_instance_id =
        application->source.application_instance_id;
    receipt->target.device_id =
        application->source.local_identity.device_id;
    receipt->target.installation_id =
        application->source.local_identity.installation_id;
    receipt->target.site_domain_id =
        application->source.local_identity.site_domain_id;
    receipt->target.binding_epoch =
        application->source.local_identity.binding_epoch;
    receipt->target.membership_epoch =
        application->source.local_identity.membership_epoch;
    receipt->target.flags = application->source.local_identity.flags;

    set_header(
        &receipt->evidence_time.abi_version,
        &receipt->evidence_time.struct_size,
        sizeof(receipt->evidence_time));
    receipt->evidence_time.clock_epoch_id =
        application->deadline_clock_epoch_id;
    receipt->evidence_time.now_ms = 1u;
    receipt->evidence_time.trust = NINLIL_CLOCK_TRUSTED;
}

static void set_receipt_source_from_target(
    ninlil_bearer_message_t *receipt,
    const ninlil_concrete_target_t *target)
{
    set_header(
        &receipt->source.abi_version,
        &receipt->source.struct_size,
        sizeof(receipt->source));
    receipt->source.runtime_id = target->target_runtime_id;
    receipt->source.application_instance_id =
        target->target_application_instance_id;
    set_header(
        &receipt->source.local_identity.abi_version,
        &receipt->source.local_identity.struct_size,
        sizeof(receipt->source.local_identity));
    receipt->source.local_identity.device_id = target->device_id;
    receipt->source.local_identity.installation_id =
        target->installation_id;
    receipt->source.local_identity.site_domain_id =
        target->site_domain_id;
    receipt->source.local_identity.binding_epoch =
        target->binding_epoch;
    receipt->source.local_identity.membership_epoch =
        target->membership_epoch;
    receipt->source.local_identity.flags = target->flags;
}

static int receive_application_after_steps(
    cap_env_t *env,
    ninlil_bearer_handle_t peer,
    ninlil_bearer_message_t *out_message)
{
    uint32_t attempt;

    for (attempt = 0u; attempt < 8u; ++attempt) {
        ninlil_step_result_t step_result;
        ninlil_bearer_status_t receive_status;

        if (!step_runtime(env, 1u, &step_result)) {
            return 0;
        }
        (void)memset(out_message, 0, sizeof(*out_message));
        receive_status = env->platform.bearer->receive_next(
            env->platform.bearer->user, peer, out_message);
        if (receive_status == NINLIL_BEARER_OK) {
            return out_message->kind == NINLIL_BEARER_MESSAGE_APPLICATION;
        }
        if (receive_status != NINLIL_BEARER_EMPTY) {
            return 0;
        }
    }
    return 0;
}

static int test_two_exact_targets_admission_restart_query_and_list(void)
{
    static const uint8_t idem[] = "two-exact-targets";
    cap_env_t env;
    ninlil_concrete_target_t targets[2];
    ninlil_concrete_target_t original_targets[2];
    ninlil_concrete_target_t reordered_targets[2];
    ninlil_concrete_target_t conflict_targets[2];
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_result_t admitted;
    ninlil_submission_result_t duplicate;
    ninlil_submission_result_t conflict;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target_snapshots[2];
    ninlil_target_snapshot_t target_sentinel;
    ninlil_query_t query;
    ninlil_transaction_page_t page;
    ninlil_transaction_summary_t item;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_targets_per_transaction = 4u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(0x9bu);
    descriptor.target_limit = 4u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    /* Reverse caller order proves canonical roster storage. */
    fill_exact_target(&targets[0], 0x30u, 0x70u);
    fill_exact_target(&targets[1], 0x20u, 0x60u);
    original_targets[0] = targets[0];
    original_targets[1] = targets[1];
    REQUIRE(submit_exact_roster(
        &env, targets, 2u, idem, sizeof(idem) - 1u, &admitted));
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(submit_exact_roster(
        &env, targets, 2u, idem, sizeof(idem) - 1u, &duplicate));
    REQUIRE(duplicate.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
    REQUIRE(memcmp(
        duplicate.transaction_id.bytes,
        admitted.transaction_id.bytes,
        sizeof(admitted.transaction_id.bytes)) == 0);
    reordered_targets[0] = targets[1];
    reordered_targets[1] = targets[0];
    REQUIRE(submit_exact_roster(
        &env,
        reordered_targets,
        2u,
        idem,
        sizeof(idem) - 1u,
        &duplicate));
    REQUIRE(duplicate.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
    REQUIRE(memcmp(
        duplicate.transaction_id.bytes,
        admitted.transaction_id.bytes,
        sizeof(admitted.transaction_id.bytes)) == 0);

    conflict_targets[0] = targets[0];
    conflict_targets[1] = targets[1];
    set_id(&conflict_targets[0].target_runtime_id, 0x40u);
    REQUIRE(submit_exact_roster(
        &env,
        conflict_targets,
        2u,
        idem,
        sizeof(idem) - 1u,
        &conflict));
    REQUIRE(conflict.kind == NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT);
    (void)memset(targets, 0xa5, sizeof(targets));

    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    (void)memset(target_snapshots, 0xa5, sizeof(target_snapshots));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    target_sentinel = target_snapshots[0];
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 1u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(snapshot.target_count == 2u);
    REQUIRE(memcmp(
        &target_snapshots[0],
        &target_sentinel,
        sizeof(target_sentinel)) == 0);

    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.target_count == 2u);
    REQUIRE(target_snapshots[0].target.target_runtime_id.bytes[0] == 0x20u);
    REQUIRE(target_snapshots[1].target.target_runtime_id.bytes[0] == 0x30u);

    (void)memset(&query, 0, sizeof(query));
    set_header(&query.abi_version, &query.struct_size, sizeof(query));
    query.include_nonterminal = 1u;
    (void)memset(&page, 0, sizeof(page));
    set_header(&page.abi_version, &page.struct_size, sizeof(page));
    (void)memset(&item, 0, sizeof(item));
    set_header(&item.abi_version, &item.struct_size, sizeof(item));
    page.items = &item;
    page.item_capacity = 1u;
    REQUIRE(ninlil_transaction_list(env.runtime, &query, &page)
        == NINLIL_OK);
    REQUIRE(page.item_count == 1u);
    REQUIRE(memcmp(
        item.transaction_id.bytes,
        admitted.transaction_id.bytes,
        sizeof(item.transaction_id.bytes)) == 0);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    {
        ninlil_status_t restart_status = ninlil_runtime_create(
            &env.config, &env.platform, &env.runtime);
        if (restart_status != NINLIL_OK) {
            (void)fprintf(stderr,
                "two-target restart failed: status=%u\n",
                (unsigned)restart_status);
        }
        REQUIRE(restart_status == NINLIL_OK);
    }
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.target_count == 2u);
    REQUIRE(submit_exact_roster(
        &env,
        original_targets,
        2u,
        idem,
        sizeof(idem) - 1u,
        &duplicate));
    REQUIRE(duplicate.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);

    platform_teardown(&env);
    return 0;
}

static int test_target_snapshot_future_stride_and_nonmutation(void)
{
    static const uint8_t idem[] = "future-target-stride";
    cap_env_t env;
    ninlil_concrete_target_t targets[2];
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_result_t admitted;
    ninlil_transaction_snapshot_t snapshot;
    future_target_snapshot_t future[4];
    future_target_snapshot_t before[4];
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_targets_per_transaction = 4u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(0x9fu);
    descriptor.target_limit = 4u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    fill_exact_target(&targets[0], 0x33u, 0x73u);
    fill_exact_target(&targets[1], 0x22u, 0x62u);
    REQUIRE(submit_exact_roster(
        &env, targets, 2u, idem, sizeof(idem) - 1u, &admitted));
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    /*
     * Capacity one is a valid future-sized array. BUFFER_TOO_SMALL reports
     * only required target_count and does not touch any target prefix/tail.
     */
    (void)memset(future, 0xa5, sizeof(future));
    for (index = 0u; index < 4u; ++index) {
        set_header(
            &future[index].known.abi_version,
            &future[index].known.struct_size,
            sizeof(future[index]));
    }
    (void)memcpy(before, future, sizeof(before));
    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.targets = &future[0].known;
    snapshot.target_capacity = 1u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(snapshot.target_count == 2u);
    REQUIRE(memcmp(future, before, sizeof(future)) == 0);

    /*
     * Two future-sized elements prove that the second element is reached by
     * first.struct_size, not by sizeof(the library's known prefix).
     */
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.targets = &future[0].known;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.target_count == 2u);
    REQUIRE(
        future[0].known.target.target_runtime_id.bytes[0] == 0x22u);
    REQUIRE(
        future[1].known.target.target_runtime_id.bytes[0] == 0x33u);
    REQUIRE(memcmp(
        future[0].future_tail,
        before[0].future_tail,
        sizeof(future[0].future_tail)) == 0);
    REQUIRE(memcmp(
        future[1].future_tail,
        before[1].future_tail,
        sizeof(future[1].future_tail)) == 0);

    /*
     * Capacity four validates all four headers, writes only the two returned
     * elements, preserves every future tail, and leaves surplus elements
     * byte-for-byte unchanged.
     */
    (void)memset(future, 0x5a, sizeof(future));
    for (index = 0u; index < 4u; ++index) {
        set_header(
            &future[index].known.abi_version,
            &future[index].known.struct_size,
            sizeof(future[index]));
    }
    (void)memcpy(before, future, sizeof(before));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.targets = &future[0].known;
    snapshot.target_capacity = 4u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.target_count == 2u);
    for (index = 0u; index < 2u; ++index) {
        REQUIRE(memcmp(
            future[index].future_tail,
            before[index].future_tail,
            sizeof(future[index].future_tail)) == 0);
    }
    REQUIRE(memcmp(&future[2], &before[2], sizeof(future[2])) == 0);
    REQUIRE(memcmp(&future[3], &before[3], sizeof(future[3])) == 0);

    /*
     * Mixed element sizes are not an alternate stride description. Reject
     * before any target element is projected.
     */
    (void)memset(future, 0x3c, sizeof(future));
    for (index = 0u; index < 4u; ++index) {
        set_header(
            &future[index].known.abi_version,
            &future[index].known.struct_size,
            sizeof(future[index]));
    }
    future[2].known.struct_size =
        (uint16_t)sizeof(ninlil_target_snapshot_t);
    (void)memcpy(before, future, sizeof(before));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.targets = &future[0].known;
    snapshot.target_capacity = 4u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_E_ABI_MISMATCH);
    REQUIRE(memcmp(future, before, sizeof(future)) == 0);

    platform_teardown(&env);
    return 0;
}

static const ninlil_model_capacity_entry_t *ledger_entry(
    const ninlil_model_resource_ledger_t *ledger,
    ninlil_resource_kind_t kind)
{
    uint32_t index;

    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        if (ledger->entries[index].kind == kind) {
            return &ledger->entries[index];
        }
    }
    return NULL;
}

static int test_four_exact_targets_atomic_completion_and_restart(void)
{
    static const uint8_t idem[] = "four-target-public-e2e";
    cap_env_t env;
    ninlil_concrete_target_t targets[4];
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_result_t admitted;
    ninlil_bearer_handle_t peer = NULL;
    ninlil_step_result_t step_result;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t projected[4];
    ninlil_target_snapshot_t before_small[3];
    ninlil_rt_transaction_slot_t *transaction;
    const ninlil_model_capacity_entry_t *target_capacity;
    const ninlil_model_capacity_entry_t *evidence_capacity;
    uint32_t completed;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_targets_per_transaction = 4u;
    env.config.limits.max_evidence_per_target = 8u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(0xa1u);
    descriptor.target_limit = 4u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);

    /* Reverse order; all four services live behind the same remote Runtime. */
    fill_exact_target(&targets[0], 0x24u, 0x84u);
    fill_exact_target(&targets[1], 0x24u, 0x54u);
    fill_exact_target(&targets[2], 0x24u, 0x74u);
    fill_exact_target(&targets[3], 0x24u, 0x64u);
    REQUIRE(submit_exact_roster(
        &env, targets, 4u, idem, sizeof(idem) - 1u, &admitted));
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->bound_target_count == 4u);
    REQUIRE(transaction->reservation_evidence_units == 36u);
    target_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_TARGET);
    evidence_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_EVIDENCE);
    REQUIRE(target_capacity != NULL);
    REQUIRE(evidence_capacity != NULL);
    REQUIRE(target_capacity->used == 4u);
    REQUIRE(target_capacity->reserved == 0u);
    REQUIRE(evidence_capacity->used == 4u);
    REQUIRE(evidence_capacity->reserved == 32u);

    /* Admission owns the roster; caller destruction cannot alter projection. */
    (void)memset(targets, 0xa5, sizeof(targets));
    (void)memset(projected, 0x5a, sizeof(projected));
    for (index = 0u; index < 4u; ++index) {
        set_header(
            &projected[index].abi_version,
            &projected[index].struct_size,
            sizeof(projected[index]));
    }
    (void)memcpy(before_small, projected, sizeof(before_small));
    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    snapshot.targets = projected;
    snapshot.target_capacity = 3u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(snapshot.target_count == 4u);
    REQUIRE(memcmp(projected, before_small, sizeof(before_small)) == 0);

    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &transaction->bound_targets[0].target.target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);

    for (completed = 0u; completed < 4u; ++completed) {
        ninlil_bearer_message_t application;
        ninlil_bearer_message_t receipt;
        uint32_t satisfied = 0u;

        REQUIRE(receive_application_after_steps(
            &env, peer, &application));
        make_receipt_from_application(&application, &receipt);
        env.platform.bearer->release_received(
            env.platform.bearer->user, peer, &application);
        REQUIRE(ninlil_test_bearer_deliver_to_runtime(
            env.bearer_fixture, &env.config.runtime_id, &receipt));
        REQUIRE(step_runtime(&env, 0u, &step_result));
        REQUIRE(step_runtime(&env, 0u, &step_result));

        (void)memset(&snapshot, 0, sizeof(snapshot));
        set_header(
            &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
        (void)memset(projected, 0, sizeof(projected));
        for (index = 0u; index < 4u; ++index) {
            set_header(
                &projected[index].abi_version,
                &projected[index].struct_size,
                sizeof(projected[index]));
        }
        snapshot.targets = projected;
        snapshot.target_capacity = 4u;
        REQUIRE(ninlil_transaction_query(
                    env.runtime, &admitted.transaction_id, &snapshot)
            == NINLIL_OK);
        REQUIRE(snapshot.target_count == 4u);
        for (index = 0u; index < 4u; ++index) {
            if (projected[index].outcome == NINLIL_OUTCOME_SATISFIED) {
                satisfied += 1u;
                REQUIRE(projected[index].valid_evidence_count == 1u);
            } else {
                REQUIRE(projected[index].outcome == NINLIL_OUTCOME_NONE);
                REQUIRE(projected[index].valid_evidence_count == 0u);
            }
        }
        REQUIRE(satisfied == completed + 1u);
        if (completed + 1u < 4u) {
            REQUIRE(snapshot.state != NINLIL_TXN_TERMINAL);
        }
    }
    REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_SATISFIED);
    for (index = 0u; index < 4u; ++index) {
        REQUIRE(projected[index].cumulative_attempts == 1u);
    }

    target_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_TARGET);
    evidence_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_EVIDENCE);
    REQUIRE(target_capacity != NULL && target_capacity->used == 4u);
    REQUIRE(evidence_capacity != NULL && evidence_capacity->used == 8u);
    REQUIRE(evidence_capacity->reserved == 28u);

    env.platform.bearer->close(
        env.platform.bearer->user, peer);
    peer = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    (void)memset(projected, 0, sizeof(projected));
    for (index = 0u; index < 4u; ++index) {
        set_header(
            &projected[index].abi_version,
            &projected[index].struct_size,
            sizeof(projected[index]));
    }
    snapshot.targets = projected;
    snapshot.target_capacity = 4u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_SATISFIED);
    for (index = 0u; index < 4u; ++index) {
        REQUIRE(projected[index].cumulative_attempts == 1u);
        REQUIRE(projected[index].outcome == NINLIL_OUTCOME_SATISFIED);
    }
    target_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_TARGET);
    evidence_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_EVIDENCE);
    REQUIRE(target_capacity != NULL && target_capacity->used == 4u);
    REQUIRE(evidence_capacity != NULL && evidence_capacity->used == 8u);
    REQUIRE(evidence_capacity->reserved == 28u);

    platform_teardown(&env);
    return 0;
}

static int test_four_exact_targets_retry_exhaustion_and_restart(void)
{
    static const uint8_t idem[] = "four-target-retry-exhaustion";
    cap_env_t env;
    ninlil_concrete_target_t targets[4];
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_result_t admitted;
    ninlil_bearer_handle_t peer = NULL;
    ninlil_bearer_send_result_t no_send;
    ninlil_bearer_state_t bearer_state;
    ninlil_id128_t bearer_clock_epoch;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t projected[4];
    ninlil_rt_transaction_slot_t *transaction;
    const ninlil_model_capacity_entry_t *target_capacity;
    const ninlil_model_capacity_entry_t *evidence_capacity;
    const ninlil_model_capacity_entry_t *outbox_capacity;
    uint64_t sends_before;
    uint64_t sends_after;
    uint32_t turn;
    uint32_t index;
    int terminal = 0;

    (void)memset(&env, 0, sizeof(env));
    (void)memset(&bearer_clock_epoch, 0, sizeof(bearer_clock_epoch));
    bearer_clock_epoch.bytes[0] = 0xa0u;
    bearer_clock_epoch.bytes[15] = 0x01u;
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_targets_per_transaction = 4u;
    env.config.limits.max_evidence_per_target = 8u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(0xa2u);
    descriptor.target_limit = 4u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);

    fill_exact_target(&targets[0], 0x25u, 0x85u);
    fill_exact_target(&targets[1], 0x25u, 0x55u);
    fill_exact_target(&targets[2], 0x25u, 0x75u);
    fill_exact_target(&targets[3], 0x25u, 0x65u);
    REQUIRE(submit_exact_roster(
        &env, targets, 4u, idem, sizeof(idem) - 1u, &admitted));
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &targets[0].target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);

    /*
     * A valid definite-no-send observation consumes an attempt but never
     * queues APPLICATION bytes. Forty scripted observations leave headroom
     * beyond the expected 4 targets * 8 attempts and prove that terminal
     * exhaustion, not fixture depletion, stops sending.
     */
    (void)memset(&no_send, 0, sizeof(no_send));
    set_header(
        &no_send.abi_version, &no_send.struct_size, sizeof(no_send));
    (void)memset(&bearer_state, 0, sizeof(bearer_state));
    REQUIRE(env.platform.bearer->state(
                env.platform.bearer->user,
                env.runtime->bearer,
                &bearer_state)
        == NINLIL_BEARER_OK);
    no_send.availability_epoch = bearer_state.availability_epoch;
    REQUIRE(ninlil_test_bearer_raw_send_enqueue(
        env.bearer_fixture,
        NINLIL_BEARER_WOULD_BLOCK,
        &no_send,
        40u));
    sends_before = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);

    for (turn = 0u; turn < 80u; ++turn) {
        ninlil_step_result_t step_result;
        uint64_t cumulative = 0u;
        uint32_t attempted_targets = 0u;

        REQUIRE(step_runtime(&env, 1u, &step_result));
        (void)memset(&snapshot, 0, sizeof(snapshot));
        set_header(
            &snapshot.abi_version,
            &snapshot.struct_size,
            sizeof(snapshot));
        (void)memset(projected, 0, sizeof(projected));
        for (index = 0u; index < 4u; ++index) {
            set_header(
                &projected[index].abi_version,
                &projected[index].struct_size,
                sizeof(projected[index]));
        }
        snapshot.targets = projected;
        snapshot.target_capacity = 4u;
        REQUIRE(ninlil_transaction_query(
                    env.runtime, &admitted.transaction_id, &snapshot)
            == NINLIL_OK);
        for (index = 0u; index < 4u; ++index) {
            REQUIRE(projected[index].cumulative_attempts
                <= NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
            cumulative += projected[index].cumulative_attempts;
            if (projected[index].cumulative_attempts != 0u) {
                attempted_targets += 1u;
            }
        }
        if (cumulative == 1u) {
            REQUIRE(attempted_targets == 1u);
        }
        if (snapshot.state == NINLIL_TXN_TERMINAL) {
            terminal = 1;
            break;
        }
        REQUIRE(ninlil_test_clock_advance(env.clock, 50u));
        REQUIRE(ninlil_test_bearer_set_time(
            env.bearer_fixture,
            bearer_clock_epoch,
            (uint64_t)(turn + 1u) * 50u));
    }
    REQUIRE(terminal);
    sends_after = ninlil_test_bearer_call_count(
        env.bearer_fixture, NINLIL_TEST_BEARER_OP_SEND);
    REQUIRE(sends_after - sends_before
        == (uint64_t)4u * NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_FAILED_DEFINITIVE);
    REQUIRE(snapshot.reason
        == NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT);
    for (index = 0u; index < 4u; ++index) {
        REQUIRE(projected[index].outcome
            == NINLIL_OUTCOME_FAILED_DEFINITIVE);
        REQUIRE(projected[index].reason
            == NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT);
        REQUIRE(projected[index].cumulative_attempts
            == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    }
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL && transaction->reservation_active == 0u);

    target_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_TARGET);
    evidence_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_EVIDENCE);
    outbox_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_OUTBOX_BYTES);
    REQUIRE(target_capacity != NULL && target_capacity->used == 4u);
    REQUIRE(target_capacity->reserved == 0u);
    REQUIRE(evidence_capacity != NULL && evidence_capacity->used == 4u);
    REQUIRE(evidence_capacity->reserved == 32u);
    REQUIRE(outbox_capacity != NULL && outbox_capacity->used == 0u);
    REQUIRE(outbox_capacity->reserved == 0u);

    env.platform.bearer->close(
        env.platform.bearer->user, peer);
    peer = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);

    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    (void)memset(projected, 0, sizeof(projected));
    for (index = 0u; index < 4u; ++index) {
        set_header(
            &projected[index].abi_version,
            &projected[index].struct_size,
            sizeof(projected[index]));
    }
    snapshot.targets = projected;
    snapshot.target_capacity = 4u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_FAILED_DEFINITIVE);
    for (index = 0u; index < 4u; ++index) {
        REQUIRE(projected[index].cumulative_attempts
            == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
        REQUIRE(projected[index].outcome
            == NINLIL_OUTCOME_FAILED_DEFINITIVE);
    }
    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL && transaction->reservation_active == 0u);
    target_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_TARGET);
    evidence_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_EVIDENCE);
    outbox_capacity = ledger_entry(
        &env.runtime->resource_ledger, NINLIL_RESOURCE_OUTBOX_BYTES);
    REQUIRE(target_capacity != NULL && target_capacity->used == 4u);
    REQUIRE(target_capacity->reserved == 0u);
    REQUIRE(evidence_capacity != NULL && evidence_capacity->used == 4u);
    REQUIRE(evidence_capacity->reserved == 32u);
    REQUIRE(outbox_capacity != NULL && outbox_capacity->used == 0u);
    REQUIRE(outbox_capacity->reserved == 0u);

    platform_teardown(&env);
    return 0;
}

typedef enum evidence_counter_case {
    EVIDENCE_COUNTER_VALID = 1,
    EVIDENCE_COUNTER_DUPLICATE = 2,
    EVIDENCE_COUNTER_RAW_OVERFLOW = 3,
    EVIDENCE_COUNTER_LATE = 4
} evidence_counter_case_t;

static int project_single_target(
    cap_env_t *env,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *out_snapshot,
    ninlil_target_snapshot_t *out_target)
{
    (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
    set_header(
        &out_snapshot->abi_version,
        &out_snapshot->struct_size,
        sizeof(*out_snapshot));
    (void)memset(out_target, 0, sizeof(*out_target));
    set_header(
        &out_target->abi_version,
        &out_target->struct_size,
        sizeof(*out_target));
    out_snapshot->targets = out_target;
    out_snapshot->target_capacity = 1u;
    return ninlil_transaction_query(
        env->runtime, transaction_id, out_snapshot) == NINLIL_OK;
}

static int run_evidence_counter_saturation_case(
    evidence_counter_case_t counter_case)
{
    static const uint8_t case_keys[][24] = {
        "counter-unused",
        "counter-valid",
        "counter-duplicate",
        "counter-overflow",
        "counter-late"
    };
    cap_env_t env;
    ninlil_concrete_target_t target;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_result_t admitted;
    ninlil_bearer_handle_t peer = NULL;
    ninlil_bearer_message_t application;
    ninlil_bearer_message_t receipt;
    ninlil_step_result_t step_result;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t candidate;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t projected;
    uint8_t evidence[3] = {0x41u, 0x42u, 0x43u};
    uint64_t expected_before_restart;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_targets_per_transaction = 1u;
    env.config.limits.max_evidence_per_target = 1u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(
        (uint8_t)(0xb0u + (uint8_t)counter_case));
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    fill_exact_target(
        &target,
        0x25u,
        (uint8_t)(0x50u + (uint8_t)counter_case));
    REQUIRE(submit_exact_roster(
        &env,
        &target,
        1u,
        case_keys[counter_case],
        (uint32_t)strlen((const char *)case_keys[counter_case]),
        &admitted));
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &target.target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);
    REQUIRE(receive_application_after_steps(&env, peer, &application));
    make_receipt_from_application(&application, &receipt);
    receipt.receipt_stage = NINLIL_EVIDENCE_APPLIED;
    receipt.evidence.data = &evidence[0];
    receipt.evidence.length = 1u;
    env.platform.bearer->release_received(
        env.platform.bearer->user, peer, &application);
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));

    transaction = ninlil_rt_find_transaction(
        env.runtime, &admitted.transaction_id);
    REQUIRE(transaction != NULL);
    candidate = *transaction;
    candidate.bound_targets[0].evidence_counter_saturated = 0u;
    switch (counter_case) {
    case EVIDENCE_COUNTER_VALID:
        candidate.bound_targets[0].valid_evidence_count =
            UINT64_MAX - 1u;
        break;
    case EVIDENCE_COUNTER_DUPLICATE:
        candidate.bound_targets[0].duplicate_evidence_count =
            UINT64_MAX - 1u;
        break;
    case EVIDENCE_COUNTER_RAW_OVERFLOW:
        candidate.bound_targets[0].raw_evidence_overflow_count =
            UINT64_MAX - 1u;
        break;
    case EVIDENCE_COUNTER_LATE:
        candidate.bound_targets[0].has_late_evidence = 1u;
        candidate.bound_targets[0].late_evidence_count =
            UINT64_MAX - 1u;
        candidate.has_late_evidence = 1u;
        break;
    default:
        return 1;
    }
    REQUIRE(ninlil_rt_v1_commit_transaction_snapshot(
                env.runtime,
                transaction,
                &candidate,
                0x4556u,
                NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT)
        == NINLIL_OK);

    if (counter_case != EVIDENCE_COUNTER_DUPLICATE) {
        receipt.evidence.data = &evidence[1];
        receipt.evidence_time.now_ms += 1u;
    }
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(project_single_target(
        &env, &admitted.transaction_id, &snapshot, &projected));
    REQUIRE(projected.evidence_counter_saturated == 0u);
    switch (counter_case) {
    case EVIDENCE_COUNTER_VALID:
        expected_before_restart = projected.valid_evidence_count;
        break;
    case EVIDENCE_COUNTER_DUPLICATE:
        expected_before_restart = projected.duplicate_evidence_count;
        break;
    case EVIDENCE_COUNTER_RAW_OVERFLOW:
        expected_before_restart = projected.raw_evidence_overflow_count;
        break;
    case EVIDENCE_COUNTER_LATE:
        expected_before_restart = projected.late_evidence_count;
        break;
    default:
        expected_before_restart = 0u;
        break;
    }
    REQUIRE(expected_before_restart == UINT64_MAX);

    /*
     * MAX with flag zero is a durable, recoverable boundary.  The flag is
     * raised only by the next attempted increment at MAX.
     */
    env.platform.bearer->close(env.platform.bearer->user, peer);
    peer = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    REQUIRE(project_single_target(
        &env, &admitted.transaction_id, &snapshot, &projected));
    REQUIRE(projected.evidence_counter_saturated == 0u);
    switch (counter_case) {
    case EVIDENCE_COUNTER_VALID:
        REQUIRE(projected.valid_evidence_count == UINT64_MAX);
        break;
    case EVIDENCE_COUNTER_DUPLICATE:
        REQUIRE(projected.duplicate_evidence_count == UINT64_MAX);
        break;
    case EVIDENCE_COUNTER_RAW_OVERFLOW:
        REQUIRE(projected.raw_evidence_overflow_count == UINT64_MAX);
        break;
    case EVIDENCE_COUNTER_LATE:
        REQUIRE(projected.late_evidence_count == UINT64_MAX);
        REQUIRE(projected.has_late_evidence == 1u);
        break;
    default:
        return 1;
    }
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &target.target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);

    if (counter_case != EVIDENCE_COUNTER_DUPLICATE) {
        receipt.evidence.data = &evidence[2];
        receipt.evidence_time.now_ms += 1u;
    }
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(project_single_target(
        &env, &admitted.transaction_id, &snapshot, &projected));
    REQUIRE(projected.evidence_counter_saturated == 1u);
    switch (counter_case) {
    case EVIDENCE_COUNTER_VALID:
        REQUIRE(projected.valid_evidence_count == UINT64_MAX);
        REQUIRE(projected.latest_evidence
            == NINLIL_EVIDENCE_APPLIED);
        REQUIRE(projected.late_evidence_count == 2u);
        break;
    case EVIDENCE_COUNTER_DUPLICATE:
        REQUIRE(projected.duplicate_evidence_count == UINT64_MAX);
        REQUIRE(projected.valid_evidence_count == 1u);
        break;
    case EVIDENCE_COUNTER_RAW_OVERFLOW:
        REQUIRE(projected.raw_evidence_overflow_count == UINT64_MAX);
        REQUIRE(projected.latest_evidence
            == NINLIL_EVIDENCE_APPLIED);
        REQUIRE(projected.late_evidence_count == 2u);
        break;
    case EVIDENCE_COUNTER_LATE:
        REQUIRE(projected.late_evidence_count == UINT64_MAX);
        REQUIRE(projected.has_late_evidence == 1u);
        REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
        REQUIRE(snapshot.outcome == NINLIL_OUTCOME_SATISFIED);
        REQUIRE(snapshot.reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET);
        break;
    default:
        return 1;
    }

    env.platform.bearer->close(
        env.platform.bearer->user, peer);
    peer = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    REQUIRE(project_single_target(
        &env, &admitted.transaction_id, &snapshot, &projected));
    REQUIRE(projected.evidence_counter_saturated == 1u);
    switch (counter_case) {
    case EVIDENCE_COUNTER_VALID:
        REQUIRE(projected.valid_evidence_count == UINT64_MAX);
        REQUIRE(projected.latest_evidence
            == NINLIL_EVIDENCE_APPLIED);
        REQUIRE(projected.late_evidence_count == 2u);
        break;
    case EVIDENCE_COUNTER_DUPLICATE:
        REQUIRE(projected.duplicate_evidence_count == UINT64_MAX);
        REQUIRE(projected.valid_evidence_count == 1u);
        break;
    case EVIDENCE_COUNTER_RAW_OVERFLOW:
        REQUIRE(projected.raw_evidence_overflow_count == UINT64_MAX);
        REQUIRE(projected.latest_evidence
            == NINLIL_EVIDENCE_APPLIED);
        REQUIRE(projected.late_evidence_count == 2u);
        break;
    case EVIDENCE_COUNTER_LATE:
        REQUIRE(projected.late_evidence_count == UINT64_MAX);
        REQUIRE(projected.has_late_evidence == 1u);
        REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
        REQUIRE(snapshot.outcome == NINLIL_OUTCOME_SATISFIED);
        REQUIRE(snapshot.reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET);
        break;
    default:
        return 1;
    }

    platform_teardown(&env);
    return 0;
}

static int test_evidence_counter_saturation_restart_boundaries(void)
{
    REQUIRE(run_evidence_counter_saturation_case(
                EVIDENCE_COUNTER_VALID) == 0);
    REQUIRE(run_evidence_counter_saturation_case(
                EVIDENCE_COUNTER_DUPLICATE) == 0);
    REQUIRE(run_evidence_counter_saturation_case(
                EVIDENCE_COUNTER_RAW_OVERFLOW) == 0);
    REQUIRE(run_evidence_counter_saturation_case(
                EVIDENCE_COUNTER_LATE) == 0);
    return 0;
}

static int test_exact_target_roster_rejections(void)
{
    static const uint8_t zero_key[] = "zero-targets";
    static const uint8_t duplicate_key[] = "duplicate-targets";
    static const uint8_t service_key[] = "over-service-limit";
    static const uint8_t runtime_key[] = "over-runtime-limit";
    static const uint8_t profile_key[] = "over-profile-limit";
    static const uint8_t limited_service_id[] = "limited-state";
    cap_env_t env;
    ninlil_concrete_target_t targets[5];
    ninlil_concrete_target_t duplicates[2];
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *wide_service;
    ninlil_service_t *limited_service = NULL;
    ninlil_submission_result_t result;
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_targets_per_transaction = 4u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(0x9cu);
    descriptor.target_limit = 4u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &wide_service)
        == NINLIL_OK);
    env.service = wide_service;

    REQUIRE(submit_exact_roster(
        &env,
        NULL,
        0u,
        zero_key,
        sizeof(zero_key) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_TARGET_COUNT_UNSUPPORTED);

    fill_exact_target(&duplicates[0], 0x21u, 0x61u);
    duplicates[1] = duplicates[0];
    REQUIRE(submit_exact_roster(
        &env,
        duplicates,
        2u,
        duplicate_key,
        sizeof(duplicate_key) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_TARGET_COUNT_UNSUPPORTED);

    descriptor = desired_descriptor(0x9du);
    descriptor.service_id.data = limited_service_id;
    descriptor.service_id.length = sizeof(limited_service_id) - 1u;
    descriptor.target_limit = 2u;
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &limited_service)
        == NINLIL_OK);
    for (index = 0u; index < 5u; ++index) {
        fill_exact_target(
            &targets[index],
            (uint8_t)(0x30u + index * 0x10u),
            (uint8_t)(0x70u + index * 0x10u));
    }
    env.service = limited_service;
    REQUIRE(submit_exact_roster(
        &env,
        targets,
        3u,
        service_key,
        sizeof(service_key) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_TARGET_COUNT_UNSUPPORTED);

    env.service = wide_service;
    REQUIRE(submit_exact_roster(
        &env,
        targets,
        5u,
        profile_key,
        sizeof(profile_key) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_TARGET_COUNT_UNSUPPORTED);

    platform_teardown(&env);

    /*
     * A Service cannot advertise above the Runtime roster bound.  With an
     * accepted exact bound of two, a three-target submission also fails
     * before admission mutation.
     */
    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(2u);
    env.config.limits.max_targets_per_transaction = 2u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(0x9eu);
    descriptor.target_limit = 4u;
    limited_service = NULL;
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &limited_service)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(limited_service == NULL);
    descriptor.target_limit = 2u;
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &limited_service)
        == NINLIL_OK);
    env.service = limited_service;
    REQUIRE(submit_exact_roster(
        &env,
        targets,
        3u,
        runtime_key,
        sizeof(runtime_key) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(result.reason == NINLIL_REASON_TARGET_COUNT_UNSUPPORTED);
    platform_teardown(&env);
    return 0;
}

static int test_two_exact_targets_delivery_dedup_and_restart(void)
{
    static const uint8_t idem[] = "two-target-delivery";
    static const uint8_t late_evidence[] = {0x4cu};
    cap_env_t env;
    ninlil_concrete_target_t targets[2];
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_submission_result_t admitted;
    ninlil_bearer_handle_t peer = NULL;
    ninlil_bearer_message_t application;
    ninlil_bearer_message_t receipt;
    ninlil_bearer_message_t duplicate_receipt;
    ninlil_bearer_message_t wrong_target_receipt;
    ninlil_bearer_message_t crossed_receipt;
    ninlil_bearer_message_t lower_receipt;
    ninlil_bearer_message_t late_receipt;
    ninlil_step_result_t step_result;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target_snapshots[2];
    uint32_t first_completed_index;
    uint64_t terminal_revision;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_targets_per_transaction = 4u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    descriptor = desired_descriptor(0x9fu);
    descriptor.target_limit = 4u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);

    /*
     * Two services on one remote Runtime exercise exact-target fan-out
     * without requiring the two-endpoint simulated bearer to model a group.
     */
    fill_exact_target(&targets[0], 0x20u, 0x70u);
    fill_exact_target(&targets[1], 0x20u, 0x60u);
    REQUIRE(submit_exact_roster(
        &env, targets, 2u, idem, sizeof(idem) - 1u, &admitted));
    REQUIRE(admitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &targets[0].target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);

    REQUIRE(receive_application_after_steps(&env, peer, &application));
    REQUIRE(application.target.target_application_instance_id.bytes[0]
        == 0x60u);
    make_receipt_from_application(&application, &receipt);
    duplicate_receipt = receipt;
    wrong_target_receipt = receipt;
    set_receipt_source_from_target(
        &wrong_target_receipt, &targets[0]);
    env.platform.bearer->release_received(
        env.platform.bearer->user, peer, &application);
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture,
        &env.config.runtime_id,
        &wrong_target_receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));

    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    (void)memset(target_snapshots, 0, sizeof(target_snapshots));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(target_snapshots[0].outcome == NINLIL_OUTCOME_NONE);
    REQUIRE(target_snapshots[1].outcome == NINLIL_OUTCOME_NONE);
    REQUIRE(target_snapshots[0].latest_evidence == NINLIL_EVIDENCE_NONE);
    REQUIRE(target_snapshots[1].latest_evidence == NINLIL_EVIDENCE_NONE);
    REQUIRE(target_snapshots[0].valid_evidence_count == 0u);
    REQUIRE(target_snapshots[1].valid_evidence_count == 0u);
    REQUIRE(target_snapshots[0].duplicate_evidence_count == 0u);
    REQUIRE(target_snapshots[1].duplicate_evidence_count == 0u);
    REQUIRE(
        target_snapshots[0].cumulative_attempts
            + target_snapshots[1].cumulative_attempts
        == 1u);
    REQUIRE(
        (target_snapshots[0].cumulative_attempts == 1u
            && target_snapshots[1].cumulative_attempts == 0u)
        || (target_snapshots[0].cumulative_attempts == 0u
            && target_snapshots[1].cumulative_attempts == 1u));
    REQUIRE(target_snapshots[0].retry_cycle_id == 0u);
    REQUIRE(target_snapshots[1].retry_cycle_id == 0u);

    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));

    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    (void)memset(target_snapshots, 0, sizeof(target_snapshots));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state != NINLIL_TXN_TERMINAL);
    REQUIRE(snapshot.target_count == 2u);
    first_completed_index =
        target_snapshots[0].target
                    .target_application_instance_id.bytes[0]
                == 0x60u
        ? 0u : 1u;
    REQUIRE(target_snapshots[first_completed_index].outcome
        == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(target_snapshots[1u - first_completed_index].outcome
        == NINLIL_OUTCOME_NONE);
    REQUIRE(target_snapshots[first_completed_index].valid_evidence_count
        == 1u);
    REQUIRE(target_snapshots[first_completed_index].duplicate_evidence_count
        == 0u);
    REQUIRE(target_snapshots[first_completed_index].has_late_evidence == 0u);
    REQUIRE(
        target_snapshots[first_completed_index].attempt_in_cycle == 1u);
    REQUIRE(
        target_snapshots[first_completed_index].cumulative_attempts == 1u);
    /*
     * Receipt reduction is one atomic ordered-input commit. The following
     * step may therefore prepare the next exact target; it must never charge
     * the completed target or more than one attempt to the remaining target.
     */
    REQUIRE(
        target_snapshots[1u - first_completed_index].attempt_in_cycle <= 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].cumulative_attempts
        == target_snapshots[1u - first_completed_index].attempt_in_cycle);
    REQUIRE(target_snapshots[0].retry_cycle_id == 0u);
    REQUIRE(target_snapshots[1].retry_cycle_id == 0u);

    /* Replayed receipt from the old attempt cannot complete another target. */
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture,
        &env.config.runtime_id,
        &duplicate_receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state != NINLIL_TXN_TERMINAL);
    REQUIRE(target_snapshots[1u - first_completed_index].outcome
        == NINLIL_OUTCOME_NONE);
    REQUIRE(target_snapshots[first_completed_index].valid_evidence_count
        == 1u);
    REQUIRE(target_snapshots[first_completed_index].duplicate_evidence_count
        == 1u);

    REQUIRE(receive_application_after_steps(&env, peer, &application));
    REQUIRE(application.target.target_application_instance_id.bytes[0]
        == 0x70u);
    make_receipt_from_application(&application, &receipt);
    crossed_receipt = receipt;
    crossed_receipt.source = duplicate_receipt.source;
    env.platform.bearer->release_received(
        env.platform.bearer->user, peer, &application);
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &crossed_receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));

    receipt.receipt_stage = NINLIL_EVIDENCE_DURABLY_RECORDED;
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));

    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state != NINLIL_TXN_TERMINAL);
    REQUIRE(target_snapshots[first_completed_index].outcome
        == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(target_snapshots[first_completed_index].latest_evidence
        == NINLIL_EVIDENCE_APPLIED);
    REQUIRE(target_snapshots[1u - first_completed_index].outcome
        == NINLIL_OUTCOME_NONE);
    REQUIRE(target_snapshots[1u - first_completed_index].latest_evidence
        == NINLIL_EVIDENCE_DURABLY_RECORDED);
    REQUIRE(target_snapshots[first_completed_index].valid_evidence_count
        == 1u);
    REQUIRE(target_snapshots[first_completed_index].duplicate_evidence_count
        == 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].valid_evidence_count
        == 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index]
            .duplicate_evidence_count
        == 0u);
    REQUIRE(
        target_snapshots[1u - first_completed_index]
            .raw_evidence_overflow_count
        == 0u);
    REQUIRE(target_snapshots[0].cumulative_attempts == 1u);
    REQUIRE(target_snapshots[1].cumulative_attempts == 1u);

    duplicate_receipt = receipt;
    lower_receipt = receipt;
    lower_receipt.receipt_stage = NINLIL_EVIDENCE_RECEIVED;
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture,
        &env.config.runtime_id,
        &duplicate_receipt));
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture,
        &env.config.runtime_id,
        &lower_receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(target_snapshots[first_completed_index].latest_evidence
        == NINLIL_EVIDENCE_APPLIED);
    REQUIRE(target_snapshots[1u - first_completed_index].latest_evidence
        == NINLIL_EVIDENCE_DURABLY_RECORDED);
    REQUIRE(target_snapshots[first_completed_index].valid_evidence_count
        == 1u);
    REQUIRE(target_snapshots[first_completed_index].duplicate_evidence_count
        == 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].valid_evidence_count
        == 2u);
    REQUIRE(
        target_snapshots[1u - first_completed_index]
            .duplicate_evidence_count
        == 1u);

    env.platform.bearer->close(env.platform.bearer->user, peer);
    peer = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    REQUIRE(env.platform.bearer->open(
                env.platform.bearer->user,
                &targets[0].target_runtime_id,
                NINLIL_ROLE_ENDPOINT,
                &peer)
        == NINLIL_BEARER_OK);
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state != NINLIL_TXN_TERMINAL);
    REQUIRE(target_snapshots[first_completed_index].outcome
        == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(target_snapshots[first_completed_index].latest_evidence
        == NINLIL_EVIDENCE_APPLIED);
    REQUIRE(target_snapshots[1u - first_completed_index].outcome
        == NINLIL_OUTCOME_NONE);
    REQUIRE(target_snapshots[1u - first_completed_index].latest_evidence
        == NINLIL_EVIDENCE_DURABLY_RECORDED);
    REQUIRE(
        target_snapshots[1u - first_completed_index].valid_evidence_count
        == 2u);
    REQUIRE(
        target_snapshots[1u - first_completed_index]
            .duplicate_evidence_count
        == 1u);
    REQUIRE(target_snapshots[0].cumulative_attempts == 1u);
    REQUIRE(target_snapshots[1].cumulative_attempts == 1u);

    receipt.receipt_stage = NINLIL_EVIDENCE_APPLIED;
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(target_snapshots[0].outcome == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(target_snapshots[1].outcome == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(
        target_snapshots[1u - first_completed_index].valid_evidence_count
        == 3u);
    terminal_revision = snapshot.record_revision;

    late_receipt = receipt;
    late_receipt.evidence.data = late_evidence;
    late_receipt.evidence.length = sizeof(late_evidence);
    late_receipt.evidence_time.now_ms += 1u;
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &late_receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    REQUIRE(ninlil_test_bearer_deliver_to_runtime(
        env.bearer_fixture, &env.config.runtime_id, &late_receipt));
    REQUIRE(step_runtime(&env, 0u, &step_result));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(snapshot.reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET);
    REQUIRE(snapshot.has_late_evidence == 1u);
    REQUIRE(snapshot.record_revision == terminal_revision + 2u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].has_late_evidence
        == 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].late_evidence_count
        == 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].valid_evidence_count
        == 4u);
    REQUIRE(
        target_snapshots[1u - first_completed_index]
            .duplicate_evidence_count
        == 2u);
    REQUIRE(
        target_snapshots[1u - first_completed_index]
            .raw_evidence_overflow_count
        == 1u);
    REQUIRE(target_snapshots[first_completed_index].has_late_evidence == 0u);

    env.platform.bearer->close(env.platform.bearer->user, peer);
    peer = NULL;
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    env.service = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_service_register(
                env.runtime, &descriptor, &callbacks, &env.service)
        == NINLIL_OK);
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    set_header(
        &target_snapshots[0].abi_version,
        &target_snapshots[0].struct_size,
        sizeof(target_snapshots[0]));
    set_header(
        &target_snapshots[1].abi_version,
        &target_snapshots[1].struct_size,
        sizeof(target_snapshots[1]));
    snapshot.targets = target_snapshots;
    snapshot.target_capacity = 2u;
    REQUIRE(ninlil_transaction_query(
                env.runtime, &admitted.transaction_id, &snapshot)
        == NINLIL_OK);
    REQUIRE(snapshot.state == NINLIL_TXN_TERMINAL);
    REQUIRE(snapshot.outcome == NINLIL_OUTCOME_SATISFIED);
    REQUIRE(snapshot.has_late_evidence == 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].late_evidence_count
        == 1u);
    REQUIRE(
        target_snapshots[1u - first_completed_index].valid_evidence_count
        == 4u);
    REQUIRE(
        target_snapshots[1u - first_completed_index]
            .duplicate_evidence_count
        == 2u);

    platform_teardown(&env);
    return 0;
}

static int test_payload_is_owned_across_caller_mutation_and_restart(void)
{
    cap_env_t env;
    ninlil_submission_result_t result;
    ninlil_rt_transaction_slot_t *transaction;
    static const uint8_t idem[] = "owned-payload";
    uint32_t index;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x77u));
    REQUIRE(submit_with_payload(
        &env,
        32u,
        5000u,
        0x29u,
        idem,
        sizeof(idem) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL);
    for (index = 0u; index < 32u; ++index) {
        REQUIRE(transaction->owned_payload[index] == 0xa5u);
    }
    (void)memset(env.payload, 0x3cu, 32u);
    for (index = 0u; index < 32u; ++index) {
        REQUIRE(transaction->owned_payload[index] == 0xa5u);
    }

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL);
    REQUIRE(transaction->payload_length == 32u);
    for (index = 0u; index < 32u; ++index) {
        REQUIRE(transaction->owned_payload[index] == 0xa5u);
    }
    platform_teardown(&env);
    return 0;
}

static int test_outbox_capacity_reject_restart_release_readmit(void)
{
    cap_env_t env;
    ninlil_submission_result_t first;
    ninlil_submission_result_t blocked;
    ninlil_submission_result_t readmitted;
    ninlil_cancel_result_t cancel_result;
    static const uint8_t idem_first[] = "capacity-first";
    static const uint8_t idem_blocked[] = "capacity-blocked";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    env.config = config_controller(4u);
    env.config.limits.max_durable_outbox_payload_bytes = 1024u;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env_register(&env, 0x78u));
    REQUIRE(submit_with_payload(
        &env,
        926u,
        5000u,
        0x2au,
        idem_first,
        sizeof(idem_first) - 1u,
        &first));
    REQUIRE(first.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env_register(&env, 0x78u));
    REQUIRE(submit_with_payload(
        &env,
        100u,
        5000u,
        0x2bu,
        idem_blocked,
        sizeof(idem_blocked) - 1u,
        &blocked));
    REQUIRE(blocked.kind == NINLIL_SUBMISSION_REJECTED);
    REQUIRE(blocked.reason == NINLIL_REASON_CAPACITY_EXHAUSTED);
    REQUIRE(blocked.retry_guidance == NINLIL_RETRY_SAME_AFTER);

    (void)memset(&cancel_result, 0, sizeof(cancel_result));
    set_header(
        &cancel_result.abi_version,
        &cancel_result.struct_size,
        sizeof(cancel_result));
    REQUIRE(ninlil_cancel_request(
                env.runtime, &first.transaction_id, &cancel_result)
        == NINLIL_OK);
    REQUIRE(cancel_result.kind == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH);

    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(ninlil_runtime_create(
                &env.config, &env.platform, &env.runtime)
        == NINLIL_OK);
    REQUIRE(env_register(&env, 0x78u));
    REQUIRE(submit_with_payload(
        &env,
        100u,
        5000u,
        0x2bu,
        idem_blocked,
        sizeof(idem_blocked) - 1u,
        &readmitted));
    REQUIRE(readmitted.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    platform_teardown(&env);
    return 0;
}

static int test_restart_rejects_missing_capacity_row(void)
{
    cap_env_t env;
    ninlil_model_runtime_store_key_t key;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
                &key)
        == NINLIL_OK);
    REQUIRE(raw_storage_mutate(
        env.storage_fixture,
        env.config.storage_namespace,
        (ninlil_bytes_view_t){key.bytes, key.length},
        NULL));
    status = ninlil_runtime_create(
        &env.config, &env.platform, &env.runtime);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(env.runtime == NULL);
    platform_teardown(&env);
    return 0;
}

static int test_restart_rejects_capacity_ledger_mismatch(void)
{
    cap_env_t env;
    ninlil_model_runtime_store_key_t key;
    ninlil_model_runtime_store_capacity_t capacity;
    uint8_t value_bytes[NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES];
    uint32_t value_length = 0u;
    ninlil_bytes_view_t value;
    ninlil_status_t status;

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_OUTBOX_BYTES,
                &key)
        == NINLIL_OK);
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.kind = NINLIL_RESOURCE_OUTBOX_BYTES;
    capacity.limit =
        env.config.limits.max_durable_outbox_payload_bytes;
    capacity.used = 1u;
    capacity.high_water = 1u;
    capacity.capacity_epoch = 1u;
    REQUIRE(ninlil_model_runtime_store_encode_capacity(
                NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_OUTBOX_BYTES,
                &capacity,
                value_bytes,
                (uint32_t)sizeof(value_bytes),
                &value_length)
        == NINLIL_OK);
    value.data = value_bytes;
    value.length = value_length;
    REQUIRE(raw_storage_mutate(
        env.storage_fixture,
        env.config.storage_namespace,
        (ninlil_bytes_view_t){key.bytes, key.length},
        &value));
    status = ninlil_runtime_create(
        &env.config, &env.platform, &env.runtime);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(env.runtime == NULL);
    platform_teardown(&env);
    return 0;
}

static int run_restart_reservation_pair_corruption(int erase_tx)
{
    cap_env_t env;
    ninlil_submission_result_t result;
    ninlil_status_t status;
    static const uint8_t idem[] = "reservation-pair";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x79u));
    REQUIRE(submit_with_payload(
        &env,
        16u,
        5000u,
        0x2cu,
        idem,
        sizeof(idem) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    REQUIRE(raw_erase_marker(
        &env,
        erase_tx != 0 ? 0x5458u : NINLIL_RT_V1_MARKER_RV,
        &result.transaction_id));
    status = ninlil_runtime_create(
        &env.config, &env.platform, &env.runtime);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(env.runtime == NULL);
    platform_teardown(&env);
    return 0;
}

static int test_restart_rejects_missing_or_orphan_reservation(void)
{
    REQUIRE(run_restart_reservation_pair_corruption(0) == 0);
    REQUIRE(run_restart_reservation_pair_corruption(1) == 0);
    return 0;
}

static int test_restart_rejects_same_revision_conflict(void)
{
    cap_env_t env;
    ninlil_submission_result_t result;
    ninlil_rt_transaction_slot_t *transaction;
    ninlil_rt_transaction_slot_t conflict;
    uint8_t key[18];
    uint8_t value_bytes[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t value_length = 0u;
    ninlil_bytes_view_t value;
    ninlil_status_t status;
    static const uint8_t idem[] = "revision-conflict";

    (void)memset(&env, 0, sizeof(env));
    REQUIRE(platform_init(&env));
    REQUIRE(env_create(&env));
    REQUIRE(env_register(&env, 0x7au));
    REQUIRE(submit_with_payload(
        &env,
        16u,
        5000u,
        0x2du,
        idem,
        sizeof(idem) - 1u,
        &result));
    REQUIRE(result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    transaction =
        ninlil_rt_find_transaction(env.runtime, &result.transaction_id);
    REQUIRE(transaction != NULL);
    conflict = *transaction;
    conflict.retry_budget = transaction->retry_budget - 1u;
    REQUIRE(conflict.active_target_index < conflict.bound_target_count);
    conflict.bound_targets[conflict.active_target_index].retry_budget =
        conflict.retry_budget;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &conflict,
                value_bytes,
                (uint32_t)sizeof(value_bytes),
                &value_length)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(env.runtime) == NINLIL_OK);
    env.runtime = NULL;
    key[0] = 0x45u;
    key[1] = 0x56u;
    (void)memcpy(
        &key[2],
        result.transaction_id.bytes,
        sizeof(result.transaction_id.bytes));
    value.data = value_bytes;
    value.length = value_length;
    REQUIRE(raw_storage_mutate(
        env.storage_fixture,
        env.config.storage_namespace,
        (ninlil_bytes_view_t){key, sizeof(key)},
        &value));
    status = ninlil_runtime_create(
        &env.config, &env.platform, &env.runtime);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(env.runtime == NULL);
    platform_teardown(&env);
    return 0;
}

int main(void)
{
    int rc = 0;

    if (test_bearer_limit_table() != 0) {
        rc = 1;
    }
    if (test_logical_fragment_single() != 0) {
        rc = 1;
    }
    if (test_payload_max_minus_one_admitted() != 0) {
        rc = 1;
    }
    if (test_payload_max_admitted() != 0) {
        rc = 1;
    }
    if (test_payload_max_plus_one_rejected() != 0) {
        rc = 1;
    }
    if (test_deadline_timeout_outcome() != 0) {
        rc = 1;
    }
    if (test_priority_dispatch_order() != 0) {
        rc = 1;
    }
    if (test_restart_preserves_admission() != 0) {
        rc = 1;
    }
#if defined(NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED)
    if (test_mfdt_runtime_waits_without_single_frame_fallback() != 0) {
        rc = 1;
    }
    if (test_mfdt_session_binding_fail_closed() != 0) {
        rc = 1;
    }
    if (test_mfdt_public_owner_boundaries_and_isolation() != 0) {
        rc = 1;
    }
    if (test_mfdt_public_owner_commit_failures() != 0) {
        rc = 1;
    }
    if (test_mfdt_attempt_entropy_partial_then_success() != 0) {
        rc = 1;
    }
    if (test_mfdt_attempt_entropy_four_draw_exhaustion() != 0) {
        rc = 1;
    }
    if (test_mfdt_multi_target_admission_success() != 0) {
        rc = 1;
    }
    if (test_mfdt_duplicate_runtime_rejected_before_entropy() != 0) {
        rc = 1;
    }
    if (test_mfdt_multi_target_candidate_collision_and_exhaustion() != 0) {
        rc = 1;
    }
    if (test_mfdt_multi_target_arm_and_foundation_cuts() != 0) {
        rc = 1;
    }
    if (test_mfdt_multi_target_cleanup_failure_cuts() != 0) {
        rc = 1;
    }
    if (test_mfdt_exact_one_cold_restart_reconciliation() != 0) {
        rc = 1;
    }
    if (test_mfdt_multi_target_cold_restart_reconciliation() != 0) {
        rc = 1;
    }
    if (test_mfdt_cold_restart_orphan_cleanup() != 0) {
        rc = 1;
    }
    if (test_mfdt_cold_restart_mismatch_and_terminal_fence() != 0) {
        rc = 1;
    }
    if (test_mfdt_application_evidence_digest_kat() != 0) {
        rc = 1;
    }
    if (test_mfdt_cold_restart_receiver_handoff() != 0) {
        rc = 1;
    }
#endif
    if (test_simulated_bearer_loss_injection() != 0) {
        rc = 1;
    }
    if (test_retry_budget_exhaustion() != 0) {
        rc = 1;
    }
    if (test_retry_and_dedup_profile_boundaries() != 0) {
        rc = 1;
    }
    if (test_public_runtime_role_environment_matrix() != 0) {
        rc = 1;
    }
    if (test_two_exact_targets_admission_restart_query_and_list() != 0) {
        rc = 1;
    }
    if (test_target_snapshot_future_stride_and_nonmutation() != 0) {
        rc = 1;
    }
    if (test_four_exact_targets_atomic_completion_and_restart()
        != 0) {
        rc = 1;
    }
    if (test_four_exact_targets_retry_exhaustion_and_restart()
        != 0) {
        rc = 1;
    }
    if (test_evidence_counter_saturation_restart_boundaries() != 0) {
        rc = 1;
    }
    if (test_exact_target_roster_rejections() != 0) {
        rc = 1;
    }
    if (test_two_exact_targets_delivery_dedup_and_restart() != 0) {
        rc = 1;
    }
    if (test_payload_is_owned_across_caller_mutation_and_restart() != 0) {
        rc = 1;
    }
    if (test_outbox_capacity_reject_restart_release_readmit() != 0) {
        rc = 1;
    }
    if (test_restart_rejects_missing_capacity_row() != 0) {
        rc = 1;
    }
    if (test_restart_rejects_capacity_ledger_mismatch() != 0) {
        rc = 1;
    }
    if (test_restart_rejects_missing_or_orphan_reservation() != 0) {
        rc = 1;
    }
    if (test_restart_rejects_same_revision_conflict() != 0) {
        rc = 1;
    }

    if (rc != 0) {
        (void)fprintf(stderr, "v1_runtime_capability_test failed\n");
    }
    return rc;
}
