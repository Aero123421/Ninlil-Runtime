/*
 * V1-LAB unit 6: B5 application capability families.
 */

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_v1_family_capability.h"
#include "runtime_v1_target_resolver.h"
#include "runtime_lifecycle_model.h"
#include "typed_simulated_bearer.h"

#include <ninlil/runtime.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t TEST_NAMESPACE[] = "v1-runtime-family-test";
static const char NS_TEXT[] = "org.ninlil.examples";

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static void set_digest(ninlil_digest256_t *digest, uint8_t value)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = value;
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static ninlil_service_descriptor_t make_descriptor(
    ninlil_family_t family,
    ninlil_role_t role,
    uint8_t app_tag,
    const char *service_id)
{
    ninlil_service_descriptor_t descriptor;
    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(&descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)service_id;
    descriptor.service_id.length = strlen(service_id);
    descriptor.schema_id.data = (const uint8_t *)service_id;
    descriptor.schema_id.length = strlen(service_id);
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, app_tag);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = family;
    descriptor.logical_payload_limit = 512u;
    descriptor.target_limit = 2u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    if (ninlil_rt_v1_family_is_uplink(family)) {
        descriptor.direction = NINLIL_DIRECTION_UPLINK;
        descriptor.admission_authority = NINLIL_AUTHORITY_ORIGIN_WITH_GRANT;
        descriptor.minimum_deadline_ms = NINLIL_NO_DEADLINE;
        descriptor.maximum_deadline_ms = NINLIL_NO_DEADLINE;
        descriptor.maximum_evidence_grace_ms = 0u;
    } else {
        descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
        descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
        descriptor.minimum_deadline_ms = 5000u;
        descriptor.maximum_deadline_ms = 5000u;
        descriptor.maximum_evidence_grace_ms = 1000u;
    }
    (void)role;
    return descriptor;
}

static int test_latest_state_apply_and_stale(void)
{
    ninlil_rt_v1_family_workspace_t ws;
    ninlil_id128_t app_id;
    ninlil_application_result_t result;

    (void)memset(&ws, 0, sizeof(ws));
    set_id(&app_id, 0x31u);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_rt_v1_family_latest_state_apply(&ws, &app_id, 10u, &result) == 1);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_rt_v1_family_latest_state_apply(&ws, &app_id, 12u, &result) == 1);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_rt_v1_family_latest_state_apply(&ws, &app_id, 11u, &result) == 0);
    REQUIRE(result.disposition == NINLIL_DISPOSITION_STALE_NOT_APPLIED);
    return 0;
}

static int test_measurement_batch_retention(void)
{
    ninlil_rt_v1_family_workspace_t ws;
    ninlil_id128_t app_id;
    ninlil_application_result_t result;

    (void)memset(&ws, 0, sizeof(ws));
    set_id(&app_id, 0x41u);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_rt_v1_family_measurement_batch_accept(
        &ws, &app_id, 1u, 32u, &result) == 1);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_rt_v1_family_measurement_batch_accept(
        &ws, &app_id, 2u, 32u, &result) == 1);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_rt_v1_family_measurement_batch_accept(
        &ws, &app_id, 1u, 32u, &result) == 0);
    REQUIRE(result.disposition == NINLIL_DISPOSITION_STALE_NOT_APPLIED);
    return 0;
}

static int test_bounded_transfer_partial_apply_zero(void)
{
    ninlil_rt_v1_family_workspace_t ws;
    ninlil_id128_t txn_id;

    (void)memset(&ws, 0, sizeof(ws));
    set_id(&txn_id, 0x51u);
    REQUIRE(ninlil_rt_v1_family_bounded_transfer_begin(&ws, &txn_id, 100u) == 1);
    REQUIRE(ninlil_rt_v1_family_bounded_transfer_may_apply(&ws, &txn_id) == 0);
    REQUIRE(ninlil_rt_v1_family_bounded_transfer_receive(
        &ws, &txn_id, 40u, 0) == 1);
    REQUIRE(ninlil_rt_v1_family_bounded_transfer_may_apply(&ws, &txn_id) == 0);
    REQUIRE(ninlil_rt_v1_family_bounded_transfer_abort(&ws, &txn_id) == 1);
    REQUIRE(ninlil_rt_v1_family_bounded_transfer_may_apply(&ws, &txn_id) == 0);
    return 0;
}

static int test_config_revision_stage_commit_rollback(void)
{
    ninlil_rt_v1_family_workspace_t ws;
    ninlil_id128_t app_id;
    ninlil_application_result_t result;

    (void)memset(&ws, 0, sizeof(ws));
    set_id(&app_id, 0x61u);
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_rt_v1_family_config_revision_advance(
        &ws, &app_id, 5u, NINLIL_RT_V1_CONFIG_STAGE_STAGED, &result) == 1);
    REQUIRE(ninlil_rt_v1_family_config_revision_advance(
        &ws, &app_id, 5u, NINLIL_RT_V1_CONFIG_STAGE_VALIDATE, &result) == 1);
    REQUIRE(ninlil_rt_v1_family_config_revision_advance(
        &ws, &app_id, 5u, NINLIL_RT_V1_CONFIG_STAGE_COMMIT, &result) == 1);
    REQUIRE(ninlil_rt_v1_family_config_revision_advance(
        &ws, &app_id, 4u, NINLIL_RT_V1_CONFIG_STAGE_COMMIT, &result) == 0);
    REQUIRE(result.disposition == NINLIL_DISPOSITION_INVALID_PAYLOAD);
    ninlil_rt_v1_family_config_revision_rollback(&ws, &app_id);
    REQUIRE(ninlil_rt_v1_family_config_revision_advance(
        &ws, &app_id, 6u, NINLIL_RT_V1_CONFIG_STAGE_STAGED, &result) == 1);
    REQUIRE(ninlil_rt_v1_family_config_revision_advance(
        &ws, &app_id, 6u, NINLIL_RT_V1_CONFIG_STAGE_VALIDATE, &result) == 1);
    REQUIRE(ninlil_rt_v1_family_config_revision_advance(
        &ws, &app_id, 6u, NINLIL_RT_V1_CONFIG_STAGE_COMMIT, &result) == 1);
    return 0;
}

static int test_target_aggregate(void)
{
    ninlil_rt_transaction_slot_t txn;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;

    (void)memset(&txn, 0, sizeof(txn));
    txn.bound_target_count = 2u;
    txn.bound_targets[0].in_use = 1u;
    txn.bound_targets[0].outcome = NINLIL_OUTCOME_SATISFIED;
    txn.bound_targets[1].in_use = 1u;
    txn.bound_targets[1].outcome = NINLIL_OUTCOME_SATISFIED;
    ninlil_rt_v1_aggregate_target_outcomes(&txn, &outcome, &reason);
    REQUIRE(outcome == NINLIL_OUTCOME_SATISFIED);
    txn.bound_targets[1].outcome = NINLIL_OUTCOME_FAILED_DEFINITIVE;
    ninlil_rt_v1_aggregate_target_outcomes(&txn, &outcome, &reason);
    REQUIRE(outcome == NINLIL_OUTCOME_FAILED_DEFINITIVE);
    REQUIRE(reason == NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT);
    return 0;
}

static ninlil_runtime_config_t family_controller_config(uint8_t runtime_tag)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, runtime_tag);
    config.storage_namespace.data = TEST_NAMESPACE;
    config.storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    set_header(
        &config.limits.abi_version, &config.limits.struct_size, sizeof(config.limits));
    config.limits.max_services = 4u;
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
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, (uint8_t)(runtime_tag + 1u));
    set_id(&config.local_identity.installation_id, (uint8_t)(runtime_tag + 2u));
    set_id(&config.local_identity.site_domain_id, (uint8_t)(runtime_tag + 3u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static int family_runtime_create(
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform,
    ninlil_runtime_t **out_runtime)
{
    ninlil_model_runtime_validation_result_t validation;
    ninlil_status_t status;

    status = ninlil_model_runtime_validate_and_derive(config, platform, &validation);
    if (status != NINLIL_OK) {
        return validation.status;
    }
    return ninlil_runtime_create(config, platform, out_runtime);
}

static ninlil_test_bearer_t *create_test_bearer(void)
{
    ninlil_test_bearer_config_t bearer_config;

    (void)memset(&bearer_config, 0, sizeof(bearer_config));
    bearer_config.max_entries_per_direction = 32u;
    bearer_config.max_bytes_per_direction = 65536u;
    bearer_config.max_permits = 32u;
    bearer_config.permit_issuer_id.bytes[0] = 0x80u;
    bearer_config.permit_issuer_id.bytes[15] = 0x01u;
    bearer_config.initial_clock_epoch_id.bytes[0] = 0xa0u;
    bearer_config.initial_clock_epoch_id.bytes[15] = 0x01u;
    return ninlil_test_bearer_create(&bearer_config);
}

static void attach_bearer(
    ninlil_platform_ops_t *platform,
    ninlil_test_bearer_t *bearer_fixture)
{
    platform->bearer = ninlil_test_bearer_ops(bearer_fixture);
    platform->tx_gate = ninlil_test_bearer_tx_gate_ops(bearer_fixture);
}

static ninlil_origin_auth_status_t origin_allow(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)request;
    (void)memset(decision, 0, sizeof(*decision));
    set_header(
        &decision->abi_version, &decision->struct_size, sizeof(*decision));
    decision->allowed = 1u;
    decision->reason = NINLIL_REASON_NONE;
    return NINLIL_ORIGIN_AUTH_OK;
}

static void attach_platform(
    ninlil_platform_ops_t *platform,
    ninlil_test_allocator_t *allocator,
    ninlil_test_execution_t *execution,
    ninlil_test_clock_t *clock,
    ninlil_test_entropy_t *entropy,
    ninlil_test_storage_t *storage_fixture,
    ninlil_test_bearer_t *bearer_fixture,
    ninlil_origin_authorization_ops_t *origin)
{
    (void)memset(platform, 0, sizeof(*platform));
    set_header(&platform->abi_version, &platform->struct_size, sizeof(*platform));
    platform->allocator = ninlil_test_allocator_ops(allocator);
    platform->execution = ninlil_test_execution_ops(execution);
    platform->clock = ninlil_test_clock_ops(clock);
    platform->entropy = ninlil_test_entropy_ops(entropy);
    platform->storage = ninlil_test_storage_ops(storage_fixture);
    attach_bearer(platform, bearer_fixture);
    set_header(&origin->abi_version, &origin->struct_size, sizeof(*origin));
    origin->evaluate = origin_allow;
    platform->origin_authorization = origin;
}

static ninlil_callback_action_t noop_delivery_cb(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    (void)user;
    (void)token;
    (void)delivery;
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t noop_reconcile_cb(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

static int test_multiple_service_register(void)
{
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_bearer_t *bearer_fixture;
    ninlil_platform_ops_t platform;
    ninlil_origin_authorization_ops_t origin;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime;
    ninlil_service_t *svc_a;
    ninlil_service_t *svc_b;
    ninlil_service_descriptor_t desc_a;
    ninlil_service_descriptor_t desc_b;
    ninlil_service_callbacks_t callbacks;

    allocator = ninlil_test_allocator_create();
    execution = ninlil_test_execution_create(1u);
    clock = ninlil_test_clock_create();
    entropy = ninlil_test_entropy_create(0x46414d4cu, 1u);
    storage_fixture = ninlil_test_storage_create(&(ninlil_test_storage_config_t){
        .max_namespaces = 2u,
        .max_entries_per_namespace = 128u,
        .max_bytes_per_namespace = 65536u});
    bearer_fixture = create_test_bearer();
    REQUIRE(bearer_fixture != NULL);
    attach_platform(
        &platform,
        allocator,
        execution,
        clock,
        entropy,
        storage_fixture,
        bearer_fixture,
        &origin);
    config = family_controller_config(0x70u);
    desc_a = make_descriptor(
        NINLIL_FAMILY_LATEST_STATE_RESERVED,
        NINLIL_ROLE_CONTROLLER,
        0x71u,
        "latest-state");
    desc_b = make_descriptor(
        NINLIL_FAMILY_TRANSFER_RESERVED,
        NINLIL_ROLE_CONTROLLER,
        0x72u,
        "bounded-transfer");
    desc_a.target_limit = 1u;
    desc_b.target_limit = 1u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    callbacks.on_delivery = noop_delivery_cb;
    callbacks.on_reconcile = noop_reconcile_cb;
    REQUIRE(family_runtime_create(&config, &platform, &runtime) == NINLIL_OK);
    REQUIRE(ninlil_service_register(runtime, &desc_a, &callbacks, &svc_a) == NINLIL_OK);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(runtime, &desc_b, &callbacks, &svc_b) == NINLIL_OK);
    REQUIRE(svc_a != NULL && svc_b != NULL && svc_a != svc_b);
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    ninlil_test_bearer_destroy(bearer_fixture);
    ninlil_test_storage_destroy(storage_fixture);
    ninlil_test_entropy_destroy(entropy);
    ninlil_test_clock_destroy(clock);
    ninlil_test_execution_destroy(execution);
    ninlil_test_allocator_destroy(allocator);
    return 0;
}

static int test_offer_accept_unsupported(void)
{
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage_fixture;
    ninlil_test_bearer_t *bearer_fixture;
    ninlil_platform_ops_t platform;
    ninlil_origin_authorization_ops_t origin;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime;
    ninlil_id128_t offer_id;
    ninlil_submission_result_t result;

    allocator = ninlil_test_allocator_create();
    execution = ninlil_test_execution_create(1u);
    clock = ninlil_test_clock_create();
    entropy = ninlil_test_entropy_create(0x4f464652u, 1u);
    storage_fixture = ninlil_test_storage_create(&(ninlil_test_storage_config_t){
        .max_namespaces = 2u,
        .max_entries_per_namespace = 64u,
        .max_bytes_per_namespace = 32768u});
    bearer_fixture = create_test_bearer();
    REQUIRE(bearer_fixture != NULL);
    attach_platform(
        &platform,
        allocator,
        execution,
        clock,
        entropy,
        storage_fixture,
        bearer_fixture,
        &origin);
    config = family_controller_config(0x80u);
    set_id(&offer_id, 0x81u);
    REQUIRE(family_runtime_create(&config, &platform, &runtime) == NINLIL_OK);
    REQUIRE(ninlil_offer_accept(runtime, &offer_id, &result) == NINLIL_E_UNSUPPORTED);
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    ninlil_test_bearer_destroy(bearer_fixture);
    ninlil_test_storage_destroy(storage_fixture);
    ninlil_test_entropy_destroy(entropy);
    ninlil_test_clock_destroy(clock);
    ninlil_test_execution_destroy(execution);
    ninlil_test_allocator_destroy(allocator);
    return 0;
}

int main(void)
{
    if (test_latest_state_apply_and_stale() != 0) {
        return 1;
    }
    if (test_measurement_batch_retention() != 0) {
        return 1;
    }
    if (test_bounded_transfer_partial_apply_zero() != 0) {
        return 1;
    }
    if (test_config_revision_stage_commit_rollback() != 0) {
        return 1;
    }
    if (test_target_aggregate() != 0) {
        return 1;
    }
    if (test_multiple_service_register() != 0) {
        return 1;
    }
    if (test_offer_accept_unsupported() != 0) {
        return 1;
    }
    (void)fprintf(stdout, "v1_runtime_family_test ok\n");
    return 0;
}
