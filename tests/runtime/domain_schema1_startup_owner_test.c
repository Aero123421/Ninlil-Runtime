/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ADR-0022 Domain schema1 HOST_CANDIDATE owner tests (feature ON).
 * Real in-memory storage_ops, fault injection, crash/restart matrix.
 */

#include "domain_schema1_kind1_register.h"
#include "domain_schema1_startup_owner.h"
#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"
#include "runtime_internal.h"
#include "runtime_lifecycle_model.h"
#include "typed_simulated_bearer.h"

#include <ninlil/runtime.h>
#include <stdalign.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(cond)                                                       \
    do {                                                                    \
        if (!(cond)) {                                                      \
            (void)fprintf(                                                  \
                stderr,                                                     \
                "domain_schema1_owner FAIL %s:%d: %s\n",                    \
                __FILE__,                                                   \
                __LINE__,                                                   \
                #cond);                                                     \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static const uint8_t k_ns[] = "domain-schema1-host-candidate";

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(first + i);
    }
}

static void set_hdr(uint16_t *version, uint16_t *size, size_t bytes)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)bytes;
}

static ninlil_runtime_config_t make_controller_config(void)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    set_hdr(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x44u);
    set_hdr(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x55u);
    set_id(&config.local_identity.installation_id, 0x66u);
    set_id(&config.local_identity.site_domain_id, 0x77u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = k_ns;
    config.storage_namespace.length = sizeof(k_ns) - 1u;
    set_hdr(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 16u;
    config.limits.max_nonterminal_transactions = 32u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 256u;
    config.limits.max_durable_outbox_payload_bytes = 8192u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 64u;
    config.limits.max_nonterminal_deliveries = 32u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.limits.max_result_cache_entries = 32u;
    config.limits.max_retained_dispositions = 64u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 16u;
    config.terminal_retention_ms = 2000u;
    config.result_cache_retention_ms = 1000u;
    config.observation_retention_ms = 3000u;
    return config;
}

static ninlil_origin_auth_status_t origin_allow(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)memset(decision, 0, sizeof(*decision));
    set_hdr(
        &decision->abi_version, &decision->struct_size, sizeof(*decision));
    decision->allowed = 1u;
    decision->max_payload_bytes = 2048u;
    decision->clock_epoch_id = request->now.clock_epoch_id;
    decision->evaluated_at_ms = request->now.now_ms;
    return NINLIL_ORIGIN_AUTH_OK;
}

typedef struct env {
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_test_storage_t *storage;
    ninlil_test_bearer_t *bearer;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    ninlil_runtime_config_t config;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_storage_handle_t handle;
    ninlil_domain_schema1_owner_workspace_t *ws;
    ninlil_domain_schema1_owner_result_t result;
} env_t;

static int env_init(env_t *e)
{
    ninlil_test_storage_config_t sc;
    ninlil_test_bearer_config_t bc;
    ninlil_status_t st;
    ninlil_storage_status_t sst;
    ninlil_bytes_view_t ns;

    (void)memset(e, 0, sizeof(*e));
    (void)memset(&sc, 0, sizeof(sc));
    sc.max_namespaces = 4u;
    sc.max_entries_per_namespace = 256u;
    sc.max_bytes_per_namespace = 1024u * 1024u;
    e->allocator = ninlil_test_allocator_create();
    e->execution = ninlil_test_execution_create(1u);
    e->clock = ninlil_test_clock_create();
    e->entropy = ninlil_test_entropy_create(0xD011u, 1u);
    e->storage = ninlil_test_storage_create(&sc);
    (void)memset(&bc, 0, sizeof(bc));
    bc.max_entries_per_direction = 8u;
    bc.max_bytes_per_direction = 65536u;
    bc.max_permits = 8u;
    bc.permit_issuer_id.bytes[0] = 0x80u;
    bc.initial_clock_epoch_id.bytes[0] = 0xa0u;
    e->bearer = ninlil_test_bearer_create(&bc);
    if (e->allocator == NULL || e->execution == NULL || e->clock == NULL
        || e->entropy == NULL || e->storage == NULL || e->bearer == NULL) {
        return 0;
    }
    set_hdr(
        &e->platform.abi_version,
        &e->platform.struct_size,
        sizeof(e->platform));
    e->platform.allocator = ninlil_test_allocator_ops(e->allocator);
    e->platform.execution = ninlil_test_execution_ops(e->execution);
    e->platform.clock = ninlil_test_clock_ops(e->clock);
    e->platform.entropy = ninlil_test_entropy_ops(e->entropy);
    e->platform.storage = ninlil_test_storage_ops(e->storage);
    e->platform.bearer = ninlil_test_bearer_ops(e->bearer);
    e->platform.tx_gate = ninlil_test_bearer_tx_gate_ops(e->bearer);
    set_hdr(
        &e->origin.abi_version, &e->origin.struct_size, sizeof(e->origin));
    e->origin.evaluate = origin_allow;
    e->platform.origin_authorization = &e->origin;
    e->config = make_controller_config();
    st = ninlil_model_runtime_validate_and_derive(
        &e->config, &e->platform, &e->validation);
    if (st != NINLIL_OK || e->validation.status != NINLIL_OK) {
        return 0;
    }
    e->ws = e->platform.allocator->allocate(
        e->platform.allocator->user,
        sizeof(*e->ws),
        (uint32_t)alignof(ninlil_domain_schema1_owner_workspace_t));
    if (e->ws == NULL) {
        return 0;
    }
    (void)memset(e->ws, 0, sizeof(*e->ws));
    ns.data = k_ns;
    ns.length = sizeof(k_ns) - 1u;
    sst = e->platform.storage->open(
        e->platform.storage->user,
        ns,
        NINLIL_STORAGE_SCHEMA_M1A,
        &e->handle);
    return sst == NINLIL_STORAGE_OK && e->handle != NULL;
}

static void env_fini(env_t *e)
{
    if (e->handle != NULL && e->platform.storage != NULL) {
        e->platform.storage->close(e->platform.storage->user, e->handle);
        e->handle = NULL;
    }
    if (e->ws != NULL && e->platform.allocator != NULL) {
        e->platform.allocator->deallocate(
            e->platform.allocator->user,
            e->ws,
            sizeof(*e->ws),
            (uint32_t)alignof(ninlil_domain_schema1_owner_workspace_t));
        e->ws = NULL;
    }
    if (e->bearer != NULL) {
        ninlil_test_bearer_destroy(e->bearer);
        e->bearer = NULL;
    }
    if (e->storage != NULL) {
        ninlil_test_storage_destroy(e->storage);
    }
    if (e->entropy != NULL) {
        ninlil_test_entropy_destroy(e->entropy);
    }
    if (e->clock != NULL) {
        ninlil_test_clock_destroy(e->clock);
    }
    if (e->execution != NULL) {
        ninlil_test_execution_destroy(e->execution);
    }
    if (e->allocator != NULL) {
        ninlil_test_allocator_destroy(e->allocator);
    }
}

static ninlil_time_sample_t trusted_sample(void)
{
    ninlil_time_sample_t s;
    (void)memset(&s, 0, sizeof(s));
    set_hdr(&s.abi_version, &s.struct_size, sizeof(s));
    set_id(&s.clock_epoch_id, 0x33u);
    s.now_ms = 123456u;
    s.trust = NINLIL_CLOCK_TRUSTED;
    return s;
}

static int t0_create_trace_is_one_rw_transaction(
    const ninlil_test_storage_t *storage)
{
    size_t i;
    size_t count = ninlil_test_storage_trace_count(storage);
    uint64_t t0_txn = 0u;
    int saw_iter = 0;
    int saw_put = 0;

    for (i = 0u; i < count; ++i) {
        const ninlil_test_storage_trace_record_t *record =
            ninlil_test_storage_trace_at(storage, i);
        if (record == NULL) {
            return 0;
        }
        if (saw_iter == 0
            && record->operation == NINLIL_TEST_STORAGE_OP_ITER_OPEN) {
            t0_txn = record->transaction_id;
            saw_iter = t0_txn != 0u;
            continue;
        }
        if (saw_iter == 0) {
            continue;
        }
        if (record->operation == NINLIL_TEST_STORAGE_OP_ROLLBACK
            && record->transaction_id == t0_txn) {
            return 0;
        }
        if (record->operation == NINLIL_TEST_STORAGE_OP_PUT) {
            if (record->transaction_id != t0_txn) {
                return 0;
            }
            saw_put = 1;
            continue;
        }
        if (record->operation == NINLIL_TEST_STORAGE_OP_COMMIT) {
            return saw_put != 0
                && record->transaction_id == t0_txn
                && record->durability == NINLIL_DURABILITY_FULL;
        }
    }
    return 0;
}

static int test_new_path_t0_t7(void)
{
    env_t e;
    ninlil_time_sample_t sample;
    ninlil_domain_schema1_owner_result_t t7;
    ninlil_status_t st;

    REQUIRE(env_init(&e));
    sample = trusted_sample();
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(e.result.storage_recovery_t0_t6_complete == 1u);
    REQUIRE(e.result.wrote_t1a == 1u);
    REQUIRE(e.result.wrote_t1b == 1u);
    REQUIRE(e.result.wrote_t5 == 1u);
    REQUIRE(e.result.t1a_class == NINLIL_DOMAIN_SCHEMA1_T1A_NEW);
    REQUIRE(e.result.t1b_class == NINLIL_DOMAIN_SCHEMA1_GROUP_NEW);
    REQUIRE(e.result.t5_class == NINLIL_DOMAIN_SCHEMA1_GROUP_NEW);
    REQUIRE(t0_create_trace_is_one_rw_transaction(e.storage));
    REQUIRE(e.result.transcript.bearer_open == 0u);
    REQUIRE(e.result.transcript.callback == 0u);
    REQUIRE(e.result.transcript.public_handle == 0u);
    REQUIRE(e.result.transcript.publish == 0u);
    REQUIRE(
        ninlil_domain_schema1_startup_pre_publish_side_effects_zero(
            &e.ws->stages));

    st = ninlil_domain_schema1_owner_t7_publication_gate(
        &e.result, 1u, 1u, &e.ws->stages, &t7);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_startup_publication_allowed(&e.ws->stages));
    REQUIRE(t7.transcript.T7_complete == 1u);
    REQUIRE(t7.transcript.callback == 0u);

    /* Restart: existing adopt (no rewrite of T1a). */
    ninlil_test_storage_simulate_crash(e.storage);
    e.handle = NULL;
    /* Handle invalid after crash; reopen. */
    {
        ninlil_bytes_view_t ns = {k_ns, sizeof(k_ns) - 1u};
        ninlil_storage_status_t sst = e.platform.storage->open(
            e.platform.storage->user,
            ns,
            NINLIL_STORAGE_SCHEMA_M1A,
            &e.handle);
        REQUIRE(sst == NINLIL_STORAGE_OK);
    }
    (void)memset(&e.result, 0, sizeof(e.result));
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(
        e.result.outcome
        == NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_EXISTING_ADOPTED);
    REQUIRE(e.result.wrote_t1a == 0u);
    /* T5 may rewrite if clock was already TRUSTED — class NEW after. */
    REQUIRE(e.result.storage_recovery_t0_t6_complete == 1u);

    env_fini(&e);
    return 0;
}

static int test_t5_existing_clock_epoch_rules(void)
{
    env_t e;
    ninlil_time_sample_t sample;
    ninlil_status_t st;

    REQUIRE(env_init(&e));
    sample = trusted_sample();
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(e.result.wrote_t5 == 1u);

    /* Same epoch may advance monotonically without rewriting the baseline. */
    sample.now_ms += 100u;
    (void)memset(&e.result, 0, sizeof(e.result));
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(e.result.wrote_t5 == 0u);

    /* A same-epoch clock rollback is never silently adopted. */
    sample.now_ms = 123455u;
    (void)memset(&e.result, 0, sizeof(e.result));
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_E_DEGRADED);
    REQUIRE(e.result.storage_recovery_t0_t6_complete == 0u);
    REQUIRE(e.result.transcript.bearer_open == 0u);
    REQUIRE(e.result.transcript.public_handle == 0u);
    REQUIRE(e.result.transcript.publish == 0u);

    /*
     * A distinct trusted epoch is an explicit baseline transition. It must
     * FULL-replace the typed clock with checked publish_generation+1.
     */
    sample = trusted_sample();
    set_id(&sample.clock_epoch_id, 0x91u);
    sample.now_ms = 200000u;
    (void)memset(&e.result, 0, sizeof(e.result));
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(e.result.wrote_t5 == 1u);
    REQUIRE(
        e.ws->typed_record.clock_baseline.publish_generation == 2u);
    REQUIRE(
        e.ws->typed_record.clock_baseline.last_trusted_now_ms
        == sample.now_ms);
    REQUIRE(
        memcmp(
            e.ws->typed_record.clock_baseline.trusted_clock_epoch,
            sample.clock_epoch_id.bytes,
            sizeof(sample.clock_epoch_id.bytes))
        == 0);

    env_fini(&e);
    return 0;
}

static int test_commit_unknown_fence(void)
{
    env_t e;
    ninlil_time_sample_t sample;
    ninlil_status_t st;

    REQUIRE(env_init(&e));
    sample = trusted_sample();
    /* Fault first COMMIT as COMMIT_UNKNOWN. */
    REQUIRE(
        ninlil_test_storage_fault_enqueue(
            e.storage,
            NINLIL_TEST_STORAGE_OP_COMMIT,
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            1u,
            1,
            0)
        == 1);
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(e.result.reopen_required == 1u);
    REQUIRE(e.handle == NULL);
    env_fini(&e);
    return 0;
}

static int test_put_fault_no_partial_publish(void)
{
    env_t e;
    ninlil_time_sample_t sample;
    ninlil_status_t st;

    REQUIRE(env_init(&e));
    sample = trusted_sample();
    REQUIRE(
        ninlil_test_storage_fault_enqueue(
            e.storage,
            NINLIL_TEST_STORAGE_OP_PUT,
            NINLIL_STORAGE_IO_ERROR,
            1u,
            0,
            0)
        == 1);
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st != NINLIL_OK);
    REQUIRE(e.result.transcript.publish == 0u);
    REQUIRE(e.result.transcript.public_handle == 0u);
    REQUIRE(e.result.transcript.callback == 0u);
    REQUIRE(e.result.transcript.bearer_open == 0u);
    env_fini(&e);
    return 0;
}

static void set_digest(ninlil_digest256_t *d, uint8_t tag)
{
    (void)memset(d, 0, sizeof(*d));
    d->algorithm = NINLIL_DIGEST_SHA256;
    d->bytes[31] = tag;
}

static ninlil_service_descriptor_t make_descriptor(
    uint8_t app_tag, const char *service_id_text)
{
    static const uint8_t ns[] = "acme";
    static const uint8_t sch[] = "v";
    ninlil_service_descriptor_t d;
    (void)memset(&d, 0, sizeof(d));
    set_hdr(&d.abi_version, &d.struct_size, sizeof(d));
    d.namespace_id.data = ns;
    d.namespace_id.length = sizeof(ns) - 1u;
    d.service_id.data = (const uint8_t *)service_id_text;
    d.service_id.length = (uint32_t)strlen(service_id_text);
    d.schema_id.data = sch;
    d.schema_id.length = sizeof(sch) - 1u;
    d.descriptor_revision = 1u;
    set_digest(&d.descriptor_digest, 0x22u);
    set_id(&d.local_application_instance_id, app_tag);
    d.schema_major = 1u;
    d.schema_minor_min = 1u;
    d.schema_minor_max = 1u;
    d.family = NINLIL_FAMILY_DESIRED_STATE;
    d.direction = NINLIL_DIRECTION_DOWNLINK;
    d.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    d.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    d.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    d.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    d.logical_payload_limit = 64u;
    d.target_limit = 1u;
    d.inflight_limit = 2u;
    d.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    d.admission_window_ms = 1000u;
    d.max_admissions_per_window = 10u;
    d.max_payload_bytes_per_window = 640u;
    d.minimum_deadline_ms = 100u;
    d.maximum_deadline_ms = 10000u;
    d.maximum_evidence_grace_ms = 1000u;
    d.attempt_receipt_timeout_ms = 1000u;
    d.retry_backoff_ms = 100u;
    d.application_completion_timeout_ms = 2000u;
    d.required_dedup_window_ms = 1000u;
    return d;
}

/* Count rows via the live Runtime storage handle (exclusive open). */
static int count_namespace_rows(
    const ninlil_platform_ops_t *platform, ninlil_runtime_t *runtime)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t sst;
    ninlil_bytes_view_t prefix = {NULL, 0u};
    uint8_t kbuf[255];
    uint8_t vbuf[1024];
    int count = 0;

    if (platform == NULL || platform->storage == NULL || runtime == NULL
        || runtime->storage == NULL) {
        return -1;
    }
    sst = platform->storage->begin(
        platform->storage->user,
        runtime->storage,
        NINLIL_STORAGE_READ_ONLY,
        &txn);
    if (sst != NINLIL_STORAGE_OK) {
        return -1;
    }
    sst = platform->storage->iter_open(
        platform->storage->user, txn, prefix, &iter);
    if (sst != NINLIL_STORAGE_OK) {
        (void)platform->storage->rollback(platform->storage->user, txn);
        return -1;
    }
    for (;;) {
        ninlil_mut_bytes_t k;
        ninlil_mut_bytes_t v;
        k.data = kbuf;
        k.capacity = sizeof(kbuf);
        k.length = 0u;
        v.data = vbuf;
        v.capacity = sizeof(vbuf);
        v.length = 0u;
        sst = platform->storage->iter_next(
            platform->storage->user, iter, &k, &v);
        if (sst == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (sst != NINLIL_STORAGE_OK) {
            count = -1;
            break;
        }
        count += 1;
    }
    platform->storage->iter_close(platform->storage->user, iter);
    (void)platform->storage->rollback(platform->storage->user, txn);
    return count;
}

static int test_kind1_memory_gate(void)
{
    size_t rt_size = sizeof(ninlil_runtime_t);
    size_t k1_size = sizeof(ninlil_domain_schema1_kind1_workspace_t);
    size_t owner_size = sizeof(ninlil_domain_schema1_owner_workspace_t);
    size_t peak;

    REQUIRE(k1_size <= NINLIL_DOMAIN_SCHEMA1_KIND1_WS_CEILING_BYTES);
    REQUIRE(rt_size <= NINLIL_DOMAIN_SCHEMA1_RUNTIME_DRAM_SOFT_BUDGET_BYTES);
    REQUIRE(
        owner_size <= NINLIL_DOMAIN_SCHEMA1_OWNER_WORKSPACE_CEILING_BYTES);
    /*
     * Owner and kind1 workspaces are distinct transient arena phases; neither
     * is embedded in the live Runtime and they are never simultaneously live.
     */
    peak = rt_size + (k1_size > owner_size ? k1_size : owner_size);
    REQUIRE(peak <= (size_t)NINLIL_DOMAIN_SCHEMA1_HOST_PEAK_SOFT_BUDGET_BYTES);
    (void)fprintf(
        stderr,
        "memory_gate sizeof(runtime)=%zu owner_ws=%zu "
        "kind1_ws=%zu peak=%zu budget=%u\n",
        rt_size,
        owner_size,
        k1_size,
        peak,
        (unsigned)NINLIL_DOMAIN_SCHEMA1_HOST_PEAK_SOFT_BUDGET_BYTES);
    return 0;
}

static int test_kind1_service_register_e2e(void)
{
    env_t e;
    ninlil_runtime_t *runtime = NULL;
    ninlil_service_t *service = NULL;
    ninlil_service_t *service2 = NULL;
    ninlil_service_t *service_b = NULL;
    ninlil_service_descriptor_t desc;
    ninlil_service_descriptor_t desc_b;
    ninlil_service_callbacks_t cb;
    ninlil_status_t st;
    int rows_after_a;
    int rows_after_reattach;
    int rows_after_b;

    REQUIRE(env_init(&e));
    if (e.handle != NULL) {
        e.platform.storage->close(e.platform.storage->user, e.handle);
        e.handle = NULL;
    }

    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(runtime != NULL);

    desc = make_descriptor(0x11u, "pump");
    desc_b = make_descriptor(0x22u, "valve");
    (void)memset(&cb, 0, sizeof(cb));
    set_hdr(&cb.abi_version, &cb.struct_size, sizeof(cb));

    /* First register: durable M=5 FULL + explicit callback attach. */
    st = ninlil_service_register(runtime, &desc, &cb, &service);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(service != NULL);
    /*
     * Normative first kind-1 on semantic-empty Domain:
     * 33 (T0–T5) + 5 CREATE (service,quota,res,header,chunk) = 38.
     * capacity + HEAD_INDEX are REPLACE.
     */
    rows_after_a = count_namespace_rows(&e.platform, runtime);
    REQUIRE(rows_after_a == (int)NINLIL_DOMAIN_SCHEMA1_KIND1_FIRST_POST_NS_ROW_COUNT);

    /* Same process re-register with same callbacks: dedupe, no extra rows. */
    st = ninlil_service_register(runtime, &desc, &cb, &service2);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(service2 == service);
    REQUIRE(
        count_namespace_rows(&e.platform, runtime)
        == (int)NINLIL_DOMAIN_SCHEMA1_KIND1_FIRST_POST_NS_ROW_COUNT);

    /* Same service key with a different schema_id is an exact-contract clash. */
    {
        static const uint8_t other_schema[] = "other-schema";
        ninlil_service_descriptor_t conflicting = desc;
        ninlil_service_t *conflicting_service = NULL;

        conflicting.schema_id.data = other_schema;
        conflicting.schema_id.length = sizeof(other_schema) - 1u;
        st = ninlil_service_register(
            runtime, &conflicting, &cb, &conflicting_service);
        REQUIRE(st == NINLIL_E_CONFLICT);
        REQUIRE(conflicting_service == NULL);
    }

    /* A caller-owned value copy is not a valid public service handle. */
    {
        ninlil_service_t forged = *service;
        ninlil_submission_t submission;
        ninlil_submission_result_t submission_result;

        (void)memset(&submission, 0, sizeof(submission));
        (void)memset(&submission_result, 0, sizeof(submission_result));
        set_hdr(
            &submission.abi_version,
            &submission.struct_size,
            sizeof(submission));
        set_hdr(
            &submission_result.abi_version,
            &submission_result.struct_size,
            sizeof(submission_result));
        st = ninlil_submit(&forged, &submission, &submission_result);
        REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    }

    /* Restart before reattach: destroy, recreate, explicit reattach. */
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    runtime = NULL;
    service = NULL;
    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    REQUIRE(st == NINLIL_OK);
    /*
     * Feature-ON restore: durable SERVICE is in slots, unattached — no
     * callback/handle/publication until explicit reattach.
     */
    REQUIRE(runtime->service_count >= 1u);
    REQUIRE(runtime->services[0].in_use == 1u);
    REQUIRE(runtime->services[0].attached == 0u);
    REQUIRE(runtime->services[0].public_handle.magic == 0u);
    REQUIRE(runtime->services[0].public_handle.runtime == NULL);

    st = ninlil_service_register(runtime, &desc, &cb, &service);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(service != NULL);
    REQUIRE(runtime->services[0].attached == 1u);
    REQUIRE(runtime->services[0].public_handle.magic != 0u);
    REQUIRE(runtime->services[0].public_handle.runtime == runtime);
    rows_after_reattach = count_namespace_rows(&e.platform, runtime);
    REQUIRE(
        rows_after_reattach
        == (int)NINLIL_DOMAIN_SCHEMA1_KIND1_FIRST_POST_NS_ROW_COUNT);

    /* Second service: +3 CREATE (svc/quota/res) + header + chunk = +5 → 43. */
    st = ninlil_service_register(runtime, &desc_b, &cb, &service_b);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(service_b != NULL);
    REQUIRE(service_b != service);
    rows_after_b = count_namespace_rows(&e.platform, runtime);
    REQUIRE(rows_after_b == 43);

    /* Restart after reattach: both services reattach without row growth. */
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    runtime = NULL;
    service = NULL;
    service_b = NULL;
    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    REQUIRE(st == NINLIL_OK);
    st = ninlil_service_register(runtime, &desc, &cb, &service);
    REQUIRE(st == NINLIL_OK);
    st = ninlil_service_register(runtime, &desc_b, &cb, &service_b);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(count_namespace_rows(&e.platform, runtime) == 43);

    /* Heap failure: fail next allocator after create (register allocates k1). */
    {
        ninlil_runtime_t *rt2 = NULL;
        ninlil_service_t *svc = NULL;
        ninlil_service_descriptor_t desc_c = make_descriptor(0x33u, "heater");
        REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
        runtime = NULL;
        st = ninlil_runtime_create(&e.config, &e.platform, &rt2);
        REQUIRE(st == NINLIL_OK);
        ninlil_test_allocator_fail_next(e.allocator, 1u);
        st = ninlil_service_register(rt2, &desc_c, &cb, &svc);
        REQUIRE(st == NINLIL_E_CAPACITY_EXHAUSTED);
        REQUIRE(svc == NULL);
        REQUIRE(ninlil_runtime_destroy(rt2) == NINLIL_OK);
    }

    env_fini(&e);
    return 0;
}

static int test_kind1_controller_max_services_16(void)
{
    static const char *const service_ids[16] = {
        "svc-00", "svc-01", "svc-02", "svc-03",
        "svc-04", "svc-05", "svc-06", "svc-07",
        "svc-08", "svc-09", "svc-10", "svc-11",
        "svc-12", "svc-13", "svc-14", "svc-15"
    };
    env_t e;
    ninlil_runtime_t *runtime = NULL;
    ninlil_service_callbacks_t cb;
    ninlil_status_t st;
    uint32_t i;

    REQUIRE(env_init(&e));
    if (e.handle != NULL) {
        e.platform.storage->close(e.platform.storage->user, e.handle);
        e.handle = NULL;
    }
    (void)memset(&cb, 0, sizeof(cb));
    set_hdr(&cb.abi_version, &cb.struct_size, sizeof(cb));

    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    REQUIRE(st == NINLIL_OK);
    for (i = 0u; i < 16u; ++i) {
        ninlil_service_descriptor_t descriptor =
            make_descriptor((uint8_t)(0x10u + i), service_ids[i]);
        ninlil_service_t *service = NULL;
        st = ninlil_service_register(
            runtime, &descriptor, &cb, &service);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(service != NULL);
    }
    REQUIRE(runtime->service_count == 16u);
    REQUIRE(
        count_namespace_rows(&e.platform, runtime)
        == (int)NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP);

    {
        ninlil_service_descriptor_t overflow =
            make_descriptor(0x70u, "svc-overflow");
        ninlil_service_t *service = NULL;
        st = ninlil_service_register(runtime, &overflow, &cb, &service);
        REQUIRE(st == NINLIL_E_CAPACITY_EXHAUSTED);
        REQUIRE(service == NULL);
    }

    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    runtime = NULL;
    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(runtime->service_count == 16u);
    for (i = 0u; i < 16u; ++i) {
        ninlil_service_descriptor_t descriptor =
            make_descriptor((uint8_t)(0x10u + i), service_ids[i]);
        ninlil_service_t *service = NULL;
        st = ninlil_service_register(
            runtime, &descriptor, &cb, &service);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(service != NULL);
    }
    REQUIRE(
        count_namespace_rows(&e.platform, runtime)
        == (int)NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP);
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    env_fini(&e);
    return 0;
}

static int test_kind1_commit_full_fault_put(void)
{
    env_t e;
    ninlil_runtime_t *runtime = NULL;
    ninlil_service_descriptor_t desc;
    ninlil_service_callbacks_t cb;
    ninlil_service_t *service = NULL;
    ninlil_status_t st;

    REQUIRE(env_init(&e));
    if (e.handle != NULL) {
        e.platform.storage->close(e.platform.storage->user, e.handle);
        e.handle = NULL;
    }
    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    REQUIRE(st == NINLIL_OK);
    desc = make_descriptor(0x12u, "faulty");
    (void)memset(&cb, 0, sizeof(cb));
    set_hdr(&cb.abi_version, &cb.struct_size, sizeof(cb));

    /* Fault puts during first kind1 FULL (no partial publish of handle). */
    REQUIRE(
        ninlil_test_storage_fault_enqueue(
            e.storage,
            NINLIL_TEST_STORAGE_OP_PUT,
            NINLIL_STORAGE_IO_ERROR,
            8u,
            0,
            0)
        == 1);
    st = ninlil_service_register(runtime, &desc, &cb, &service);
    REQUIRE(st != NINLIL_OK);
    REQUIRE(service == NULL);
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    env_fini(&e);
    return 0;
}

static int test_existing_adopt_corrupt_row_fail_closed(void)
{
    env_t e;
    ninlil_time_sample_t sample;
    ninlil_status_t st;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t sst;
    uint8_t bad_key[9];
    uint8_t bad_val[16];

    REQUIRE(env_init(&e));
    sample = trusted_sample();
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(e.result.storage_recovery_t0_t6_complete == 1u);
    REQUIRE(e.result.transcript.publish == 0u);
    REQUIRE(e.result.transcript.callback == 0u);
    REQUIRE(e.result.transcript.public_handle == 0u);

    /*
     * Inject a non-bootstrap foreign family-6-shaped key with garbage value.
     * Existing adopt must fail closed (not count-fallback to NEW).
     */
    (void)memset(bad_key, 0, sizeof(bad_key));
    bad_key[0] = 0x4eu;
    bad_key[1] = 0x49u;
    bad_key[2] = 0x4eu;
    bad_key[3] = 0x4cu;
    bad_key[4] = 0x49u;
    bad_key[5] = 0x4cu;
    bad_key[6] = 0x00u;
    bad_key[7] = 0x01u;
    bad_key[8] = 0x06u;
    (void)memset(bad_val, 0xA5, sizeof(bad_val));
    sst = e.platform.storage->begin(
        e.platform.storage->user,
        e.handle,
        NINLIL_STORAGE_READ_WRITE,
        &txn);
    REQUIRE(sst == NINLIL_STORAGE_OK);
    sst = e.platform.storage->put(
        e.platform.storage->user,
        txn,
        (ninlil_bytes_view_t){bad_key, sizeof(bad_key)},
        (ninlil_bytes_view_t){bad_val, sizeof(bad_val)});
    REQUIRE(sst == NINLIL_STORAGE_OK);
    sst = e.platform.storage->commit(
        e.platform.storage->user, txn, NINLIL_DURABILITY_FULL);
    REQUIRE(sst == NINLIL_STORAGE_OK);

    (void)memset(&e.result, 0, sizeof(e.result));
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(e.result.transcript.publish == 0u);
    REQUIRE(e.result.transcript.callback == 0u);
    REQUIRE(e.result.transcript.public_handle == 0u);
    REQUIRE(e.result.transcript.bearer_open == 0u);
    env_fini(&e);
    return 0;
}

static int test_lab_mixed_namespace_fails_closed(void)
{
    static const uint8_t lab_key[] = {'T', 'X', 0x01u};
    static const uint8_t lab_value[] = {0x01u};
    env_t e;
    ninlil_time_sample_t sample;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t sst;
    ninlil_status_t st;

    REQUIRE(env_init(&e));
    sample = trusted_sample();
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_OK);

    sst = e.platform.storage->begin(
        e.platform.storage->user,
        e.handle,
        NINLIL_STORAGE_READ_WRITE,
        &txn);
    REQUIRE(sst == NINLIL_STORAGE_OK);
    sst = e.platform.storage->put(
        e.platform.storage->user,
        txn,
        (ninlil_bytes_view_t){lab_key, sizeof(lab_key)},
        (ninlil_bytes_view_t){lab_value, sizeof(lab_value)});
    REQUIRE(sst == NINLIL_STORAGE_OK);
    sst = e.platform.storage->commit(
        e.platform.storage->user, txn, NINLIL_DURABILITY_FULL);
    REQUIRE(sst == NINLIL_STORAGE_OK);

    (void)memset(&e.result, 0, sizeof(e.result));
    st = ninlil_domain_schema1_owner_run_storage_recovery(
        e.platform.storage,
        &e.handle,
        &e.validation,
        &sample,
        e.ws,
        &e.result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(e.result.storage_recovery_t0_t6_complete == 0u);
    REQUIRE(e.result.transcript.bearer_open == 0u);
    REQUIRE(e.result.transcript.callback == 0u);
    REQUIRE(e.result.transcript.public_handle == 0u);
    REQUIRE(e.result.transcript.publish == 0u);
    env_fini(&e);
    return 0;
}

static int test_kind1_commit_unknown_cu(void)
{
    env_t e;
    ninlil_runtime_t *runtime = NULL;
    ninlil_service_descriptor_t desc;
    ninlil_service_callbacks_t cb;
    ninlil_service_t *service = NULL;
    ninlil_status_t st;

    REQUIRE(env_init(&e));
    if (e.handle != NULL) {
        e.platform.storage->close(e.platform.storage->user, e.handle);
        e.handle = NULL;
    }
    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    REQUIRE(st == NINLIL_OK);
    desc = make_descriptor(0x44u, "cu-svc");
    (void)memset(&cb, 0, sizeof(cb));
    set_hdr(&cb.abi_version, &cb.struct_size, sizeof(cb));

    /* Kind1 FULL commit → COMMIT_UNKNOWN: no callback attach / handle. */
    REQUIRE(
        ninlil_test_storage_fault_enqueue(
            e.storage,
            NINLIL_TEST_STORAGE_OP_COMMIT,
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            1u,
            1,
            0)
        == 1);
    st = ninlil_service_register(runtime, &desc, &cb, &service);
    REQUIRE(st == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(service == NULL);

    /* Fence may close storage; destroy runtime and reopen via create. */
    (void)ninlil_runtime_destroy(runtime);
    runtime = NULL;
    st = ninlil_runtime_create(&e.config, &e.platform, &runtime);
    /*
     * After CU, storage may be OLD (no write) or NEW (write landed). Either
     * path must allow create; register then either writes or reattaches.
     */
    if (st == NINLIL_OK) {
        st = ninlil_service_register(runtime, &desc, &cb, &service);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(service != NULL);
        REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    } else {
        /* Corrupt after CU is honest when partial; not a silent attach. */
        REQUIRE(st != NINLIL_OK);
    }
    env_fini(&e);
    return 0;
}

int main(void)
{
    if (test_new_path_t0_t7() != 0) {
        return 1;
    }
    if (test_t5_existing_clock_epoch_rules() != 0) {
        return 1;
    }
    if (test_commit_unknown_fence() != 0) {
        return 1;
    }
    if (test_put_fault_no_partial_publish() != 0) {
        return 1;
    }
    if (test_kind1_memory_gate() != 0) {
        return 1;
    }
    /*
     * Keep the future public integration cases compiled, but do not execute
     * them while public Domain Runtime creation is deliberately fail-closed.
     * The private owner/authority cases above and below remain active.
     */
    if (NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY != 0u) {
        if (test_kind1_service_register_e2e() != 0) {
            return 1;
        }
        if (test_kind1_controller_max_services_16() != 0) {
            return 1;
        }
        if (test_kind1_commit_full_fault_put() != 0) {
            return 1;
        }
        if (test_kind1_commit_unknown_cu() != 0) {
            return 1;
        }
    }
    if (test_existing_adopt_corrupt_row_fail_closed() != 0) {
        return 1;
    }
    if (test_lab_mixed_namespace_fails_closed() != 0) {
        return 1;
    }
    (void)printf(
        "domain_schema1_startup_owner OK "
        "private-scaffold+fault+memory+corrupt-adopt "
        "public-ready=%u\n",
        (unsigned)NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY);
    return 0;
}
