/*
 * External installed-package consumer.
 *
 * This file deliberately includes only installed public headers and links only
 * installed CMake targets. It creates, steps, and destroys a real Runtime with
 * a minimal valid Host platform fixture. The default executable supplies a
 * consumer-owned bounded in-memory storage provider through the public ABI, so
 * it proves that Ninlil::runtime is usable without the optional SQLite port.
 * An optional second executable repeats the lifecycle with the installed
 * SQLite target.
 */

#include <ninlil/runtime.h>

#if defined(NINLIL_CONSUMER_WITH_SQLITE)
#include <ninlil_posix_sqlite_storage.h>
#else
#include "memory_storage.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct consumer_fixture {
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_bearer_ops_t bearer;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
    uint64_t entropy_counter;
    uint64_t now_ms;
    ninlil_tx_gate_status_t tx_gate_status;
    uint64_t tx_gate_calls;
    uint8_t bearer_token;
} consumer_fixture_t;

static const uint8_t STORAGE_NAMESPACE[] =
    "installed-host-runtime-consumer";

static void set_header(
    uint16_t *abi_version,
    uint16_t *struct_size,
    size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;

    for (index = 0u; index < NINLIL_ID_BYTES; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static int power_of_two(uint32_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static void *fixture_allocate(
    void *user,
    uint64_t size,
    uint32_t alignment)
{
    (void)user;
    if (size == 0u || size > (uint64_t)SIZE_MAX
        || !power_of_two(alignment)
        || alignment > (uint32_t)_Alignof(max_align_t)) {
        return NULL;
    }
    return malloc((size_t)size);
}

static void fixture_deallocate(
    void *user,
    void *pointer,
    uint64_t size,
    uint32_t alignment)
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
    void *user,
    ninlil_time_sample_t *out_sample)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;

    if (fixture == NULL || out_sample == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    (void)memset(out_sample, 0, sizeof(*out_sample));
    set_header(
        &out_sample->abi_version,
        &out_sample->struct_size,
        sizeof(*out_sample));
    set_id(&out_sample->clock_epoch_id, 0xa0u);
    out_sample->now_ms = fixture->now_ms;
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static ninlil_port_status_t fixture_entropy_fill(
    void *user,
    uint8_t *out,
    uint32_t length)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;
    uint32_t index;

    if (fixture == NULL || out == NULL || length == 0u) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    fixture->entropy_counter += 1u;
    for (index = 0u; index < length; ++index) {
        out[index] = (uint8_t)(
            1u + ((fixture->entropy_counter * 37u + index * 17u) % 251u));
    }
    return NINLIL_PORT_OK;
}

static ninlil_bearer_status_t fixture_bearer_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;

    if (fixture == NULL || runtime_id == NULL || out_handle == NULL
        || (role != NINLIL_ROLE_CONTROLLER
            && role != NINLIL_ROLE_ENDPOINT
            && role != NINLIL_ROLE_CELL_AGENT)) {
        return NINLIL_BEARER_DENIED;
    }
    *out_handle = &fixture->bearer_token;
    return NINLIL_BEARER_OK;
}

static void fixture_bearer_close(
    void *user,
    ninlil_bearer_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_bearer_status_t fixture_bearer_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    (void)user;
    (void)handle;
    (void)permit;
    (void)message;
    (void)out_result;
    return NINLIL_BEARER_WOULD_BLOCK;
}

static ninlil_bearer_status_t fixture_bearer_receive_next(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    (void)user;
    (void)handle;
    (void)out_message;
    return NINLIL_BEARER_EMPTY;
}

static void fixture_bearer_release_received(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    (void)user;
    (void)handle;
    (void)message;
}

static ninlil_bearer_status_t fixture_bearer_state(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state)
{
    (void)user;
    if (handle == NULL || out_state == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    set_header(
        &out_state->abi_version,
        &out_state->struct_size,
        sizeof(*out_state));
    out_state->availability_epoch = 1u;
    out_state->available = 1u;
    return NINLIL_BEARER_OK;
}

static ninlil_tx_gate_status_t fixture_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    consumer_fixture_t *fixture = (consumer_fixture_t *)user;

    (void)request;
    (void)now;
    if (fixture == NULL || out_permit == NULL) {
        return NINLIL_TX_GATE_DENIED;
    }
    fixture->tx_gate_calls += 1u;
    (void)memset(out_permit, 0, sizeof(*out_permit));
    return fixture->tx_gate_status;
}

static void fixture_tx_release_unused(
    void *user,
    const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t fixture_origin_evaluate(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    (void)user;
    if (request == NULL || out_decision == NULL) {
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    (void)memset(out_decision, 0, sizeof(*out_decision));
    set_header(
        &out_decision->abi_version,
        &out_decision->struct_size,
        sizeof(*out_decision));
    out_decision->allowed = 1u;
    out_decision->reason = NINLIL_REASON_NONE;
    out_decision->retry_guidance = NINLIL_RETRY_NEVER;
    set_id(&out_decision->provider_id, 0xd0u);
    out_decision->provider_revision = 1u;
    out_decision->decision_digest.algorithm = NINLIL_DIGEST_SHA256;
    out_decision->decision_digest.bytes[NINLIL_SHA256_BYTES - 1u] = 0xd1u;
    set_id(&out_decision->grant_id, 0xd2u);
    out_decision->grant_revision = 1u;
    out_decision->clock_epoch_id = request->now.clock_epoch_id;
    out_decision->evaluated_at_ms = request->now.now_ms;
    out_decision->valid_from_ms = 0u;
    out_decision->expires_at_ms = UINT64_MAX;
    out_decision->max_payload_bytes = 1024u;
    out_decision->max_active_spool_count = 16u;
    out_decision->max_active_spool_bytes = 16384u;
    out_decision->rate_window_ms = 10000u;
    out_decision->max_admissions_per_window = 16u;
    out_decision->max_attempts_per_retry_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    return NINLIL_ORIGIN_AUTH_OK;
}

static void fixture_init(
    consumer_fixture_t *fixture,
    const ninlil_storage_ops_t *storage)
{
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->now_ms = 1000u;
    fixture->tx_gate_status = NINLIL_TX_GATE_DENIED;

    set_header(
        &fixture->allocator.abi_version,
        &fixture->allocator.struct_size,
        sizeof(fixture->allocator));
    fixture->allocator.allocate = fixture_allocate;
    fixture->allocator.deallocate = fixture_deallocate;

    set_header(
        &fixture->execution.abi_version,
        &fixture->execution.struct_size,
        sizeof(fixture->execution));
    fixture->execution.current_context_id = fixture_context_id;

    set_header(
        &fixture->clock.abi_version,
        &fixture->clock.struct_size,
        sizeof(fixture->clock));
    fixture->clock.user = fixture;
    fixture->clock.now = fixture_now;

    set_header(
        &fixture->entropy.abi_version,
        &fixture->entropy.struct_size,
        sizeof(fixture->entropy));
    fixture->entropy.user = fixture;
    fixture->entropy.fill = fixture_entropy_fill;

    set_header(
        &fixture->bearer.abi_version,
        &fixture->bearer.struct_size,
        sizeof(fixture->bearer));
    fixture->bearer.user = fixture;
    fixture->bearer.open = fixture_bearer_open;
    fixture->bearer.close = fixture_bearer_close;
    fixture->bearer.send = fixture_bearer_send;
    fixture->bearer.receive_next = fixture_bearer_receive_next;
    fixture->bearer.release_received = fixture_bearer_release_received;
    fixture->bearer.state = fixture_bearer_state;

    set_header(
        &fixture->tx_gate.abi_version,
        &fixture->tx_gate.struct_size,
        sizeof(fixture->tx_gate));
    fixture->tx_gate.user = fixture;
    fixture->tx_gate.acquire = fixture_tx_acquire;
    fixture->tx_gate.release_unused = fixture_tx_release_unused;

    set_header(
        &fixture->origin.abi_version,
        &fixture->origin.struct_size,
        sizeof(fixture->origin));
    fixture->origin.evaluate = fixture_origin_evaluate;

    set_header(
        &fixture->platform.abi_version,
        &fixture->platform.struct_size,
        sizeof(fixture->platform));
    fixture->platform.allocator = &fixture->allocator;
    fixture->platform.execution = &fixture->execution;
    fixture->platform.clock = &fixture->clock;
    fixture->platform.entropy = &fixture->entropy;
    fixture->platform.storage = storage;
    fixture->platform.bearer = &fixture->bearer;
    fixture->platform.tx_gate = &fixture->tx_gate;
    fixture->platform.origin_authorization = &fixture->origin;
}

static ninlil_runtime_config_t runtime_config_for(
    ninlil_role_t role,
    ninlil_environment_t environment,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    uint8_t identity_tag)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = role;
    config.environment = environment;
    set_id(&config.runtime_id, identity_tag);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(
        &config.local_identity.device_id,
        (uint8_t)(identity_tag + 0x10u));
    set_id(
        &config.local_identity.installation_id,
        (uint8_t)(identity_tag + 0x20u));
    set_id(
        &config.local_identity.site_domain_id,
        (uint8_t)(identity_tag + 0x30u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = storage_namespace;
    config.storage_namespace.length = storage_namespace_length;

    set_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions = 8u;
    config.limits.max_targets_per_transaction =
        NINLIL_FOUNDATION_MAX_EXACT_TARGETS;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes =
        role == NINLIL_ROLE_CONTROLLER ? 16384u : 0u;
    config.limits.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 8u;
    config.limits.max_nonterminal_deliveries = 8u;
    config.limits.max_event_spool_count =
        role == NINLIL_ROLE_ENDPOINT ? 8u : 0u;
    config.limits.max_event_spool_bytes =
        role == NINLIL_ROLE_ENDPOINT ? 8192u : 0u;
    config.limits.max_result_cache_entries = 8u;
    config.limits.max_retained_dispositions = 8u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 8u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static ninlil_runtime_config_t runtime_config(void)
{
    return runtime_config_for(
        NINLIL_ROLE_ENDPOINT,
        NINLIL_ENV_TEST,
        STORAGE_NAMESPACE,
        (uint32_t)(sizeof(STORAGE_NAMESPACE) - 1u),
        0x10u);
}

#define CONSUMER_REQUIRE(condition)                                           \
    do {                                                                      \
        if (!(condition)) {                                                   \
            (void)fprintf(                                                    \
                stderr,                                                       \
                "%s:%d: installed consumer assertion failed: %s\n",          \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition);                                                  \
            return 0;                                                         \
        }                                                                     \
    } while (0)

#if defined(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY)

static int exercise_domain_create_fail_closed(
    const ninlil_storage_ops_t *storage)
{
    consumer_fixture_t fixture;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_status_t status;

    fixture_init(&fixture, storage);
    config = runtime_config();
    status = ninlil_runtime_create(&config, &fixture.platform, &runtime);
    if (status != NINLIL_E_UNSUPPORTED || runtime != NULL) {
        (void)fprintf(
            stderr,
            "runtime create fail-closed mismatch: status=%d runtime=%p\n",
            (int)status,
            (void *)runtime);
        return 0;
    }
    return 1;
}

#else

static int id_equal(
    const ninlil_id128_t *left,
    const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, NINLIL_ID_BYTES) == 0;
}

static int digest_equal(
    const ninlil_digest256_t *left,
    const ninlil_digest256_t *right)
{
    return left->algorithm == right->algorithm
        && left->reserved_zero == right->reserved_zero
        && memcmp(left->bytes, right->bytes, NINLIL_SHA256_BYTES) == 0;
}

static int text_id_equals(
    const ninlil_text_id_t *actual,
    const char *expected);

static int get_capacity_used(
    ninlil_runtime_t *runtime,
    ninlil_resource_kind_t kind,
    uint64_t *out_used);

static void set_digest_bytes(
    ninlil_digest256_t *digest,
    const uint8_t bytes[NINLIL_SHA256_BYTES])
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(digest->bytes, bytes, NINLIL_SHA256_BYTES);
}

enum {
    CONSUMER_SERVICE_DISPLAY_COMMAND = 0,
    CONSUMER_SERVICE_ACCESS_EVENT = 1,
    CONSUMER_SERVICE_TEMPERATURE_TELEMETRY = 2,
    CONSUMER_SERVICE_TEMPERATURE_QUERY = 3,
    CONSUMER_SERVICE_COUNT = 4,
    CONSUMER_TRANSACTION_COUNT = 3
};

typedef struct consumer_services {
    ninlil_service_descriptor_t descriptors[CONSUMER_SERVICE_COUNT];
    ninlil_service_callbacks_t callbacks[CONSUMER_SERVICE_COUNT];
    ninlil_service_t *handles[CONSUMER_SERVICE_COUNT];
} consumer_services_t;

typedef struct consumer_persisted_transaction {
    ninlil_id128_t transaction_id;
    ninlil_digest256_t content_digest;
    uint64_t transaction_sequence;
    uint64_t record_revision;
    ninlil_transaction_state_t state;
    ninlil_outcome_t outcome;
    uint32_t service_index;
} consumer_persisted_transaction_t;

typedef struct consumer_restart_evidence {
    consumer_persisted_transaction_t
        transactions[CONSUMER_TRANSACTION_COUNT];
    uint64_t service_capacity_used;
    uint64_t transaction_capacity_used;
} consumer_restart_evidence_t;

enum {
    CONSUMER_EXACT_TRANSACTION_COUNT = 2,
    CONSUMER_EXACT_MAX_TARGETS =
        NINLIL_FOUNDATION_MAX_EXACT_TARGETS
};

typedef struct consumer_exact_transaction_evidence {
    ninlil_id128_t transaction_id;
    ninlil_digest256_t content_digest;
    uint64_t transaction_sequence;
    uint64_t record_revision;
    uint32_t target_count;
    ninlil_concrete_target_t targets[CONSUMER_EXACT_MAX_TARGETS];
    uint32_t attempt_in_cycle[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t retry_cycle_id[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t cumulative_attempts[CONSUMER_EXACT_MAX_TARGETS];
    uint32_t has_late_evidence[CONSUMER_EXACT_MAX_TARGETS];
    uint32_t evidence_counter_saturated[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t valid_evidence_count[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t duplicate_evidence_count[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t raw_evidence_overflow_count[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t late_evidence_count[CONSUMER_EXACT_MAX_TARGETS];
} consumer_exact_transaction_evidence_t;

typedef struct consumer_exact_restart_evidence {
    consumer_exact_transaction_evidence_t
        transactions[CONSUMER_EXACT_TRANSACTION_COUNT];
    uint64_t service_capacity_used;
    uint64_t transaction_capacity_used;
} consumer_exact_restart_evidence_t;

typedef struct consumer_future_target_snapshot {
    ninlil_target_snapshot_t known;
    uint8_t future_tail[32];
} consumer_future_target_snapshot_t;

static const char CONSUMER_NAMESPACE_ID[] = "org.ninlil.consumer";
static const char *const CONSUMER_SERVICE_IDS[CONSUMER_SERVICE_COUNT] = {
    "display.command",
    "access.event",
    "temperature.telemetry",
    "temperature.query",
};

static const uint8_t ACCESS_PAYLOAD[] = {
    0x00u, 0xffu, 0x80u, 0x7fu, 0x01u, 0x02u, 0x00u, 0xa5u,
    0x5au, 0xc3u, 0x28u, 0x10u, 0x20u, 0x30u, 0x40u, 0x00u,
};
static const uint8_t ACCESS_PAYLOAD_DIGEST[NINLIL_SHA256_BYTES] = {
    0x6cu, 0x17u, 0x25u, 0x54u, 0xf7u, 0x2fu, 0xe0u, 0x6cu,
    0x80u, 0x30u, 0x46u, 0xceu, 0xf3u, 0xefu, 0xd5u, 0xe6u,
    0xd7u, 0xa0u, 0x22u, 0x31u, 0x66u, 0xbau, 0x0eu, 0x4bu,
    0x6bu, 0x89u, 0x1du, 0xb4u, 0xb6u, 0xf1u, 0x09u, 0x49u,
};
static const uint8_t ACCESS_CONFLICT_PAYLOAD[] = {
    0x00u, 0xffu, 0x80u, 0x7fu, 0x01u, 0x02u, 0x00u, 0xa5u,
    0x5au, 0xc3u, 0x28u, 0x10u, 0x20u, 0x30u, 0x40u, 0xffu,
};
static const uint8_t ACCESS_CONFLICT_DIGEST[NINLIL_SHA256_BYTES] = {
    0xeau, 0x32u, 0x67u, 0xa0u, 0x33u, 0x8cu, 0x5eu, 0xe5u,
    0x6cu, 0xe7u, 0xffu, 0xf2u, 0xc1u, 0xc0u, 0xf0u, 0x12u,
    0x4du, 0xfcu, 0xfcu, 0x89u, 0xedu, 0x95u, 0x7bu, 0x57u,
    0xbcu, 0xcfu, 0xf4u, 0x8au, 0xd2u, 0x05u, 0x79u, 0xdeu,
};
static const uint8_t TEMPERATURE_PAYLOAD[] = {
    0x01u, 0x19u, 0x01u, 0x00u, 0xc4u, 0x09u,
};
static const uint8_t TEMPERATURE_DIGEST[NINLIL_SHA256_BYTES] = {
    0x2bu, 0x99u, 0x37u, 0xd4u, 0x6du, 0xa3u, 0x7bu, 0x59u,
    0xe6u, 0xb7u, 0xcdu, 0x7du, 0x45u, 0xe7u, 0xa7u, 0x1fu,
    0x7cu, 0x76u, 0xaeu, 0x3du, 0xe9u, 0xd7u, 0xd2u, 0x3eu,
    0xdbu, 0x92u, 0xdcu, 0x7cu, 0xdeu, 0x60u, 0xcau, 0x45u,
};
static const uint8_t QUERY_RESPONSE_PAYLOAD[] = {
    0x51u, 0x52u, 0x59u, 0x00u, 0x01u,
    0x02u, 0x03u, 0xffu, 0x7fu, 0x80u,
};
static const uint8_t QUERY_RESPONSE_DIGEST[NINLIL_SHA256_BYTES] = {
    0x08u, 0x25u, 0x0eu, 0xb1u, 0x0au, 0x17u, 0x1eu, 0x0eu,
    0x0du, 0x8eu, 0x81u, 0x32u, 0xdau, 0x69u, 0xb4u, 0x1cu,
    0x2au, 0x01u, 0x55u, 0x11u, 0x4au, 0x5bu, 0x7cu, 0x86u,
    0x5fu, 0xb1u, 0xc4u, 0xf0u, 0x93u, 0x8du, 0xbbu, 0xe6u,
};

static const uint8_t EXACT_FOUR_KEY[] = "desired-four-targets";
static const uint8_t EXACT_FOUR_PAYLOAD[] = {
    0x44u, 0x00u, 0xffu, 0x10u, 0x20u, 0x30u,
};
static const uint8_t EXACT_FOUR_CONFLICT_PAYLOAD[] = {
    0x44u, 0x00u, 0xffu, 0x10u, 0x20u, 0x31u,
};
static const uint8_t EXACT_FOUR_DIGEST[NINLIL_SHA256_BYTES] = {
    0xdcu, 0x07u, 0x25u, 0xaau, 0x07u, 0x86u, 0xbau, 0xb1u,
    0x8fu, 0x1cu, 0xc1u, 0x3bu, 0xc4u, 0x5fu, 0x52u, 0xe0u,
    0xf3u, 0xf1u, 0x75u, 0x7du, 0xb4u, 0x49u, 0x84u, 0x47u,
    0x8fu, 0x2bu, 0x41u, 0xf6u, 0x5au, 0xcdu, 0x65u, 0x27u,
};
static const uint8_t EXACT_FOUR_CONFLICT_DIGEST[NINLIL_SHA256_BYTES] = {
    0x6eu, 0x9fu, 0x41u, 0xa3u, 0x78u, 0xb0u, 0xefu, 0x98u,
    0x34u, 0xe6u, 0xc0u, 0x21u, 0xceu, 0xd2u, 0xe1u, 0x15u,
    0x03u, 0x69u, 0x20u, 0xe1u, 0x57u, 0x67u, 0xbbu, 0x78u,
    0x1au, 0xd9u, 0x1eu, 0x51u, 0x7cu, 0x69u, 0x1fu, 0xbau,
};
static const uint8_t EXACT_TWO_KEY[] = "desired-two-targets";
static const uint8_t EXACT_TWO_PAYLOAD[] = {
    0x22u, 0x7fu, 0x80u, 0x00u,
};
static const uint8_t EXACT_TWO_DIGEST[NINLIL_SHA256_BYTES] = {
    0x93u, 0x07u, 0x2bu, 0xbdu, 0x3bu, 0x2au, 0xd0u, 0xeeu,
    0xceu, 0x47u, 0x63u, 0xd6u, 0x24u, 0x90u, 0xe9u, 0x11u,
    0x31u, 0x67u, 0x19u, 0x40u, 0xaau, 0x2fu, 0x01u, 0x6bu,
    0xa6u, 0x97u, 0x32u, 0x7cu, 0x0fu, 0x37u, 0x0du, 0x58u,
};

static ninlil_callback_action_t desired_on_delivery(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    if (token == NULL || delivery == NULL || out_result == NULL) {
        return NINLIL_CALLBACK_FATAL;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t desired_on_reconcile(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    if (delivery == NULL || out_result == NULL) {
        return NINLIL_RECONCILE_OUTCOME_UNKNOWN;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    return NINLIL_RECONCILE_KNOWN_RESULT;
}

static ninlil_service_descriptor_t make_service_descriptor(
    uint32_t service_index)
{
    ninlil_service_descriptor_t descriptor;
    const char *service_id = CONSUMER_SERVICE_IDS[service_index];
    int event_sender =
        service_index == CONSUMER_SERVICE_ACCESS_EVENT
        || service_index == CONSUMER_SERVICE_TEMPERATURE_TELEMETRY;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version,
        &descriptor.struct_size,
        sizeof(descriptor));
    descriptor.namespace_id.data =
        (const uint8_t *)CONSUMER_NAMESPACE_ID;
    descriptor.namespace_id.length =
        (uint32_t)(sizeof(CONSUMER_NAMESPACE_ID) - 1u);
    descriptor.service_id.data = (const uint8_t *)service_id;
    descriptor.service_id.length = (uint32_t)strlen(service_id);
    descriptor.schema_id.data = (const uint8_t *)service_id;
    descriptor.schema_id.length = (uint32_t)strlen(service_id);
    descriptor.descriptor_revision = 1u;
    descriptor.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    descriptor.descriptor_digest.bytes[NINLIL_SHA256_BYTES - 1u] =
        (uint8_t)(0x70u + service_index);
    set_id(
        &descriptor.local_application_instance_id,
        (uint8_t)(0x70u + service_index));
    descriptor.schema_major = 1u;
    descriptor.family = event_sender
        ? NINLIL_FAMILY_EVENT_FACT
        : NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = event_sender
        ? NINLIL_DIRECTION_UPLINK
        : NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = event_sender
        ? NINLIL_AUTHORITY_ORIGIN_WITH_GRANT
        : NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy =
        NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 256u;
    descriptor.target_limit = event_sender
        ? 1u : NINLIL_FOUNDATION_MAX_EXACT_TARGETS;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 16u;
    descriptor.max_payload_bytes_per_window = 4096u;
    descriptor.minimum_deadline_ms =
        event_sender ? NINLIL_NO_DEADLINE : 5000u;
    descriptor.maximum_deadline_ms =
        event_sender ? NINLIL_NO_DEADLINE : 5000u;
    descriptor.maximum_evidence_grace_ms = event_sender ? 0u : 1000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    return descriptor;
}

enum {
    CONSUMER_ROLE_COUNT = 3,
    CONSUMER_ENVIRONMENT_COUNT = 4,
    CONSUMER_PROFILE_COUNT =
        CONSUMER_ROLE_COUNT * CONSUMER_ENVIRONMENT_COUNT
};

static const ninlil_role_t CONSUMER_ROLES[CONSUMER_ROLE_COUNT] = {
    NINLIL_ROLE_CONTROLLER,
    NINLIL_ROLE_ENDPOINT,
    NINLIL_ROLE_CELL_AGENT,
};

static const ninlil_environment_t
    CONSUMER_ENVIRONMENTS[CONSUMER_ENVIRONMENT_COUNT] = {
        NINLIL_ENV_TEST,
        NINLIL_ENV_LAB,
        NINLIL_ENV_FIELD,
        NINLIL_ENV_PRODUCTION,
    };

static int exercise_public_profile_case(
    const ninlil_storage_ops_t *storage,
    uint32_t profile_index)
{
    char storage_namespace[64];
    consumer_fixture_t fixture;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_role_t role;
    ninlil_environment_t environment;
    int written;
    int ok = 0;

    CONSUMER_REQUIRE(profile_index < CONSUMER_PROFILE_COUNT);
    role = CONSUMER_ROLES[
        profile_index / CONSUMER_ENVIRONMENT_COUNT];
    environment = CONSUMER_ENVIRONMENTS[
        profile_index % CONSUMER_ENVIRONMENT_COUNT];
    written = snprintf(
        storage_namespace,
        sizeof(storage_namespace),
        "installed-profile-%02u",
        (unsigned)profile_index);
    CONSUMER_REQUIRE(
        written > 0
        && (size_t)written < sizeof(storage_namespace));

    fixture_init(&fixture, storage);
    config = runtime_config_for(
        role,
        environment,
        (const uint8_t *)storage_namespace,
        (uint32_t)written,
        (uint8_t)(0x20u + profile_index));
    CONSUMER_REQUIRE(
        ninlil_runtime_create(&config, &fixture.platform, &runtime)
        == NINLIL_OK);
    CONSUMER_REQUIRE(runtime != NULL);

    if (role == NINLIL_ROLE_CELL_AGENT) {
        ninlil_service_descriptor_t descriptor =
            make_service_descriptor(CONSUMER_SERVICE_DISPLAY_COMMAND);
        ninlil_service_callbacks_t callbacks;
        ninlil_service_t *service =
            (ninlil_service_t *)(uintptr_t)1u;

        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version,
            &callbacks.struct_size,
            sizeof(callbacks));
        CONSUMER_REQUIRE(
            ninlil_service_register(
                runtime, &descriptor, &callbacks, &service)
            == NINLIL_E_UNSUPPORTED);
        CONSUMER_REQUIRE(service == NULL);
    }
    ok = 1;

    if (ninlil_runtime_destroy(runtime) != NINLIL_OK) {
        ok = 0;
    }
    return ok;
}

static int exercise_unknown_profile_rejection(
    const ninlil_storage_ops_t *storage)
{
    static const uint8_t UNKNOWN_ROLE_NAMESPACE[] =
        "installed-profile-unknown-role";
    static const uint8_t UNKNOWN_ENV_NAMESPACE[] =
        "installed-profile-unknown-environment";
    consumer_fixture_t fixture;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = (ninlil_runtime_t *)(uintptr_t)1u;

    fixture_init(&fixture, storage);
    config = runtime_config_for(
        (ninlil_role_t)0x7fffffffu,
        NINLIL_ENV_TEST,
        UNKNOWN_ROLE_NAMESPACE,
        (uint32_t)(sizeof(UNKNOWN_ROLE_NAMESPACE) - 1u),
        0x3du);
    CONSUMER_REQUIRE(
        ninlil_runtime_create(&config, &fixture.platform, &runtime)
        == NINLIL_E_INVALID_ARGUMENT);
    CONSUMER_REQUIRE(runtime == NULL);

    runtime = (ninlil_runtime_t *)(uintptr_t)1u;
    config = runtime_config_for(
        NINLIL_ROLE_CONTROLLER,
        (ninlil_environment_t)0x7fffffffu,
        UNKNOWN_ENV_NAMESPACE,
        (uint32_t)(sizeof(UNKNOWN_ENV_NAMESPACE) - 1u),
        0x3eu);
    CONSUMER_REQUIRE(
        ninlil_runtime_create(&config, &fixture.platform, &runtime)
        == NINLIL_E_INVALID_ARGUMENT);
    CONSUMER_REQUIRE(runtime == NULL);
    return 1;
}

static void make_exact_target(
    ninlil_concrete_target_t *target,
    uint8_t tag)
{
    (void)memset(target, 0, sizeof(*target));
    set_header(
        &target->abi_version,
        &target->struct_size,
        sizeof(*target));
    set_id(&target->target_runtime_id, tag);
    set_id(
        &target->target_application_instance_id,
        (uint8_t)(tag + 0x10u));
    set_id(&target->device_id, (uint8_t)(tag + 0x20u));
    set_id(&target->installation_id, (uint8_t)(tag + 0x30u));
    set_id(&target->site_domain_id, (uint8_t)(tag + 0x40u));
    target->binding_epoch = (uint64_t)tag + 1u;
    target->membership_epoch = (uint64_t)tag + 2u;
    target->flags = NINLIL_TARGET_HAS_DEVICE
        | NINLIL_TARGET_HAS_INSTALLATION
        | NINLIL_TARGET_HAS_SITE;
}

static int exact_target_equal(
    const ninlil_concrete_target_t *left,
    const ninlil_concrete_target_t *right)
{
    return memcmp(left, right, sizeof(*left)) == 0;
}

static int register_exact_target_service(
    ninlil_runtime_t *runtime,
    ninlil_service_descriptor_t *out_descriptor,
    ninlil_service_t **out_service)
{
    ninlil_service_callbacks_t callbacks;

    *out_descriptor =
        make_service_descriptor(CONSUMER_SERVICE_DISPLAY_COMMAND);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version,
        &callbacks.struct_size,
        sizeof(callbacks));
    *out_service = NULL;
    CONSUMER_REQUIRE(
        ninlil_service_register(
            runtime, out_descriptor, &callbacks, out_service)
        == NINLIL_OK);
    CONSUMER_REQUIRE(*out_service != NULL);
    return 1;
}

static int verify_exact_target_service_was_restored(
    ninlil_runtime_t *runtime)
{
    ninlil_service_descriptor_t conflicting =
        make_service_descriptor(CONSUMER_SERVICE_DISPLAY_COMMAND);
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *service =
        (ninlil_service_t *)(uintptr_t)1u;

    conflicting.descriptor_digest.bytes[NINLIL_SHA256_BYTES - 1u]
        ^= 0x0fu;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version,
        &callbacks.struct_size,
        sizeof(callbacks));
    CONSUMER_REQUIRE(
        ninlil_service_register(
            runtime, &conflicting, &callbacks, &service)
        == NINLIL_E_CONFLICT);
    CONSUMER_REQUIRE(service == NULL);
    return 1;
}

static int submit_desired_state(
    ninlil_service_t *service,
    const ninlil_concrete_target_t *targets,
    uint32_t target_count,
    const uint8_t *idempotency_key,
    uint32_t idempotency_key_length,
    const uint8_t *payload,
    uint32_t payload_length,
    const uint8_t digest_bytes[NINLIL_SHA256_BYTES],
    uint64_t generation,
    ninlil_submission_result_t *out_result)
{
    ninlil_submission_t submission;
    ninlil_status_t status;

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
    submission.idempotency_key.length = idempotency_key_length;
    set_digest_bytes(&submission.content_digest, digest_bytes);
    submission.generation = generation;
    submission.payload.data = payload;
    submission.payload.length = payload_length;

    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    status = ninlil_submit(service, &submission, out_result);
    if (status != NINLIL_OK) {
        (void)fprintf(
            stderr,
            "DesiredState submit API failure: status=%d targets=%u "
            "kind=%u reason=%u\n",
            (int)status,
            (unsigned)target_count,
            (unsigned)out_result->kind,
            (unsigned)out_result->reason);
        return 0;
    }
    return 1;
}

static void initialize_target_snapshots(
    ninlil_target_snapshot_t *targets,
    uint32_t count)
{
    uint32_t index;

    (void)memset(
        targets,
        0,
        sizeof(*targets) * (size_t)count);
    for (index = 0u; index < count; ++index) {
        set_header(
            &targets[index].abi_version,
            &targets[index].struct_size,
            sizeof(targets[index]));
    }
}

static void initialize_transaction_snapshot(
    ninlil_transaction_snapshot_t *snapshot,
    ninlil_target_snapshot_t *targets,
    uint32_t target_capacity)
{
    (void)memset(snapshot, 0, sizeof(*snapshot));
    set_header(
        &snapshot->abi_version,
        &snapshot->struct_size,
        sizeof(*snapshot));
    snapshot->targets = targets;
    snapshot->target_capacity = target_capacity;
}

static int query_exact_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *transaction_id,
    const ninlil_concrete_target_t *expected_targets,
    uint32_t expected_target_count,
    ninlil_transaction_snapshot_t *out_snapshot,
    ninlil_target_snapshot_t
        out_targets[CONSUMER_EXACT_MAX_TARGETS])
{
    uint32_t index;

    initialize_target_snapshots(
        out_targets, CONSUMER_EXACT_MAX_TARGETS);
    initialize_transaction_snapshot(
        out_snapshot,
        out_targets,
        CONSUMER_EXACT_MAX_TARGETS);
    CONSUMER_REQUIRE(
        ninlil_transaction_query(
            runtime, transaction_id, out_snapshot)
        == NINLIL_OK);
    CONSUMER_REQUIRE(
        id_equal(&out_snapshot->transaction_id, transaction_id));
    CONSUMER_REQUIRE(
        out_snapshot->family == NINLIL_FAMILY_DESIRED_STATE);
    CONSUMER_REQUIRE(
        out_snapshot->target_count == expected_target_count);
    CONSUMER_REQUIRE(
        text_id_equals(
            &out_snapshot->service.service_id,
            CONSUMER_SERVICE_IDS[
                CONSUMER_SERVICE_DISPLAY_COMMAND]));
    CONSUMER_REQUIRE(
        out_snapshot->service.descriptor_revision
        == descriptor->descriptor_revision);
    CONSUMER_REQUIRE(
        digest_equal(
            &out_snapshot->service.descriptor_digest,
            &descriptor->descriptor_digest));
    for (index = 0u; index < expected_target_count; ++index) {
        CONSUMER_REQUIRE(
            exact_target_equal(
                &out_targets[index].target,
                &expected_targets[index]));
    }
    return 1;
}

static int verify_query_buffer_too_small(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    uint32_t required_target_count)
{
    ninlil_target_snapshot_t sentinel;
    ninlil_target_snapshot_t sentinel_before;
    ninlil_transaction_snapshot_t snapshot;

    (void)memset(&sentinel, 0xa5, sizeof(sentinel));
    set_header(
        &sentinel.abi_version,
        &sentinel.struct_size,
        sizeof(sentinel));
    sentinel_before = sentinel;
    initialize_transaction_snapshot(&snapshot, &sentinel, 1u);
    CONSUMER_REQUIRE(
        ninlil_transaction_query(
            runtime, transaction_id, &snapshot)
        == NINLIL_E_BUFFER_TOO_SMALL);
    CONSUMER_REQUIRE(
        snapshot.target_count == required_target_count);
    CONSUMER_REQUIRE(
        memcmp(&sentinel, &sentinel_before, sizeof(sentinel)) == 0);
    return 1;
}

static int verify_query_future_target_stride(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_concrete_target_t
        expected_targets[CONSUMER_EXACT_MAX_TARGETS])
{
    consumer_future_target_snapshot_t
        targets[CONSUMER_EXACT_MAX_TARGETS];
    consumer_future_target_snapshot_t
        before[CONSUMER_EXACT_MAX_TARGETS];
    ninlil_transaction_snapshot_t snapshot;
    uint32_t index;

    (void)memset(targets, 0x6d, sizeof(targets));
    for (index = 0u; index < CONSUMER_EXACT_MAX_TARGETS; ++index) {
        set_header(
            &targets[index].known.abi_version,
            &targets[index].known.struct_size,
            sizeof(targets[index]));
    }
    (void)memcpy(before, targets, sizeof(before));
    initialize_transaction_snapshot(
        &snapshot,
        &targets[0].known,
        CONSUMER_EXACT_MAX_TARGETS);
    CONSUMER_REQUIRE(
        ninlil_transaction_query(
            runtime, transaction_id, &snapshot)
        == NINLIL_OK);
    CONSUMER_REQUIRE(
        snapshot.target_count == CONSUMER_EXACT_MAX_TARGETS);
    for (index = 0u; index < CONSUMER_EXACT_MAX_TARGETS; ++index) {
        CONSUMER_REQUIRE(
            exact_target_equal(
                &targets[index].known.target,
                &expected_targets[index]));
        CONSUMER_REQUIRE(
            memcmp(
                targets[index].future_tail,
                before[index].future_tail,
                sizeof(targets[index].future_tail))
            == 0);
    }
    return 1;
}

static int list_exact_transactions(
    ninlil_runtime_t *runtime,
    const consumer_exact_restart_evidence_t *evidence)
{
    ninlil_query_t query;
    ninlil_transaction_summary_t items[4];
    ninlil_transaction_page_t page;
    uint32_t found[CONSUMER_EXACT_TRANSACTION_COUNT] = {0u, 0u};
    uint32_t index;

    (void)memset(&query, 0, sizeof(query));
    set_header(&query.abi_version, &query.struct_size, sizeof(query));
    query.family_mask = NINLIL_FAMILY_MASK_DESIRED_STATE;
    query.include_terminal = 1u;
    query.include_nonterminal = 1u;
    (void)memset(items, 0, sizeof(items));
    for (index = 0u; index < 4u; ++index) {
        set_header(
            &items[index].abi_version,
            &items[index].struct_size,
            sizeof(items[index]));
    }
    (void)memset(&page, 0, sizeof(page));
    set_header(&page.abi_version, &page.struct_size, sizeof(page));
    page.items = items;
    page.item_capacity = 4u;
    CONSUMER_REQUIRE(
        ninlil_transaction_list(runtime, &query, &page) == NINLIL_OK);
    CONSUMER_REQUIRE(
        page.item_count == CONSUMER_EXACT_TRANSACTION_COUNT);
    CONSUMER_REQUIRE(page.has_more == 0u);
    for (index = 0u; index < page.item_count; ++index) {
        uint32_t expected;

        CONSUMER_REQUIRE(
            items[index].family == NINLIL_FAMILY_DESIRED_STATE);
        for (expected = 0u;
             expected < CONSUMER_EXACT_TRANSACTION_COUNT;
             ++expected) {
            if (id_equal(
                    &items[index].transaction_id,
                    &evidence->transactions[expected].transaction_id)) {
                found[expected] += 1u;
                CONSUMER_REQUIRE(
                    items[index].transaction_sequence
                    == evidence->transactions[expected]
                           .transaction_sequence);
                CONSUMER_REQUIRE(
                    items[index].record_revision
                    == evidence->transactions[expected].record_revision);
            }
        }
    }
    for (index = 0u;
         index < CONSUMER_EXACT_TRANSACTION_COUNT;
         ++index) {
        CONSUMER_REQUIRE(found[index] == 1u);
    }
    return 1;
}

static int capture_exact_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *transaction_id,
    const ninlil_digest256_t *content_digest,
    const ninlil_concrete_target_t *expected_targets,
    uint32_t expected_target_count,
    consumer_exact_transaction_evidence_t *out_evidence)
{
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t
        target_snapshots[CONSUMER_EXACT_MAX_TARGETS];
    uint32_t index;

    CONSUMER_REQUIRE(
        query_exact_transaction(
            runtime,
            descriptor,
            transaction_id,
            expected_targets,
            expected_target_count,
            &snapshot,
            target_snapshots));
    CONSUMER_REQUIRE(
        digest_equal(&snapshot.content_digest, content_digest));
    (void)memset(out_evidence, 0, sizeof(*out_evidence));
    out_evidence->transaction_id = *transaction_id;
    out_evidence->content_digest = *content_digest;
    out_evidence->transaction_sequence =
        snapshot.transaction_sequence;
    out_evidence->record_revision = snapshot.record_revision;
    out_evidence->target_count = snapshot.target_count;
    for (index = 0u; index < snapshot.target_count; ++index) {
        out_evidence->targets[index] =
            target_snapshots[index].target;
        out_evidence->attempt_in_cycle[index] =
            target_snapshots[index].attempt_in_cycle;
        out_evidence->retry_cycle_id[index] =
            target_snapshots[index].retry_cycle_id;
        out_evidence->cumulative_attempts[index] =
            target_snapshots[index].cumulative_attempts;
        out_evidence->has_late_evidence[index] =
            target_snapshots[index].has_late_evidence;
        out_evidence->evidence_counter_saturated[index] =
            target_snapshots[index].evidence_counter_saturated;
        out_evidence->valid_evidence_count[index] =
            target_snapshots[index].valid_evidence_count;
        out_evidence->duplicate_evidence_count[index] =
            target_snapshots[index].duplicate_evidence_count;
        out_evidence->raw_evidence_overflow_count[index] =
            target_snapshots[index].raw_evidence_overflow_count;
        out_evidence->late_evidence_count[index] =
            target_snapshots[index].late_evidence_count;
    }
    return 1;
}

static int verify_exact_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const consumer_exact_transaction_evidence_t *evidence)
{
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t
        target_snapshots[CONSUMER_EXACT_MAX_TARGETS];
    uint32_t index;

    CONSUMER_REQUIRE(
        query_exact_transaction(
            runtime,
            descriptor,
            &evidence->transaction_id,
            evidence->targets,
            evidence->target_count,
            &snapshot,
            target_snapshots));
    CONSUMER_REQUIRE(
        digest_equal(
            &snapshot.content_digest,
            &evidence->content_digest));
    CONSUMER_REQUIRE(
        snapshot.transaction_sequence
        == evidence->transaction_sequence);
    CONSUMER_REQUIRE(
        snapshot.record_revision == evidence->record_revision);
    for (index = 0u; index < evidence->target_count; ++index) {
        CONSUMER_REQUIRE(
            target_snapshots[index].attempt_in_cycle
            == evidence->attempt_in_cycle[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].retry_cycle_id
            == evidence->retry_cycle_id[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].cumulative_attempts
            == evidence->cumulative_attempts[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].has_late_evidence
            == evidence->has_late_evidence[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].evidence_counter_saturated
            == evidence->evidence_counter_saturated[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].valid_evidence_count
            == evidence->valid_evidence_count[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].duplicate_evidence_count
            == evidence->duplicate_evidence_count[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].raw_evidence_overflow_count
            == evidence->raw_evidence_overflow_count[index]);
        CONSUMER_REQUIRE(
            target_snapshots[index].late_evidence_count
            == evidence->late_evidence_count[index]);
    }
    return 1;
}

static int step_exact_target_once(
    ninlil_runtime_t *runtime)
{
    ninlil_step_budget_t budget;
    ninlil_step_result_t result;

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 1u;
    budget.max_callbacks = 1u;
    budget.max_state_transitions = 1u;
    budget.max_bearer_sends = 1u;
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    CONSUMER_REQUIRE(
        ninlil_runtime_step(runtime, &budget, &result) == NINLIL_OK);
    CONSUMER_REQUIRE(result.state_transitions <= 1u);
    CONSUMER_REQUIRE(result.bearer_sends <= 1u);
    CONSUMER_REQUIRE(result.health != NINLIL_HEALTH_FATAL);
    return 1;
}

static int establish_one_isolated_retry_attempt(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *transaction_id,
    const ninlil_concrete_target_t
        expected_targets[CONSUMER_EXACT_MAX_TARGETS],
    consumer_fixture_t *fixture)
{
    uint32_t turn;

    for (turn = 0u; turn < 16u; ++turn) {
        ninlil_transaction_snapshot_t snapshot;
        ninlil_target_snapshot_t
            targets[CONSUMER_EXACT_MAX_TARGETS];
        uint32_t attempted_targets = 0u;
        uint64_t cumulative_attempts = 0u;
        uint32_t index;

        CONSUMER_REQUIRE(
            query_exact_transaction(
                runtime,
                descriptor,
                transaction_id,
                expected_targets,
                CONSUMER_EXACT_MAX_TARGETS,
                &snapshot,
                targets));
        for (index = 0u;
             index < CONSUMER_EXACT_MAX_TARGETS;
             ++index) {
            if (targets[index].cumulative_attempts != 0u) {
                attempted_targets += 1u;
                cumulative_attempts +=
                    targets[index].cumulative_attempts;
            }
        }
        if (attempted_targets == 1u
            && cumulative_attempts == 1u
            && fixture->tx_gate_calls != 0u) {
            return 1;
        }
        if (attempted_targets > 1u || cumulative_attempts > 1u) {
            (void)fprintf(
                stderr,
                "retry isolation mismatch: attempted_targets=%u "
                "cumulative=%llu per_target=[%llu,%llu,%llu,%llu]\n",
                (unsigned)attempted_targets,
                (unsigned long long)cumulative_attempts,
                (unsigned long long)targets[0].cumulative_attempts,
                (unsigned long long)targets[1].cumulative_attempts,
                (unsigned long long)targets[2].cumulative_attempts,
                (unsigned long long)targets[3].cumulative_attempts);
        }
        CONSUMER_REQUIRE(attempted_targets <= 1u);
        CONSUMER_REQUIRE(cumulative_attempts <= 1u);
        CONSUMER_REQUIRE(step_exact_target_once(runtime));
    }
    (void)fprintf(
        stderr,
        "exact-target retry did not reach one isolated attempt\n");
    return 0;
}

static void make_four_target_rosters(
    ninlil_concrete_target_t
        input[CONSUMER_EXACT_MAX_TARGETS],
    ninlil_concrete_target_t
        canonical[CONSUMER_EXACT_MAX_TARGETS])
{
    make_exact_target(&input[0], 0x44u);
    make_exact_target(&input[1], 0x11u);
    make_exact_target(&input[2], 0x33u);
    make_exact_target(&input[3], 0x22u);
    make_exact_target(&canonical[0], 0x11u);
    make_exact_target(&canonical[1], 0x22u);
    make_exact_target(&canonical[2], 0x33u);
    make_exact_target(&canonical[3], 0x44u);
}

static void make_two_target_rosters(
    ninlil_concrete_target_t input[2],
    ninlil_concrete_target_t canonical[2])
{
    make_exact_target(&input[0], 0x66u);
    make_exact_target(&input[1], 0x55u);
    make_exact_target(&canonical[0], 0x55u);
    make_exact_target(&canonical[1], 0x66u);
}

static int exercise_exact_targets_before_restart(
    const ninlil_storage_ops_t *storage,
    consumer_exact_restart_evidence_t *evidence)
{
    static const uint8_t EXACT_NAMESPACE[] =
        "installed-exact-target-consumer";
    consumer_fixture_t fixture;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_t *service = NULL;
    ninlil_concrete_target_t
        four_input[CONSUMER_EXACT_MAX_TARGETS];
    ninlil_concrete_target_t
        four_canonical[CONSUMER_EXACT_MAX_TARGETS];
    ninlil_concrete_target_t two_input[2];
    ninlil_concrete_target_t two_canonical[2];
    uint8_t four_key[sizeof(EXACT_FOUR_KEY)];
    uint8_t four_payload[sizeof(EXACT_FOUR_PAYLOAD)];
    uint8_t two_key[sizeof(EXACT_TWO_KEY)];
    uint8_t two_payload[sizeof(EXACT_TWO_PAYLOAD)];
    ninlil_submission_result_t four;
    ninlil_submission_result_t replay;
    ninlil_submission_result_t conflict;
    ninlil_submission_result_t two;
    ninlil_digest256_t four_digest;
    ninlil_digest256_t two_digest;
    ninlil_transaction_snapshot_t before_replay;
    ninlil_transaction_snapshot_t after_replay;
    ninlil_target_snapshot_t
        before_targets[CONSUMER_EXACT_MAX_TARGETS];
    ninlil_target_snapshot_t
        after_targets[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t used;
    int ok = 0;
    unsigned stage = 0u;

    (void)memset(evidence, 0, sizeof(*evidence));
    fixture_init(&fixture, storage);
    fixture.tx_gate_status = NINLIL_TX_GATE_TEMPORARY;
    config = runtime_config_for(
        NINLIL_ROLE_CONTROLLER,
        NINLIL_ENV_FIELD,
        EXACT_NAMESPACE,
        (uint32_t)(sizeof(EXACT_NAMESPACE) - 1u),
        0x45u);
    if (ninlil_runtime_create(
            &config, &fixture.platform, &runtime)
            != NINLIL_OK
        || runtime == NULL
        || !register_exact_target_service(
            runtime, &descriptor, &service)) {
        (void)fprintf(
            stderr,
            "exact-target initial Runtime/service create failed\n");
        goto cleanup;
    }
    stage = 1u;

    make_four_target_rosters(four_input, four_canonical);
    (void)memcpy(four_key, EXACT_FOUR_KEY, sizeof(four_key));
    (void)memcpy(
        four_payload, EXACT_FOUR_PAYLOAD, sizeof(four_payload));
    if (!submit_desired_state(
            service,
            four_input,
            CONSUMER_EXACT_MAX_TARGETS,
            four_key,
            (uint32_t)(sizeof(four_key) - 1u),
            four_payload,
            (uint32_t)sizeof(four_payload),
            EXACT_FOUR_DIGEST,
            4u,
            &four)
        || four.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
        goto cleanup;
    }
    set_digest_bytes(&four_digest, EXACT_FOUR_DIGEST);
    stage = 2u;

    /*
     * Destroy caller-owned admission buffers immediately. Query and replay
     * below must use the Runtime's durable deep copies, not these pointers.
     */
    (void)memset(four_input, 0xa5, sizeof(four_input));
    (void)memset(four_key, 0xa5, sizeof(four_key));
    (void)memset(four_payload, 0xa5, sizeof(four_payload));
    if (!verify_query_buffer_too_small(
            runtime,
            &four.transaction_id,
            CONSUMER_EXACT_MAX_TARGETS)
        || !verify_query_future_target_stride(
            runtime,
            &four.transaction_id,
            four_canonical)
        || !query_exact_transaction(
            runtime,
            &descriptor,
            &four.transaction_id,
            four_canonical,
            CONSUMER_EXACT_MAX_TARGETS,
            &before_replay,
            before_targets)) {
        goto cleanup;
    }
    stage = 3u;

    make_four_target_rosters(four_input, four_canonical);
    if (!submit_desired_state(
            service,
            four_input,
            CONSUMER_EXACT_MAX_TARGETS,
            EXACT_FOUR_KEY,
            (uint32_t)(sizeof(EXACT_FOUR_KEY) - 1u),
            EXACT_FOUR_PAYLOAD,
            (uint32_t)sizeof(EXACT_FOUR_PAYLOAD),
            EXACT_FOUR_DIGEST,
            4u,
            &replay)
        || replay.kind != NINLIL_SUBMISSION_ALREADY_ADMITTED
        || !id_equal(
            &replay.transaction_id, &four.transaction_id)
        || !submit_desired_state(
            service,
            four_input,
            CONSUMER_EXACT_MAX_TARGETS,
            EXACT_FOUR_KEY,
            (uint32_t)(sizeof(EXACT_FOUR_KEY) - 1u),
            EXACT_FOUR_CONFLICT_PAYLOAD,
            (uint32_t)sizeof(EXACT_FOUR_CONFLICT_PAYLOAD),
            EXACT_FOUR_CONFLICT_DIGEST,
            4u,
            &conflict)
        || conflict.kind
            != NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT
        || !id_equal(
            &conflict.transaction_id, &four.transaction_id)
        || !query_exact_transaction(
            runtime,
            &descriptor,
            &four.transaction_id,
            four_canonical,
            CONSUMER_EXACT_MAX_TARGETS,
            &after_replay,
            after_targets)
        || before_replay.record_revision
            != after_replay.record_revision) {
        goto cleanup;
    }
    stage = 4u;

    if (!establish_one_isolated_retry_attempt(
            runtime,
            &descriptor,
            &four.transaction_id,
            four_canonical,
            &fixture)) {
        goto cleanup;
    }
    stage = 5u;

    make_two_target_rosters(two_input, two_canonical);
    (void)memcpy(two_key, EXACT_TWO_KEY, sizeof(two_key));
    (void)memcpy(
        two_payload, EXACT_TWO_PAYLOAD, sizeof(two_payload));
    if (!submit_desired_state(
            service,
            two_input,
            2u,
            two_key,
            (uint32_t)(sizeof(two_key) - 1u),
            two_payload,
            (uint32_t)sizeof(two_payload),
            EXACT_TWO_DIGEST,
            2u,
            &two)
        || two.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
        goto cleanup;
    }
    set_digest_bytes(&two_digest, EXACT_TWO_DIGEST);
    (void)memset(two_input, 0x5a, sizeof(two_input));
    (void)memset(two_key, 0x5a, sizeof(two_key));
    (void)memset(two_payload, 0x5a, sizeof(two_payload));
    stage = 6u;

    if (!capture_exact_transaction(
            runtime,
            &descriptor,
            &four.transaction_id,
            &four_digest,
            four_canonical,
            CONSUMER_EXACT_MAX_TARGETS,
            &evidence->transactions[0])
        || !capture_exact_transaction(
            runtime,
            &descriptor,
            &two.transaction_id,
            &two_digest,
            two_canonical,
            2u,
            &evidence->transactions[1])
        || !get_capacity_used(
            runtime, NINLIL_RESOURCE_SERVICE, &used)
        || used != 1u) {
        goto cleanup;
    }
    evidence->service_capacity_used = used;
    if (!get_capacity_used(
            runtime, NINLIL_RESOURCE_TRANSACTION, &used)
        || used != CONSUMER_EXACT_TRANSACTION_COUNT) {
        goto cleanup;
    }
    evidence->transaction_capacity_used = used;
    if (!list_exact_transactions(runtime, evidence)) {
        goto cleanup;
    }
    stage = 7u;
    ok = 1;

cleanup:
    if (!ok) {
        (void)fprintf(
            stderr,
            "exact-target initial acceptance failed at stage=%u\n",
            stage);
    }
    if (runtime != NULL
        && ninlil_runtime_destroy(runtime) != NINLIL_OK) {
        ok = 0;
    }
    return ok;
}

static int exercise_exact_targets_after_restart(
    const ninlil_storage_ops_t *storage,
    const consumer_exact_restart_evidence_t *evidence)
{
    static const uint8_t EXACT_NAMESPACE[] =
        "installed-exact-target-consumer";
    consumer_fixture_t fixture;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_t *service = NULL;
    ninlil_concrete_target_t
        four_input[CONSUMER_EXACT_MAX_TARGETS];
    ninlil_concrete_target_t
        four_canonical[CONSUMER_EXACT_MAX_TARGETS];
    ninlil_submission_result_t replay;
    ninlil_transaction_snapshot_t before_replay;
    ninlil_transaction_snapshot_t after_replay;
    ninlil_target_snapshot_t
        before_targets[CONSUMER_EXACT_MAX_TARGETS];
    ninlil_target_snapshot_t
        after_targets[CONSUMER_EXACT_MAX_TARGETS];
    uint64_t used;
    int ok = 0;
    unsigned stage = 0u;

    fixture_init(&fixture, storage);
    fixture.tx_gate_status = NINLIL_TX_GATE_TEMPORARY;
    config = runtime_config_for(
        NINLIL_ROLE_CONTROLLER,
        NINLIL_ENV_FIELD,
        EXACT_NAMESPACE,
        (uint32_t)(sizeof(EXACT_NAMESPACE) - 1u),
        0x45u);
    if (ninlil_runtime_create(
            &config, &fixture.platform, &runtime)
            != NINLIL_OK
        || runtime == NULL
        || !verify_exact_target_service_was_restored(runtime)
        || !register_exact_target_service(
            runtime, &descriptor, &service)) {
        (void)fprintf(
            stderr,
            "exact-target restart Runtime/service recovery failed\n");
        goto cleanup;
    }
    stage = 1u;

    if (!verify_query_buffer_too_small(
            runtime,
            &evidence->transactions[0].transaction_id,
            CONSUMER_EXACT_MAX_TARGETS)
        || !verify_exact_transaction(
            runtime, &descriptor, &evidence->transactions[0])
        || !verify_exact_transaction(
            runtime, &descriptor, &evidence->transactions[1])
        || !list_exact_transactions(runtime, evidence)
        || !get_capacity_used(
            runtime, NINLIL_RESOURCE_SERVICE, &used)
        || used != evidence->service_capacity_used
        || !get_capacity_used(
            runtime, NINLIL_RESOURCE_TRANSACTION, &used)
        || used != evidence->transaction_capacity_used) {
        goto cleanup;
    }
    stage = 2u;

    make_four_target_rosters(four_input, four_canonical);
    if (!query_exact_transaction(
            runtime,
            &descriptor,
            &evidence->transactions[0].transaction_id,
            four_canonical,
            CONSUMER_EXACT_MAX_TARGETS,
            &before_replay,
            before_targets)
        || !submit_desired_state(
            service,
            four_input,
            CONSUMER_EXACT_MAX_TARGETS,
            EXACT_FOUR_KEY,
            (uint32_t)(sizeof(EXACT_FOUR_KEY) - 1u),
            EXACT_FOUR_PAYLOAD,
            (uint32_t)sizeof(EXACT_FOUR_PAYLOAD),
            EXACT_FOUR_DIGEST,
            4u,
            &replay)
        || replay.kind != NINLIL_SUBMISSION_ALREADY_ADMITTED
        || !id_equal(
            &replay.transaction_id,
            &evidence->transactions[0].transaction_id)
        || !query_exact_transaction(
            runtime,
            &descriptor,
            &evidence->transactions[0].transaction_id,
            four_canonical,
            CONSUMER_EXACT_MAX_TARGETS,
            &after_replay,
            after_targets)
        || before_replay.record_revision
            != after_replay.record_revision) {
        goto cleanup;
    }
    stage = 3u;
    ok = 1;

cleanup:
    if (!ok) {
        (void)fprintf(
            stderr,
            "exact-target restart acceptance failed at stage=%u\n",
            stage);
    }
    if (runtime != NULL
        && ninlil_runtime_destroy(runtime) != NINLIL_OK) {
        ok = 0;
    }
    return ok;
}

static int register_four_services(
    ninlil_runtime_t *runtime,
    consumer_services_t *services)
{
    uint32_t index;

    (void)memset(services, 0, sizeof(*services));
    for (index = 0u; index < CONSUMER_SERVICE_COUNT; ++index) {
        int is_receiver =
            index == CONSUMER_SERVICE_DISPLAY_COMMAND
            || index == CONSUMER_SERVICE_TEMPERATURE_QUERY;
        ninlil_status_t status;

        services->descriptors[index] = make_service_descriptor(index);
        set_header(
            &services->callbacks[index].abi_version,
            &services->callbacks[index].struct_size,
            sizeof(services->callbacks[index]));
        if (is_receiver) {
            services->callbacks[index].on_delivery = desired_on_delivery;
            services->callbacks[index].on_reconcile =
                desired_on_reconcile;
        }
        status = ninlil_service_register(
            runtime,
            &services->descriptors[index],
            &services->callbacks[index],
            &services->handles[index]);
        if (status != NINLIL_OK) {
            (void)fprintf(
                stderr,
                "service register failed: index=%u id=%s status=%d\n",
                (unsigned)index,
                CONSUMER_SERVICE_IDS[index],
                (int)status);
            return 0;
        }
        CONSUMER_REQUIRE(services->handles[index] != NULL);
    }
    for (index = 0u; index < CONSUMER_SERVICE_COUNT; ++index) {
        uint32_t other;
        for (other = index + 1u;
             other < CONSUMER_SERVICE_COUNT;
             ++other) {
            CONSUMER_REQUIRE(
                services->handles[index] != services->handles[other]);
        }
    }
    return 1;
}

static int verify_four_services_were_restored(
    ninlil_runtime_t *runtime)
{
    uint32_t index;

    for (index = 0u; index < CONSUMER_SERVICE_COUNT; ++index) {
        ninlil_service_descriptor_t conflicting =
            make_service_descriptor(index);
        ninlil_service_callbacks_t callbacks;
        ninlil_service_t *service = (ninlil_service_t *)(uintptr_t)1u;
        ninlil_status_t status;
        int is_receiver =
            index == CONSUMER_SERVICE_DISPLAY_COMMAND
            || index == CONSUMER_SERVICE_TEMPERATURE_QUERY;

        /*
         * The key (namespace/service/revision) is unchanged, but the
         * descriptor contract differs. A fresh empty registry would accept
         * this valid descriptor; a restored registry must reject it without
         * publishing a handle.
         */
        conflicting.descriptor_digest.bytes[NINLIL_SHA256_BYTES - 1u]
            ^= 0x0fu;
        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version,
            &callbacks.struct_size,
            sizeof(callbacks));
        if (is_receiver) {
            callbacks.on_delivery = desired_on_delivery;
            callbacks.on_reconcile = desired_on_reconcile;
        }
        status = ninlil_service_register(
            runtime, &conflicting, &callbacks, &service);
        CONSUMER_REQUIRE(status == NINLIL_E_CONFLICT);
        CONSUMER_REQUIRE(service == NULL);
    }
    return 1;
}

static void make_controller_target(ninlil_concrete_target_t *target)
{
    (void)memset(target, 0, sizeof(*target));
    set_header(
        &target->abi_version,
        &target->struct_size,
        sizeof(*target));
    set_id(&target->target_runtime_id, 0x80u);
    set_id(&target->target_application_instance_id, 0x90u);
    set_id(&target->device_id, 0xa0u);
    set_id(&target->installation_id, 0xb0u);
    set_id(&target->site_domain_id, 0xc0u);
    target->binding_epoch = 1u;
    target->membership_epoch = 1u;
    target->flags = NINLIL_TARGET_HAS_DEVICE
        | NINLIL_TARGET_HAS_INSTALLATION
        | NINLIL_TARGET_HAS_SITE;
}

static int submit_event(
    ninlil_service_t *service,
    const uint8_t *idempotency_key,
    uint32_t idempotency_key_length,
    uint8_t event_tag,
    const uint8_t *payload,
    uint32_t payload_length,
    const uint8_t digest_bytes[NINLIL_SHA256_BYTES],
    ninlil_submission_result_t *out_result)
{
    ninlil_concrete_target_t target;
    ninlil_submission_t submission;

    make_controller_target(&target);
    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = NINLIL_NO_DEADLINE;
    submission.evidence_grace_ms = 0u;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length = idempotency_key_length;
    set_digest_bytes(&submission.content_digest, digest_bytes);
    set_id(&submission.event_id, event_tag);
    submission.generation = 0u;
    submission.payload.data = payload;
    submission.payload.length = payload_length;

    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    CONSUMER_REQUIRE(
        ninlil_submit(service, &submission, out_result) == NINLIL_OK);
    return 1;
}

static int text_id_equals(
    const ninlil_text_id_t *actual,
    const char *expected)
{
    size_t length = strlen(expected);

    return length <= UINT8_MAX
        && actual->length == (uint8_t)length
        && memcmp(actual->bytes, expected, length) == 0;
}

static int query_transaction(
    ninlil_runtime_t *runtime,
    const consumer_services_t *services,
    uint32_t service_index,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *out_snapshot)
{
    ninlil_target_snapshot_t target;

    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
    set_header(
        &out_snapshot->abi_version,
        &out_snapshot->struct_size,
        sizeof(*out_snapshot));
    out_snapshot->targets = &target;
    out_snapshot->target_capacity = 1u;
    CONSUMER_REQUIRE(
        ninlil_transaction_query(
            runtime, transaction_id, out_snapshot)
        == NINLIL_OK);
    CONSUMER_REQUIRE(
        id_equal(&out_snapshot->transaction_id, transaction_id));
    CONSUMER_REQUIRE(out_snapshot->target_count == 1u);
    CONSUMER_REQUIRE(
        out_snapshot->family == NINLIL_FAMILY_EVENT_FACT);
    CONSUMER_REQUIRE(
        text_id_equals(
            &out_snapshot->service.service_id,
            CONSUMER_SERVICE_IDS[service_index]));
    CONSUMER_REQUIRE(
        out_snapshot->service.descriptor_revision
        == services->descriptors[service_index].descriptor_revision);
    CONSUMER_REQUIRE(
        digest_equal(
            &out_snapshot->service.descriptor_digest,
            &services->descriptors[service_index].descriptor_digest));
    return 1;
}

static int list_three_transactions(
    ninlil_runtime_t *runtime,
    const consumer_restart_evidence_t *evidence)
{
    ninlil_query_t query;
    ninlil_transaction_summary_t items[8];
    ninlil_transaction_page_t page;
    uint32_t index;
    uint32_t found[CONSUMER_TRANSACTION_COUNT] = {0u, 0u, 0u};

    (void)memset(&query, 0, sizeof(query));
    set_header(&query.abi_version, &query.struct_size, sizeof(query));
    query.family_mask = NINLIL_FAMILY_MASK_EVENT_FACT;
    query.include_terminal = 1u;
    query.include_nonterminal = 1u;
    (void)memset(items, 0, sizeof(items));
    for (index = 0u; index < 8u; ++index) {
        set_header(
            &items[index].abi_version,
            &items[index].struct_size,
            sizeof(items[index]));
    }
    (void)memset(&page, 0, sizeof(page));
    set_header(&page.abi_version, &page.struct_size, sizeof(page));
    page.items = items;
    page.item_capacity = 8u;
    CONSUMER_REQUIRE(
        ninlil_transaction_list(runtime, &query, &page) == NINLIL_OK);
    CONSUMER_REQUIRE(page.item_count == CONSUMER_TRANSACTION_COUNT);
    CONSUMER_REQUIRE(page.has_more == 0u);
    for (index = 0u; index < page.item_count; ++index) {
        uint32_t expected;
        CONSUMER_REQUIRE(
            items[index].family == NINLIL_FAMILY_EVENT_FACT);
        for (expected = 0u;
             expected < CONSUMER_TRANSACTION_COUNT;
             ++expected) {
            if (id_equal(
                    &items[index].transaction_id,
                    &evidence->transactions[expected].transaction_id)) {
                found[expected] += 1u;
                CONSUMER_REQUIRE(
                    items[index].transaction_sequence
                    == evidence->transactions[expected]
                           .transaction_sequence);
                CONSUMER_REQUIRE(
                    items[index].record_revision
                    == evidence->transactions[expected].record_revision);
                CONSUMER_REQUIRE(
                    items[index].state
                    == evidence->transactions[expected].state);
                CONSUMER_REQUIRE(
                    items[index].outcome
                    == evidence->transactions[expected].outcome);
            }
        }
    }
    for (index = 0u; index < CONSUMER_TRANSACTION_COUNT; ++index) {
        CONSUMER_REQUIRE(found[index] == 1u);
    }
    return 1;
}

static int get_capacity_used(
    ninlil_runtime_t *runtime,
    ninlil_resource_kind_t kind,
    uint64_t *out_used)
{
    ninlil_capacity_entry_t entries[16];
    ninlil_capacity_snapshot_t snapshot;
    uint32_t index;

    (void)memset(entries, 0, sizeof(entries));
    for (index = 0u; index < 16u; ++index) {
        set_header(
            &entries[index].abi_version,
            &entries[index].struct_size,
            sizeof(entries[index]));
    }
    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version,
        &snapshot.struct_size,
        sizeof(snapshot));
    snapshot.entries = entries;
    snapshot.entry_capacity = 16u;
    CONSUMER_REQUIRE(
        ninlil_capacity_snapshot(runtime, &snapshot) == NINLIL_OK);
    CONSUMER_REQUIRE(snapshot.entry_count > 0u);
    for (index = 0u; index < snapshot.entry_count; ++index) {
        if (entries[index].kind == kind) {
            CONSUMER_REQUIRE(entries[index].used <= entries[index].limit);
            CONSUMER_REQUIRE(
                entries[index].high_water >= entries[index].used);
            *out_used = entries[index].used;
            return 1;
        }
    }
    (void)fprintf(
        stderr,
        "capacity entry missing for kind=%u\n",
        (unsigned)kind);
    return 0;
}

static int check_metrics(
    ninlil_runtime_t *runtime,
    uint64_t submission_calls,
    uint64_t admitted_ready,
    uint64_t already_admitted,
    uint64_t conflicts)
{
    ninlil_metrics_snapshot_t metrics;

    (void)memset(&metrics, 0, sizeof(metrics));
    set_header(
        &metrics.abi_version,
        &metrics.struct_size,
        sizeof(metrics));
    CONSUMER_REQUIRE(
        ninlil_metrics_snapshot(runtime, &metrics) == NINLIL_OK);
    CONSUMER_REQUIRE(metrics.submission_calls == submission_calls);
    CONSUMER_REQUIRE(metrics.admitted_ready == admitted_ready);
    CONSUMER_REQUIRE(metrics.already_admitted == already_admitted);
    CONSUMER_REQUIRE(metrics.idempotency_conflicts == conflicts);
    return 1;
}

static int step_runtime(ninlil_runtime_t *runtime)
{
    ninlil_step_budget_t budget;
    ninlil_step_result_t result;

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 2u;
    budget.max_callbacks = 2u;
    budget.max_state_transitions = 4u;
    budget.max_bearer_sends = 2u;
    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    CONSUMER_REQUIRE(
        ninlil_runtime_step(runtime, &budget, &result) == NINLIL_OK);
    CONSUMER_REQUIRE(
        result.ingress_processed <= budget.max_ingress_messages);
    CONSUMER_REQUIRE(result.callbacks_invoked <= budget.max_callbacks);
    CONSUMER_REQUIRE(
        result.state_transitions <= budget.max_state_transitions);
    CONSUMER_REQUIRE(result.bearer_sends <= budget.max_bearer_sends);
    CONSUMER_REQUIRE(result.health != NINLIL_HEALTH_FATAL);
    return 1;
}

static int save_transaction_evidence(
    ninlil_runtime_t *runtime,
    const consumer_services_t *services,
    consumer_restart_evidence_t *evidence)
{
    uint32_t index;

    for (index = 0u; index < CONSUMER_TRANSACTION_COUNT; ++index) {
        ninlil_transaction_snapshot_t snapshot;
        consumer_persisted_transaction_t *saved =
            &evidence->transactions[index];

        CONSUMER_REQUIRE(
            query_transaction(
                runtime,
                services,
                saved->service_index,
                &saved->transaction_id,
                &snapshot));
        CONSUMER_REQUIRE(
            digest_equal(&snapshot.content_digest, &saved->content_digest));
        saved->transaction_sequence = snapshot.transaction_sequence;
        saved->record_revision = snapshot.record_revision;
        saved->state = snapshot.state;
        saved->outcome = snapshot.outcome;
    }
    return 1;
}

static int verify_transaction_evidence(
    ninlil_runtime_t *runtime,
    const consumer_services_t *services,
    const consumer_restart_evidence_t *evidence)
{
    uint32_t index;

    for (index = 0u; index < CONSUMER_TRANSACTION_COUNT; ++index) {
        ninlil_transaction_snapshot_t snapshot;
        const consumer_persisted_transaction_t *saved =
            &evidence->transactions[index];

        CONSUMER_REQUIRE(
            query_transaction(
                runtime,
                services,
                saved->service_index,
                &saved->transaction_id,
                &snapshot));
        CONSUMER_REQUIRE(
            digest_equal(&snapshot.content_digest, &saved->content_digest));
        CONSUMER_REQUIRE(
            snapshot.transaction_sequence == saved->transaction_sequence);
        CONSUMER_REQUIRE(snapshot.record_revision == saved->record_revision);
        CONSUMER_REQUIRE(snapshot.state == saved->state);
        CONSUMER_REQUIRE(snapshot.outcome == saved->outcome);
    }
    return 1;
}

static int exercise_before_restart(
    const ninlil_storage_ops_t *storage,
    consumer_restart_evidence_t *evidence)
{
    static const uint8_t access_key[] = "access-idem";
    static const uint8_t temperature_key[] = "temperature-periodic";
    static const uint8_t response_key[] = "temperature-query-response";
    consumer_fixture_t fixture;
    consumer_services_t services;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_submission_result_t first;
    ninlil_submission_result_t repeated;
    ninlil_submission_result_t conflict;
    ninlil_submission_result_t temperature;
    ninlil_submission_result_t response;
    ninlil_transaction_snapshot_t before_dedupe;
    ninlil_transaction_snapshot_t after_dedupe;
    uint64_t used;
    int ok = 0;
    unsigned stage = 0u;

    (void)memset(evidence, 0, sizeof(*evidence));
    fixture_init(&fixture, storage);
    config = runtime_config();
    if (ninlil_runtime_create(&config, &fixture.platform, &runtime)
        != NINLIL_OK
        || runtime == NULL) {
        (void)fprintf(stderr, "initial runtime create failed\n");
        return 0;
    }
    if (!register_four_services(runtime, &services)) {
        goto cleanup;
    }
    stage = 1u;
    if (!get_capacity_used(runtime, NINLIL_RESOURCE_SERVICE, &used)
        || used != CONSUMER_SERVICE_COUNT) {
        (void)fprintf(
            stderr,
            "initial service capacity mismatch: used=%llu\n",
            (unsigned long long)used);
        goto cleanup;
    }
    stage = 2u;
    if (!get_capacity_used(
            runtime, NINLIL_RESOURCE_TRANSACTION, &used)
        || used != 0u) {
        (void)fprintf(
            stderr,
            "initial transaction capacity mismatch: used=%llu\n",
            (unsigned long long)used);
        goto cleanup;
    }
    stage = 3u;
    if (!check_metrics(runtime, 0u, 0u, 0u, 0u)) {
        goto cleanup;
    }
    stage = 4u;

    if (!submit_event(
            services.handles[CONSUMER_SERVICE_ACCESS_EVENT],
            access_key,
            (uint32_t)(sizeof(access_key) - 1u),
            0xe0u,
            ACCESS_PAYLOAD,
            (uint32_t)sizeof(ACCESS_PAYLOAD),
            ACCESS_PAYLOAD_DIGEST,
            &first)
        || first.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
        goto cleanup;
    }
    stage = 5u;
    evidence->transactions[0].transaction_id = first.transaction_id;
    set_digest_bytes(
        &evidence->transactions[0].content_digest,
        ACCESS_PAYLOAD_DIGEST);
    evidence->transactions[0].service_index =
        CONSUMER_SERVICE_ACCESS_EVENT;
    if (!query_transaction(
            runtime,
            &services,
            CONSUMER_SERVICE_ACCESS_EVENT,
            &first.transaction_id,
            &before_dedupe)) {
        goto cleanup;
    }
    stage = 6u;

    if (!submit_event(
            services.handles[CONSUMER_SERVICE_ACCESS_EVENT],
            access_key,
            (uint32_t)(sizeof(access_key) - 1u),
            0xe0u,
            ACCESS_PAYLOAD,
            (uint32_t)sizeof(ACCESS_PAYLOAD),
            ACCESS_PAYLOAD_DIGEST,
            &repeated)
        || repeated.kind != NINLIL_SUBMISSION_ALREADY_ADMITTED
        || !id_equal(&repeated.transaction_id, &first.transaction_id)
        || !submit_event(
            services.handles[CONSUMER_SERVICE_ACCESS_EVENT],
            access_key,
            (uint32_t)(sizeof(access_key) - 1u),
            0xe0u,
            ACCESS_CONFLICT_PAYLOAD,
            (uint32_t)sizeof(ACCESS_CONFLICT_PAYLOAD),
            ACCESS_CONFLICT_DIGEST,
            &conflict)
        || conflict.kind != NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT
        || !id_equal(&conflict.transaction_id, &first.transaction_id)
        || !query_transaction(
            runtime,
            &services,
            CONSUMER_SERVICE_ACCESS_EVENT,
            &first.transaction_id,
            &after_dedupe)
        || after_dedupe.transaction_sequence
            != before_dedupe.transaction_sequence
        || after_dedupe.record_revision != before_dedupe.record_revision
        || !digest_equal(
            &after_dedupe.content_digest,
            &before_dedupe.content_digest)) {
        goto cleanup;
    }
    stage = 7u;

    if (!submit_event(
            services.handles[CONSUMER_SERVICE_TEMPERATURE_TELEMETRY],
            temperature_key,
            (uint32_t)(sizeof(temperature_key) - 1u),
            0xe1u,
            TEMPERATURE_PAYLOAD,
            (uint32_t)sizeof(TEMPERATURE_PAYLOAD),
            TEMPERATURE_DIGEST,
            &temperature)
        || temperature.kind != NINLIL_SUBMISSION_ADMITTED_READY
        || !submit_event(
            services.handles[CONSUMER_SERVICE_TEMPERATURE_TELEMETRY],
            response_key,
            (uint32_t)(sizeof(response_key) - 1u),
            0xe2u,
            QUERY_RESPONSE_PAYLOAD,
            (uint32_t)sizeof(QUERY_RESPONSE_PAYLOAD),
            QUERY_RESPONSE_DIGEST,
            &response)
        || response.kind != NINLIL_SUBMISSION_ADMITTED_READY) {
        goto cleanup;
    }
    evidence->transactions[1].transaction_id = temperature.transaction_id;
    set_digest_bytes(
        &evidence->transactions[1].content_digest,
        TEMPERATURE_DIGEST);
    evidence->transactions[1].service_index =
        CONSUMER_SERVICE_TEMPERATURE_TELEMETRY;
    evidence->transactions[2].transaction_id = response.transaction_id;
    set_digest_bytes(
        &evidence->transactions[2].content_digest,
        QUERY_RESPONSE_DIGEST);
    evidence->transactions[2].service_index =
        CONSUMER_SERVICE_TEMPERATURE_TELEMETRY;

    if (!check_metrics(runtime, 5u, 3u, 1u, 1u)
        || !step_runtime(runtime)
        || !save_transaction_evidence(runtime, &services, evidence)
        || !list_three_transactions(runtime, evidence)
        || !get_capacity_used(
            runtime, NINLIL_RESOURCE_SERVICE, &used)
        || used != CONSUMER_SERVICE_COUNT) {
        goto cleanup;
    }
    evidence->service_capacity_used = used;
    if (!get_capacity_used(
            runtime, NINLIL_RESOURCE_TRANSACTION, &used)
        || used != CONSUMER_TRANSACTION_COUNT) {
        goto cleanup;
    }
    evidence->transaction_capacity_used = used;
    ok = 1;

cleanup:
    if (!ok) {
        (void)fprintf(
            stderr,
            "initial acceptance failed at stage=%u\n",
            stage);
    }
    if (ninlil_runtime_destroy(runtime) != NINLIL_OK) {
        ok = 0;
    }
    return ok;
}

static int exercise_after_restart(
    const ninlil_storage_ops_t *storage,
    const consumer_restart_evidence_t *evidence)
{
    static const uint8_t access_key[] = "access-idem";
    consumer_fixture_t fixture;
    consumer_services_t services;
    ninlil_runtime_config_t config;
    ninlil_runtime_t *runtime = NULL;
    ninlil_submission_result_t repeated;
    ninlil_submission_result_t conflict;
    ninlil_transaction_snapshot_t before_dedupe;
    ninlil_transaction_snapshot_t after_dedupe;
    uint64_t used;
    int ok = 0;
    unsigned stage = 0u;

    fixture_init(&fixture, storage);
    config = runtime_config();
    if (ninlil_runtime_create(&config, &fixture.platform, &runtime)
        != NINLIL_OK
        || runtime == NULL) {
        (void)fprintf(stderr, "fresh runtime create failed\n");
        return 0;
    }

    /*
     * Service registry restoration happens during create, before volatile
     * handles are reattached. This makes durable service state observable
     * without a private service-registry API.
     */
    if (!get_capacity_used(runtime, NINLIL_RESOURCE_SERVICE, &used)
        || used != evidence->service_capacity_used
        || !verify_four_services_were_restored(runtime)
        || !register_four_services(runtime, &services)
        || !get_capacity_used(runtime, NINLIL_RESOURCE_SERVICE, &used)
        || used != evidence->service_capacity_used
        || !verify_transaction_evidence(runtime, &services, evidence)
        || !list_three_transactions(runtime, evidence)
        || !query_transaction(
            runtime,
            &services,
            CONSUMER_SERVICE_ACCESS_EVENT,
            &evidence->transactions[0].transaction_id,
            &before_dedupe)) {
        goto cleanup;
    }
    stage = 1u;

    if (!submit_event(
            services.handles[CONSUMER_SERVICE_ACCESS_EVENT],
            access_key,
            (uint32_t)(sizeof(access_key) - 1u),
            0xe0u,
            ACCESS_PAYLOAD,
            (uint32_t)sizeof(ACCESS_PAYLOAD),
            ACCESS_PAYLOAD_DIGEST,
            &repeated)
        || repeated.kind != NINLIL_SUBMISSION_ALREADY_ADMITTED
        || !id_equal(
            &repeated.transaction_id,
            &evidence->transactions[0].transaction_id)
        || !submit_event(
            services.handles[CONSUMER_SERVICE_ACCESS_EVENT],
            access_key,
            (uint32_t)(sizeof(access_key) - 1u),
            0xe0u,
            ACCESS_CONFLICT_PAYLOAD,
            (uint32_t)sizeof(ACCESS_CONFLICT_PAYLOAD),
            ACCESS_CONFLICT_DIGEST,
            &conflict)
        || conflict.kind != NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT
        || !id_equal(
            &conflict.transaction_id,
            &evidence->transactions[0].transaction_id)
        || !query_transaction(
            runtime,
            &services,
            CONSUMER_SERVICE_ACCESS_EVENT,
            &evidence->transactions[0].transaction_id,
            &after_dedupe)
        || after_dedupe.transaction_sequence
            != before_dedupe.transaction_sequence
        || after_dedupe.record_revision != before_dedupe.record_revision
        || !digest_equal(
            &after_dedupe.content_digest,
            &before_dedupe.content_digest)
        || !get_capacity_used(
            runtime, NINLIL_RESOURCE_TRANSACTION, &used)
        || used != evidence->transaction_capacity_used
        || !list_three_transactions(runtime, evidence)
        || !check_metrics(runtime, 2u, 0u, 1u, 1u)
        || !step_runtime(runtime)) {
        goto cleanup;
    }
    stage = 2u;
    ok = 1;

cleanup:
    if (!ok) {
        (void)fprintf(
            stderr,
            "restart acceptance failed at stage=%u\n",
            stage);
    }
    if (ninlil_runtime_destroy(runtime) != NINLIL_OK) {
        ok = 0;
    }
    return ok;
}

#endif /* NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY */

#if defined(NINLIL_CONSUMER_WITH_SQLITE)
static void remove_database_artifacts(const char *path)
{
    char sidecar[1024];

    (void)remove(path);
    if (snprintf(sidecar, sizeof(sidecar), "%s-wal", path) > 0) {
        (void)remove(sidecar);
    }
    if (snprintf(sidecar, sizeof(sidecar), "%s-shm", path) > 0) {
        (void)remove(sidecar);
    }
    if (snprintf(sidecar, sizeof(sidecar), "%s.ninlil-lock", path) > 0) {
        (void)remove(sidecar);
    }
}

static ninlil_posix_sqlite_storage_t *create_sqlite_storage(
    const char *database_path)
{
    ninlil_posix_sqlite_storage_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.database_path = database_path;
    config.busy_timeout_ms =
        NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS;
    config.max_entries_per_namespace = 512u;
    config.max_bytes_per_namespace = 1048576u;
    config.max_handles = 8u;
    config.max_transactions = 8u;
    config.max_iterators = 8u;
    return ninlil_posix_sqlite_storage_create(&config);
}

static int sqlite_storage_is_clean(
    const ninlil_posix_sqlite_storage_t *storage)
{
    return ninlil_posix_sqlite_storage_live_handles(storage) == 0u
        && ninlil_posix_sqlite_storage_live_transactions(storage) == 0u
        && ninlil_posix_sqlite_storage_live_iterators(storage) == 0u;
}

static int make_database_variant_path(
    char *out,
    size_t out_size,
    const char *database_path,
    const char *suffix)
{
    int written = snprintf(
        out, out_size, "%s.%s", database_path, suffix);

    return written > 0 && (size_t)written < out_size;
}

int main(int argc, char **argv)
{
    ninlil_posix_sqlite_storage_t *storage;
    const char *database_path;
    int result = 0;
#if !defined(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY)
    consumer_restart_evidence_t evidence;
    consumer_exact_restart_evidence_t exact_evidence;
    char profile_database_path[1024];
    char exact_database_path[1024];
    uint32_t profile_index;
    int exact_before_ok = 0;
#endif

    if (argc != 2 || argv[1] == NULL || argv[1][0] == '\0') {
        (void)fprintf(stderr, "usage: consumer <sqlite-database-path>\n");
        return 2;
    }
    database_path = argv[1];
    remove_database_artifacts(database_path);
#if !defined(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY)
    if (!make_database_variant_path(
            profile_database_path,
            sizeof(profile_database_path),
            database_path,
            "profiles")
        || !make_database_variant_path(
            exact_database_path,
            sizeof(exact_database_path),
            database_path,
            "exact")) {
        (void)fprintf(stderr, "SQLite variant path is too long\n");
        return 1;
    }
    remove_database_artifacts(profile_database_path);
    remove_database_artifacts(exact_database_path);

    storage = create_sqlite_storage(profile_database_path);
    if (storage == NULL) {
        (void)fprintf(stderr, "SQLite profile storage create failed\n");
        return 1;
    }
    for (profile_index = 0u;
         profile_index < CONSUMER_PROFILE_COUNT;
         ++profile_index) {
        if (!exercise_public_profile_case(
                ninlil_posix_sqlite_storage_ops(storage),
                profile_index)) {
            result = 1;
            break;
        }
    }
    if (result == 0
        && !exercise_unknown_profile_rejection(
            ninlil_posix_sqlite_storage_ops(storage))) {
        result = 1;
    }
    if (!sqlite_storage_is_clean(storage)) {
        result = 1;
    }
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_database_artifacts(profile_database_path);

    storage = create_sqlite_storage(exact_database_path);
    if (storage != NULL
        && exercise_exact_targets_before_restart(
            ninlil_posix_sqlite_storage_ops(storage),
            &exact_evidence)
        && sqlite_storage_is_clean(storage)) {
        exact_before_ok = 1;
    } else {
        result = 1;
    }
    if (storage != NULL) {
        ninlil_posix_sqlite_storage_destroy(storage);
    }
    storage = create_sqlite_storage(exact_database_path);
    if (storage == NULL
        || exact_before_ok == 0
        || !exercise_exact_targets_after_restart(
            ninlil_posix_sqlite_storage_ops(storage),
            &exact_evidence)
        || !sqlite_storage_is_clean(storage)) {
        result = 1;
    }
    if (storage != NULL) {
        ninlil_posix_sqlite_storage_destroy(storage);
    }
    remove_database_artifacts(exact_database_path);
#endif

    storage = create_sqlite_storage(database_path);
    if (storage == NULL) {
        (void)fprintf(stderr, "SQLite storage create failed\n");
        return 1;
    }
#if defined(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY)
    result = exercise_domain_create_fail_closed(
        ninlil_posix_sqlite_storage_ops(storage))
        ? 0 : 1;
    if (!sqlite_storage_is_clean(storage)) {
        result = 1;
    }
    ninlil_posix_sqlite_storage_destroy(storage);
#else
    if (!exercise_before_restart(
            ninlil_posix_sqlite_storage_ops(storage), &evidence)
        || !sqlite_storage_is_clean(storage)) {
        result = 1;
    }
    ninlil_posix_sqlite_storage_destroy(storage);

    /*
     * A new provider object and connection must recover the durable state
     * from disk. Reusing the original provider would not prove this boundary.
     */
    storage = create_sqlite_storage(database_path);
    if (storage == NULL
        || !exercise_after_restart(
            ninlil_posix_sqlite_storage_ops(storage), &evidence)
        || !sqlite_storage_is_clean(storage)) {
        result = 1;
    }
    if (storage != NULL) {
        ninlil_posix_sqlite_storage_destroy(storage);
    }
#endif
    remove_database_artifacts(database_path);
    if (result == 0) {
        (void)printf(
            "installed_host_runtime_sqlite_consumer "
            "roles=3 environments=4 exact_targets=2,4 "
            "services=4 transactions=3 cold_reopen=1 ok\n");
    }
    return result;
}
#else
int main(void)
{
    consumer_memory_storage_t *storage;
    int result = 0;
#if !defined(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY)
    consumer_restart_evidence_t evidence;
    consumer_exact_restart_evidence_t exact_evidence;
    uint32_t profile_index;
#endif

    storage = consumer_memory_storage_create();
    if (storage == NULL) {
        (void)fprintf(stderr, "memory storage create failed\n");
        return 1;
    }
#if defined(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY)
    result = exercise_domain_create_fail_closed(
        consumer_memory_storage_ops(storage))
        ? 0 : 1;
#else
    /*
     * This intentionally tiny consumer-owned provider supports one namespace.
     * Give every profile case a fresh provider so the 3x4 create matrix does
     * not accidentally depend on SQLite's multi-namespace implementation.
     */
    consumer_memory_storage_destroy(storage);
    storage = NULL;
    for (profile_index = 0u;
         profile_index < CONSUMER_PROFILE_COUNT;
         ++profile_index) {
        storage = consumer_memory_storage_create();
        if (storage == NULL
            || !exercise_public_profile_case(
                consumer_memory_storage_ops(storage),
                profile_index)
            || consumer_memory_storage_live_handles(storage) != 0u
            || consumer_memory_storage_live_transactions(storage) != 0u
            || consumer_memory_storage_live_iterators(storage) != 0u) {
            result = 1;
        }
        if (storage != NULL) {
            consumer_memory_storage_destroy(storage);
            storage = NULL;
        }
        if (result != 0) {
            break;
        }
    }

    storage = consumer_memory_storage_create();
    if (storage == NULL
        || !exercise_unknown_profile_rejection(
            consumer_memory_storage_ops(storage))
        || !exercise_exact_targets_before_restart(
            consumer_memory_storage_ops(storage), &exact_evidence)
        || !exercise_exact_targets_after_restart(
            consumer_memory_storage_ops(storage), &exact_evidence)
        || consumer_memory_storage_live_handles(storage) != 0u
        || consumer_memory_storage_live_transactions(storage) != 0u
        || consumer_memory_storage_live_iterators(storage) != 0u) {
        result = 1;
    }
    if (storage != NULL) {
        consumer_memory_storage_destroy(storage);
    }

    storage = consumer_memory_storage_create();
    if (storage == NULL) {
        (void)fprintf(stderr, "memory lifecycle storage create failed\n");
        return 1;
    }
    if (!exercise_before_restart(
            consumer_memory_storage_ops(storage), &evidence)
        || !exercise_after_restart(
            consumer_memory_storage_ops(storage), &evidence)) {
        result = 1;
    }
#endif
    if (consumer_memory_storage_live_handles(storage) != 0u
        || consumer_memory_storage_live_transactions(storage) != 0u
        || consumer_memory_storage_live_iterators(storage) != 0u) {
        (void)fprintf(stderr, "memory storage cleanup failed\n");
        result = 1;
    }
    consumer_memory_storage_destroy(storage);
    if (result == 0) {
        (void)printf(
            "installed_host_runtime_memory_consumer "
            "roles=3 environments=4 exact_targets=2,4 "
            "services=4 transactions=3 same_durable_object=1 ok\n");
    }
    return result;
}
#endif
