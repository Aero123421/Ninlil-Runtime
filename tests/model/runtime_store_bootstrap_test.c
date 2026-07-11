#include "runtime_store_bootstrap.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct snapshot_fixture {
    ninlil_model_runtime_store_bootstrap_plan_t plan;
    ninlil_model_runtime_store_bootstrap_record_t records[17];
    ninlil_model_runtime_store_encoded_snapshot_t encoded;
    ninlil_model_runtime_store_validated_snapshot_t validated;
} snapshot_fixture_t;

static int bytes_are_zero(const void *value, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)value;
    size_t index;
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) return 0;
    }
    return 1;
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint8_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static ninlil_runtime_config_t config_fixture(void)
{
    static const uint8_t NAME[] = "bootstrap-test";
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x10u);
    config.local_identity.abi_version = NINLIL_ABI_VERSION;
    config.local_identity.struct_size =
        (uint16_t)sizeof(config.local_identity);
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x20u);
    set_id(&config.local_identity.installation_id, 0x40u);
    set_id(&config.local_identity.site_domain_id, 0x60u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = NAME;
    config.storage_namespace.length = sizeof(NAME) - 1u;
    config.limits.abi_version = NINLIL_ABI_VERSION;
    config.limits.struct_size = (uint16_t)sizeof(config.limits);
    config.limits.max_services = 7u;
    config.limits.max_nonterminal_transactions = 20u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 5000u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 30u;
    config.limits.max_nonterminal_deliveries = 12u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.limits.max_result_cache_entries = 13u;
    config.limits.max_retained_dispositions = 14u;
    config.limits.max_ingress_per_step = 15u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 17u;
    config.limits.max_bearer_sends_per_step = 18u;
    config.limits.max_deferred_tokens = 11u;
    config.terminal_retention_ms = 1000u;
    config.result_cache_retention_ms = 900u;
    config.observation_retention_ms = 800u;
    return config;
}

static ninlil_model_runtime_validation_result_t validation_fixture(
    const ninlil_runtime_config_t *config)
{
    ninlil_model_runtime_validation_result_t validation;
    (void)memset(&validation, 0, sizeof(validation));
    validation.status = NINLIL_OK;
    validation.failure_field = NINLIL_MODEL_RUNTIME_VALIDATION_NONE;
    (void)ninlil_model_runtime_derive_capacity_limits(
        &config->limits, &validation.capacity_limits);
    validation.accepted_config.role = config->role;
    validation.accepted_config.environment = config->environment;
    validation.accepted_config.runtime_id = config->runtime_id;
    validation.accepted_config.identity_flags = config->local_identity.flags;
    validation.accepted_config.device_id = config->local_identity.device_id;
    validation.accepted_config.installation_id =
        config->local_identity.installation_id;
    validation.accepted_config.site_domain_id =
        config->local_identity.site_domain_id;
    validation.accepted_config.binding_epoch =
        config->local_identity.binding_epoch;
    validation.accepted_config.membership_epoch =
        config->local_identity.membership_epoch;
#define COPY_ATTESTED_LIMIT(field) \
    validation.accepted_config.limits.field = config->limits.field
    COPY_ATTESTED_LIMIT(max_services);
    COPY_ATTESTED_LIMIT(max_nonterminal_transactions);
    COPY_ATTESTED_LIMIT(max_targets_per_transaction);
    COPY_ATTESTED_LIMIT(max_logical_payload_bytes);
    COPY_ATTESTED_LIMIT(max_durable_outbox_payload_bytes);
    COPY_ATTESTED_LIMIT(max_attempts_per_target_per_cycle);
    COPY_ATTESTED_LIMIT(max_cancel_attempts_per_transaction);
    COPY_ATTESTED_LIMIT(max_evidence_per_target);
    COPY_ATTESTED_LIMIT(max_retained_terminal_transactions);
    COPY_ATTESTED_LIMIT(max_nonterminal_deliveries);
    COPY_ATTESTED_LIMIT(max_event_spool_count);
    COPY_ATTESTED_LIMIT(max_event_spool_bytes);
    COPY_ATTESTED_LIMIT(max_result_cache_entries);
    COPY_ATTESTED_LIMIT(max_retained_dispositions);
    COPY_ATTESTED_LIMIT(max_ingress_per_step);
    COPY_ATTESTED_LIMIT(max_callbacks_per_step);
    COPY_ATTESTED_LIMIT(max_state_transitions_per_step);
    COPY_ATTESTED_LIMIT(max_bearer_sends_per_step);
    COPY_ATTESTED_LIMIT(max_deferred_tokens);
#undef COPY_ATTESTED_LIMIT
    validation.accepted_config.terminal_retention_ms =
        config->terminal_retention_ms;
    validation.accepted_config.result_cache_retention_ms =
        config->result_cache_retention_ms;
    validation.accepted_config.observation_retention_ms =
        config->observation_retention_ms;
    return validation;
}

static int make_snapshot(snapshot_fixture_t *fixture)
{
    ninlil_runtime_config_t config = config_fixture();
    ninlil_model_runtime_validation_result_t validation =
        validation_fixture(&config);
    uint32_t index;

    (void)memset(fixture, 0, sizeof(*fixture));
    if (ninlil_model_runtime_store_build_bootstrap_plan(
            &validation, &fixture->plan) != NINLIL_OK) return 0;
    for (index = 0u; index < 17u; ++index) {
        if (ninlil_model_runtime_store_bootstrap_record_at(
                &fixture->plan, index, &fixture->records[index])
            != NINLIL_OK) return 0;
        fixture->encoded.values[index].data = fixture->records[index].value;
        fixture->encoded.values[index].length =
            fixture->records[index].value_length;
    }
    return ninlil_model_runtime_store_validate_snapshot(
        &fixture->encoded, &fixture->validated) == NINLIL_OK;
}

static uint32_t crc32c(const uint8_t *bytes, uint32_t length)
{
    uint32_t crc = UINT32_MAX;
    uint32_t index;
    for (index = 0u; index < length; ++index) {
        uint32_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1u) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

static void refresh_crc(uint8_t *value, uint32_t length)
{
    uint32_t crc = crc32c(value, length - 4u);
    value[length - 4u] = (uint8_t)(crc >> 24u);
    value[length - 3u] = (uint8_t)(crc >> 16u);
    value[length - 2u] = (uint8_t)(crc >> 8u);
    value[length - 1u] = (uint8_t)crc;
}

static int expect_binding(
    const ninlil_model_runtime_store_validated_snapshot_t *stored,
    const ninlil_model_runtime_store_binding_t *candidate,
    ninlil_model_runtime_store_binding_comparison_t expected)
{
    ninlil_model_runtime_store_binding_comparison_t actual =
        NINLIL_MODEL_RUNTIME_STORE_BINDING_COMPARISON_NONE;
    return ninlil_model_runtime_store_compare_binding(
        stored, candidate, &actual) == NINLIL_OK && actual == expected;
}

static int expect_identity(
    const ninlil_model_runtime_store_validated_snapshot_t *stored,
    const ninlil_model_runtime_store_identity_t *requested,
    ninlil_model_runtime_store_identity_decision_t expected)
{
    ninlil_model_runtime_store_identity_decision_t actual =
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_DECISION_NONE;
    return ninlil_model_runtime_store_decide_identity(
        stored, requested, &actual) == NINLIL_OK && actual == expected;
}

static int test_plan_and_canonical_projection(void)
{
    snapshot_fixture_t fixture;
    ninlil_runtime_config_t config = config_fixture();
    ninlil_model_runtime_validation_result_t validation =
        validation_fixture(&config);
    uint32_t index;
    uint32_t encoded = 0u;
    uint32_t logical = 0u;

    REQUIRE(make_snapshot(&fixture));
    REQUIRE(fixture.plan.record_count == 17u);
    REQUIRE(fixture.plan.encoded_key_value_bytes == 1311u);
    REQUIRE(fixture.plan.logical_bytes == 1583u);
    REQUIRE(fixture.plan.binding.storage_schema == NINLIL_STORAGE_SCHEMA_M1A);
    REQUIRE(fixture.plan.binding.role == config.role);
    REQUIRE(fixture.plan.binding.environment == config.environment);
    REQUIRE(memcmp(fixture.plan.binding.runtime_id.bytes,
        config.runtime_id.bytes, 16u) == 0);
#define CHECK_LIMIT(field) \
    REQUIRE(fixture.plan.binding.limits.field == config.limits.field)
    CHECK_LIMIT(max_services);
    CHECK_LIMIT(max_nonterminal_transactions);
    CHECK_LIMIT(max_targets_per_transaction);
    CHECK_LIMIT(max_logical_payload_bytes);
    CHECK_LIMIT(max_durable_outbox_payload_bytes);
    CHECK_LIMIT(max_attempts_per_target_per_cycle);
    CHECK_LIMIT(max_cancel_attempts_per_transaction);
    CHECK_LIMIT(max_evidence_per_target);
    CHECK_LIMIT(max_retained_terminal_transactions);
    CHECK_LIMIT(max_nonterminal_deliveries);
    CHECK_LIMIT(max_event_spool_count);
    CHECK_LIMIT(max_event_spool_bytes);
    CHECK_LIMIT(max_result_cache_entries);
    CHECK_LIMIT(max_retained_dispositions);
    CHECK_LIMIT(max_ingress_per_step);
    CHECK_LIMIT(max_callbacks_per_step);
    CHECK_LIMIT(max_state_transitions_per_step);
    CHECK_LIMIT(max_bearer_sends_per_step);
    CHECK_LIMIT(max_deferred_tokens);
#undef CHECK_LIMIT
    REQUIRE(fixture.plan.binding.terminal_retention_ms
        == config.terminal_retention_ms);
    REQUIRE(fixture.plan.binding.result_cache_retention_ms
        == config.result_cache_retention_ms);
    REQUIRE(fixture.plan.binding.observation_retention_ms
        == config.observation_retention_ms);
    REQUIRE(memcmp(fixture.plan.capacity_limits.values,
        validation.capacity_limits.values,
        sizeof(validation.capacity_limits.values)) == 0);

    for (index = 0u; index < 17u; ++index) {
        ninlil_model_runtime_store_key_t expected_key;
        REQUIRE(ninlil_model_runtime_store_build_key(
            (ninlil_model_runtime_store_key_id_t)(index + 1u),
            &expected_key) == NINLIL_OK);
        REQUIRE(fixture.records[index].key.length == expected_key.length);
        REQUIRE(memcmp(fixture.records[index].key.bytes,
            expected_key.bytes, expected_key.length) == 0);
        if (index != 0u) {
            REQUIRE(memcmp(fixture.records[index - 1u].key.bytes,
                fixture.records[index].key.bytes,
                fixture.records[index - 1u].key.length) < 0);
        }
        encoded += fixture.records[index].key.length
            + fixture.records[index].value_length;
        logical += 16u + fixture.records[index].key.length
            + fixture.records[index].value_length;
        if (index >= 2u && index < 6u) {
            REQUIRE(fixture.validated.counters[index - 2u].kind
                == (ninlil_model_runtime_store_counter_kind_t)(index - 1u));
            REQUIRE(fixture.validated.counters[index - 2u].value == 0u);
            REQUIRE(fixture.validated.counters[index - 2u].exhausted_marker == 0u);
        } else if (index >= 6u) {
            uint32_t capacity_index = index - 6u;
            REQUIRE(fixture.validated.capacities[capacity_index].kind
                == (ninlil_resource_kind_t)(capacity_index + 1u));
            REQUIRE(fixture.validated.capacities[capacity_index].limit
                == validation.capacity_limits.values[capacity_index]);
            REQUIRE(fixture.validated.capacities[capacity_index].used == 0u);
            REQUIRE(fixture.validated.capacities[capacity_index].reserved == 0u);
            REQUIRE(fixture.validated.capacities[capacity_index].high_water == 0u);
            REQUIRE(fixture.validated.capacities[capacity_index].capacity_epoch == 1u);
            REQUIRE(fixture.validated.capacities[capacity_index].blocked == 0u);
            REQUIRE(fixture.validated.capacities[capacity_index].counter_exhausted == 0u);
        }
    }
    REQUIRE(encoded == 1311u && logical == 1583u);
    return 0;
}

static int test_binding_all_field_mutations(void)
{
    snapshot_fixture_t fixture;
    ninlil_model_runtime_store_binding_t candidate;
    REQUIRE(make_snapshot(&fixture));
    REQUIRE(expect_binding(&fixture.validated, &fixture.plan.binding,
        NINLIL_MODEL_RUNTIME_STORE_BINDING_EXACT));
#define MUTATE_BIND(field)                                                    \
    do {                                                                      \
        candidate = fixture.plan.binding;                                     \
        candidate.field ^= 1u;                                                \
        REQUIRE(expect_binding(&fixture.validated, &candidate,                \
            NINLIL_MODEL_RUNTIME_STORE_BINDING_UNSUPPORTED));                 \
    } while (0)
#define MUTATE_LIMIT(field) MUTATE_BIND(limits.field)
    MUTATE_BIND(storage_schema);
    MUTATE_BIND(role);
    MUTATE_BIND(environment);
    candidate = fixture.plan.binding;
    candidate.runtime_id.bytes[7] ^= 1u;
    REQUIRE(expect_binding(&fixture.validated, &candidate,
        NINLIL_MODEL_RUNTIME_STORE_BINDING_UNSUPPORTED));
    MUTATE_LIMIT(max_services);
    MUTATE_LIMIT(max_nonterminal_transactions);
    MUTATE_LIMIT(max_targets_per_transaction);
    MUTATE_LIMIT(max_logical_payload_bytes);
    MUTATE_LIMIT(max_durable_outbox_payload_bytes);
    MUTATE_LIMIT(max_attempts_per_target_per_cycle);
    MUTATE_LIMIT(max_cancel_attempts_per_transaction);
    MUTATE_LIMIT(max_evidence_per_target);
    MUTATE_LIMIT(max_retained_terminal_transactions);
    MUTATE_LIMIT(max_nonterminal_deliveries);
    MUTATE_LIMIT(max_event_spool_count);
    MUTATE_LIMIT(max_event_spool_bytes);
    MUTATE_LIMIT(max_result_cache_entries);
    MUTATE_LIMIT(max_retained_dispositions);
    MUTATE_LIMIT(max_ingress_per_step);
    MUTATE_LIMIT(max_callbacks_per_step);
    MUTATE_LIMIT(max_state_transitions_per_step);
    MUTATE_LIMIT(max_bearer_sends_per_step);
    MUTATE_LIMIT(max_deferred_tokens);
    MUTATE_BIND(terminal_retention_ms);
    MUTATE_BIND(result_cache_retention_ms);
    MUTATE_BIND(observation_retention_ms);
#undef MUTATE_LIMIT
#undef MUTATE_BIND
    return 0;
}

static int test_endpoint_canonical_plan(void)
{
    ninlil_runtime_config_t config = config_fixture();
    ninlil_model_runtime_validation_result_t validation;
    ninlil_model_runtime_store_bootstrap_plan_t plan;

    config.role = NINLIL_ROLE_ENDPOINT;
    config.limits.max_durable_outbox_payload_bytes = 0u;
    config.limits.max_event_spool_count = 10u;
    config.limits.max_event_spool_bytes = 10000u;
    config.local_identity.flags &=
        ~NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    (void)memset(&config.local_identity.installation_id, 0,
        sizeof(config.local_identity.installation_id));
    validation = validation_fixture(&config);
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
        &validation, &plan) == NINLIL_OK);
    REQUIRE(plan.binding.role == NINLIL_ROLE_ENDPOINT);
    REQUIRE(plan.binding.limits.max_event_spool_count == 10u);
    REQUIRE(plan.binding.limits.max_event_spool_bytes == 10000u);
    REQUIRE((plan.identity.flags
        & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) == 0u);
    REQUIRE(bytes_are_zero(&plan.identity.installation_id,
        sizeof(plan.identity.installation_id)));
    return 0;
}

static int test_presence_matrix(void)
{
    ninlil_model_runtime_store_presence_input_t input;
    ninlil_model_runtime_store_presence_class_t result;
    uint32_t index;

    input.present_mask = NINLIL_MODEL_RUNTIME_STORE_PRESENT_ALL_MASK;
    input.zero_record_scan =
        (ninlil_model_runtime_store_scan_result_t)99;
    REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
        == NINLIL_OK);
    REQUIRE(result
        == NINLIL_MODEL_RUNTIME_STORE_PRESENCE_ALL_PRESENT_UNVALIDATED);
    for (index = 0u; index < 17u; ++index) {
        input.present_mask = NINLIL_MODEL_RUNTIME_STORE_PRESENT_ALL_MASK
            & ~(UINT32_C(1) << index);
        input.zero_record_scan =
            (ninlil_model_runtime_store_scan_result_t)99;
        REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(result == NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NONE);
        input.present_mask = UINT32_C(1) << index;
        REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
            == NINLIL_E_STORAGE_CORRUPT);
    }
    input.present_mask = 0u;
    input.zero_record_scan = NINLIL_MODEL_RUNTIME_STORE_SCAN_EMPTY;
    REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
        == NINLIL_OK);
    REQUIRE(result == NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NEW);
    input.zero_record_scan = NINLIL_MODEL_RUNTIME_STORE_SCAN_NOT_CONFIRMED;
    REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    input.zero_record_scan =
        NINLIL_MODEL_RUNTIME_STORE_SCAN_CURRENT_OR_UNKNOWN_EXTRA;
    REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    input.zero_record_scan = NINLIL_MODEL_RUNTIME_STORE_SCAN_MIXED;
    REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    input.zero_record_scan =
        NINLIL_MODEL_RUNTIME_STORE_SCAN_RECOGNIZABLE_FUTURE;
    REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
        == NINLIL_E_UNSUPPORTED);
    input.present_mask = UINT32_C(1) << 17u;
    REQUIRE(ninlil_model_runtime_store_classify_presence(&input, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_identity_decision_matrix(void)
{
    snapshot_fixture_t fixture;
    ninlil_model_runtime_store_identity_t requested;
    ninlil_model_runtime_store_validated_snapshot_t max_stored;
    ninlil_model_runtime_store_identity_decision_t decision;
    REQUIRE(make_snapshot(&fixture));
    requested = fixture.plan.identity;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_EXACT));
    requested.device_id.bytes[0] ^= 1u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT));

    requested = fixture.plan.identity;
    requested.binding_epoch = 2u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION));
    max_stored = fixture.validated;
    max_stored.identity.binding_epoch = 2u;
    requested = max_stored.identity;
    requested.binding_epoch = 1u;
    REQUIRE(expect_identity(&max_stored, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT));

    requested = fixture.plan.identity;
    requested.flags &= ~NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    (void)memset(&requested.installation_id, 0,
        sizeof(requested.installation_id));
    requested.binding_epoch = 2u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION));
    max_stored = fixture.validated;
    max_stored.identity.flags &=
        ~NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    (void)memset(&max_stored.identity.installation_id, 0,
        sizeof(max_stored.identity.installation_id));
    requested = fixture.plan.identity;
    requested.binding_epoch = 2u;
    REQUIRE(expect_identity(&max_stored, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION));

    requested = fixture.plan.identity;
    requested.installation_id.bytes[0] ^= 1u;
    requested.binding_epoch = 2u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION));
    requested.binding_epoch = 1u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT));
    requested.binding_epoch = 0u;
    decision = NINLIL_MODEL_RUNTIME_STORE_IDENTITY_EXACT;
    REQUIRE(ninlil_model_runtime_store_decide_identity(
        &fixture.validated, &requested, &decision) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(decision == NINLIL_MODEL_RUNTIME_STORE_IDENTITY_DECISION_NONE);

    requested = fixture.plan.identity;
    requested.site_domain_id.bytes[0] ^= 1u;
    requested.membership_epoch = 2u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION));
    requested.membership_epoch = 1u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT));

    requested = fixture.plan.identity;
    requested.flags &= ~NINLIL_LOCAL_IDENTITY_HAS_SITE;
    (void)memset(&requested.site_domain_id, 0,
        sizeof(requested.site_domain_id));
    decision = NINLIL_MODEL_RUNTIME_STORE_IDENTITY_EXACT;
    REQUIRE(ninlil_model_runtime_store_decide_identity(
        &fixture.validated, &requested, &decision) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(decision == NINLIL_MODEL_RUNTIME_STORE_IDENTITY_DECISION_NONE);
    requested = fixture.plan.identity;
    requested.flags &= ~NINLIL_LOCAL_IDENTITY_HAS_DEVICE;
    (void)memset(&requested.device_id, 0, sizeof(requested.device_id));
    decision = NINLIL_MODEL_RUNTIME_STORE_IDENTITY_EXACT;
    REQUIRE(ninlil_model_runtime_store_decide_identity(
        &fixture.validated, &requested, &decision) == NINLIL_E_INVALID_ARGUMENT);

    requested = fixture.plan.identity;
    requested.installation_id.bytes[0] ^= 1u;
    requested.site_domain_id.bytes[0] ^= 1u;
    requested.binding_epoch = 2u;
    requested.membership_epoch = 2u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION));
    requested.membership_epoch = 1u;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT));

    requested = fixture.plan.identity;
    requested.binding_epoch = UINT64_MAX;
    requested.membership_epoch = UINT64_MAX;
    REQUIRE(expect_identity(&fixture.validated, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION));

    max_stored = fixture.validated;
    max_stored.identity.binding_epoch = UINT64_MAX;
    max_stored.identity.membership_epoch = UINT64_MAX;
    requested = max_stored.identity;
    REQUIRE(expect_identity(&max_stored, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_EXACT));
    requested.installation_id.bytes[0] ^= 1u;
    REQUIRE(expect_identity(&max_stored, &requested,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT));
    return 0;
}

static int test_snapshot_aggregate_precedence(void)
{
    snapshot_fixture_t fixture;
    ninlil_model_runtime_store_validated_snapshot_t output;
    uint8_t future_binding[NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES];
    uint8_t corrupt_capacity[NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES];
    REQUIRE(make_snapshot(&fixture));
    (void)memcpy(future_binding, fixture.records[0].value,
        fixture.records[0].value_length);
    future_binding[7] = 2u;
    refresh_crc(future_binding, sizeof(future_binding));
    fixture.encoded.values[0].data = future_binding;
    (void)memset(&output, 0xa5, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &fixture.encoded, &output) == NINLIL_E_UNSUPPORTED);
    REQUIRE(bytes_are_zero(&output, sizeof(output)));

    (void)memcpy(corrupt_capacity, fixture.records[16].value,
        fixture.records[16].value_length);
    corrupt_capacity[20] ^= 1u;
    fixture.encoded.values[16].data = corrupt_capacity;
    (void)memset(&output, 0xa5, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &fixture.encoded, &output) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(bytes_are_zero(&output, sizeof(output)));

    REQUIRE(make_snapshot(&fixture));
    fixture.encoded.values[0].data = NULL;
    fixture.encoded.values[0].length = 0u;
    (void)memset(&output, 0xa5, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &fixture.encoded, &output) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(bytes_are_zero(&output, sizeof(output)));
    REQUIRE(make_snapshot(&fixture));
    fixture.encoded.values[0].length = 0u;
    (void)memset(&output, 0xa5, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &fixture.encoded, &output) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&output, sizeof(output)));
    return 0;
}

static int test_validation_proof_and_closed_boundaries(void)
{
    ninlil_runtime_config_t config = config_fixture();
    ninlil_model_runtime_validation_result_t validation =
        validation_fixture(&config);
    ninlil_model_runtime_store_bootstrap_plan_t plan;
    ninlil_model_runtime_store_bootstrap_record_t record;
    union alias_union {
        max_align_t alignment;
        ninlil_model_runtime_validation_result_t validation;
        ninlil_model_runtime_store_bootstrap_plan_t plan;
    } alias;
    union alias_union before;
    uint32_t index;

    for (index = 0u; index < 11u; ++index) {
        validation = validation_fixture(&config);
        validation.capacity_limits.values[index] ^= 1u;
        (void)memset(&plan, 0xa5, sizeof(plan));
        REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
            &validation, &plan) == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(bytes_are_zero(&plan, sizeof(plan)));
    }
    validation = validation_fixture(&config);
    validation.status = NINLIL_E_UNSUPPORTED;
    (void)memset(&plan, 0xa5, sizeof(plan));
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
        &validation, &plan) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&plan, sizeof(plan)));

    validation = validation_fixture(&config);
    (void)memset(&alias, 0, sizeof(alias));
    alias.validation = validation;
    before = alias;
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
        &alias.validation, &alias.plan) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&alias, &before, sizeof(alias)) == 0);
    before = alias;
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
        (const ninlil_model_runtime_validation_result_t *)&alias.plan,
        &alias.plan) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&alias, &before, sizeof(alias)) == 0);

    (void)memset(&plan, 0xa5, sizeof(plan));
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
        NULL, &plan) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&plan, sizeof(plan)));
    (void)memset(&record, 0xa5, sizeof(record));
    REQUIRE(ninlil_model_runtime_store_bootstrap_record_at(
        NULL, 0u, &record) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&record, sizeof(record)));

    validation = validation_fixture(&config);
    (void)memset(&validation.accepted_config.runtime_id, 0,
        sizeof(validation.accepted_config.runtime_id));
    (void)memset(&plan, 0xa5, sizeof(plan));
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
        &validation, &plan) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&plan, sizeof(plan)));
    config = config_fixture();
    validation = validation_fixture(&config);
    validation.accepted_config.membership_epoch = 0u;
    (void)memset(&plan, 0xa5, sizeof(plan));
    REQUIRE(ninlil_model_runtime_store_build_bootstrap_plan(
        &validation, &plan) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&plan, sizeof(plan)));
    return 0;
}

static int test_all_api_alias_invariance(void)
{
    snapshot_fixture_t fixture;
    union presence_alias {
        max_align_t alignment;
        ninlil_model_runtime_store_presence_input_t input;
        ninlil_model_runtime_store_presence_class_t output;
    } presence, presence_before;
    union snapshot_alias {
        max_align_t alignment;
        ninlil_model_runtime_store_validated_snapshot_t snapshot;
        uint8_t bytes[sizeof(ninlil_model_runtime_store_validated_snapshot_t)];
    } snapshot, snapshot_before;
    union record_alias {
        max_align_t alignment;
        ninlil_model_runtime_store_bootstrap_plan_t plan;
        ninlil_model_runtime_store_bootstrap_record_t record;
    } record, record_before;
    ninlil_model_runtime_store_encoded_snapshot_t encoded;
    ninlil_model_runtime_store_binding_t candidate_binding;
    ninlil_model_runtime_store_identity_t requested;

    REQUIRE(make_snapshot(&fixture));
    (void)memset(&presence, 0, sizeof(presence));
    presence.input.present_mask =
        NINLIL_MODEL_RUNTIME_STORE_PRESENT_ALL_MASK;
    presence_before = presence;
    REQUIRE(ninlil_model_runtime_store_classify_presence(
        &presence.input, &presence.output) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&presence, &presence_before, sizeof(presence)) == 0);

    encoded = fixture.encoded;
    (void)memset(&snapshot, 0x5a, sizeof(snapshot));
    (void)memcpy(snapshot.bytes, fixture.records[0].value,
        fixture.records[0].value_length);
    encoded.values[0].data = snapshot.bytes;
    snapshot_before = snapshot;
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &encoded, &snapshot.snapshot) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&snapshot, &snapshot_before, sizeof(snapshot)) == 0);

    snapshot.snapshot = fixture.validated;
    candidate_binding = fixture.plan.binding;
    snapshot_before = snapshot;
    REQUIRE(ninlil_model_runtime_store_compare_binding(
        &snapshot.snapshot, &candidate_binding,
        (ninlil_model_runtime_store_binding_comparison_t *)&snapshot.snapshot)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&snapshot, &snapshot_before, sizeof(snapshot)) == 0);
    requested = fixture.plan.identity;
    snapshot_before = snapshot;
    REQUIRE(ninlil_model_runtime_store_decide_identity(
        &snapshot.snapshot, &requested,
        (ninlil_model_runtime_store_identity_decision_t *)&snapshot.snapshot)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&snapshot, &snapshot_before, sizeof(snapshot)) == 0);

    (void)memset(&record, 0, sizeof(record));
    record.plan = fixture.plan;
    record_before = record;
    REQUIRE(ninlil_model_runtime_store_bootstrap_record_at(
        &record.plan, 0u, &record.record) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&record, &record_before, sizeof(record)) == 0);

    encoded = fixture.encoded;
    encoded.values[1] = encoded.values[0];
    (void)memset(&snapshot, 0xa5, sizeof(snapshot));
    snapshot_before = snapshot;
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &encoded, &snapshot.snapshot) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&snapshot, &snapshot_before, sizeof(snapshot)) == 0);

    encoded = fixture.encoded;
    encoded.values[0].data = (const uint8_t *)&encoded;
    snapshot_before = snapshot;
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &encoded, &snapshot.snapshot) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&snapshot, &snapshot_before, sizeof(snapshot)) == 0);

    encoded = fixture.encoded;
    encoded.values[0].data = NULL;
    encoded.values[0].length = 1u;
    encoded.values[16].data = snapshot.bytes;
    encoded.values[16].length = 1u;
    snapshot_before = snapshot;
    REQUIRE(ninlil_model_runtime_store_validate_snapshot(
        &encoded, &snapshot.snapshot) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&snapshot, &snapshot_before, sizeof(snapshot)) == 0);
    return 0;
}

int main(void)
{
    if (test_plan_and_canonical_projection() != 0
        || test_binding_all_field_mutations() != 0
        || test_endpoint_canonical_plan() != 0
        || test_presence_matrix() != 0
        || test_identity_decision_matrix() != 0
        || test_snapshot_aggregate_precedence() != 0
        || test_validation_proof_and_closed_boundaries() != 0
        || test_all_api_alias_invariance() != 0) {
        return 1;
    }
    return 0;
}
