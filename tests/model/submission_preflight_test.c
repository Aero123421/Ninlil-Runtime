#include "submission_preflight.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                    \
    do {                                                                      \
        if (!(condition)) {                                                   \
            (void)fprintf(                                                    \
                stderr, "%s:%d: requirement failed: %s\n",                 \
                __FILE__, __LINE__, #condition);                              \
            return 0;                                                         \
        }                                                                     \
    } while (0)

static void set_id(ninlil_id128_t *id, uint8_t value)
{
    (void)memset(id, 0, sizeof(*id));
    id->bytes[sizeof(id->bytes) - 1u] = value;
}

static void set_digest(ninlil_digest256_t *digest, uint8_t value)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = value;
}

static void set_text_id(ninlil_text_id_t *text_id, const char *value)
{
    size_t length = strlen(value);

    (void)memset(text_id, 0, sizeof(*text_id));
    text_id->length = (uint8_t)length;
    (void)memcpy(text_id->bytes, value, length);
}

static ninlil_admission_assurance_t make_assurance(ninlil_family_t family)
{
    ninlil_admission_assurance_t assurance;

    (void)memset(&assurance, 0, sizeof(assurance));
    assurance.abi_version = NINLIL_ABI_VERSION;
    assurance.struct_size = (uint16_t)sizeof(assurance);
    assurance.assurance_profile = NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL;
    assurance.submission_validated = 1u;
    assurance.target_roster_fixed = 1u;
    assurance.descriptor_snapshot_fixed = 1u;
    assurance.local_journal_committed = 1u;
    assurance.local_capacity_reserved = 1u;
    assurance.idempotency_mapping_committed = 1u;
    assurance.origin_grant_snapshot_committed =
        family == NINLIL_FAMILY_EVENT_FACT ? 1u : 0u;
    return assurance;
}

static ninlil_model_existing_admission_t make_existing(
    ninlil_family_t family,
    uint8_t transaction_value,
    uint8_t digest_value)
{
    ninlil_model_existing_admission_t existing;

    (void)memset(&existing, 0, sizeof(existing));
    set_id(&existing.transaction_id, transaction_value);
    set_digest(&existing.canonical_submission_digest, digest_value);
    existing.assurance = make_assurance(family);
    return existing;
}

static void initialize_ledger(ninlil_model_resource_ledger_t *ledger)
{
    ninlil_model_capacity_limits_t limits;
    size_t index;

    (void)memset(&limits, 0, sizeof(limits));
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        limits.values[index] = 100000u;
    }
    (void)ninlil_model_resource_ledger_init(&limits, ledger);
}

static ninlil_model_submission_preflight_input_t make_input(
    ninlil_family_t family)
{
    ninlil_model_submission_preflight_input_t input;

    (void)memset(&input, 0, sizeof(input));
    input.service.family = family;
    input.service.local_side = NINLIL_MODEL_LOCAL_SUBMISSION_SENDER;
    input.service.source.abi_version = NINLIL_ABI_VERSION;
    input.service.source.struct_size =
        (uint16_t)sizeof(input.service.source);
    set_id(&input.service.source.runtime_id, 1u);
    set_id(&input.service.source.application_instance_id, 2u);
    input.service.source.local_identity.abi_version = NINLIL_ABI_VERSION;
    input.service.source.local_identity.struct_size =
        (uint16_t)sizeof(input.service.source.local_identity);
    set_id(&input.service.source.local_identity.device_id, 12u);
    set_id(&input.service.source.local_identity.site_domain_id, 13u);
    input.service.source.local_identity.binding_epoch = 1u;
    input.service.source.local_identity.membership_epoch = 1u;
    input.service.source.local_identity.flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    input.service.identity.abi_version = NINLIL_ABI_VERSION;
    input.service.identity.struct_size =
        (uint16_t)sizeof(input.service.identity);
    set_text_id(&input.service.identity.namespace_id, "org.ninlil.examples");
    set_text_id(&input.service.identity.service_id, "service");
    set_text_id(&input.service.identity.schema_id, "schema");
    input.service.identity.descriptor_revision = 1u;
    set_digest(&input.service.identity.descriptor_digest, 11u);
    input.service.identity.family = family;
    input.service.identity.schema_major = 1u;
    input.service.schema_major = 1u;
    input.service.schema_minor_min = 0u;
    input.service.schema_minor_max = 0u;
    input.service.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    input.service.logical_payload_limit = 1024u;
    input.service.inflight_limit = 32u;
    input.service.admission_window_ms = 10000u;
    input.service.max_admissions_per_window =
        family == NINLIL_FAMILY_EVENT_FACT ? 8u : 20u;
    input.service.max_payload_bytes_per_window =
        family == NINLIL_FAMILY_EVENT_FACT ? 8192u : 20480u;
    input.service.max_evidence_per_target = 8u;
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        input.service.minimum_deadline_ms = 5000u;
        input.service.maximum_deadline_ms = 5000u;
        input.service.maximum_evidence_grace_ms = 1000u;
    } else {
        input.service.minimum_deadline_ms = NINLIL_NO_DEADLINE;
        input.service.maximum_deadline_ms = NINLIL_NO_DEADLINE;
    }

    input.submission.schema_major = 1u;
    input.submission.target_count = 1u;
    input.submission.target.abi_version = NINLIL_ABI_VERSION;
    input.submission.target.struct_size =
        (uint16_t)sizeof(input.submission.target);
    set_id(&input.submission.target.target_runtime_id, 14u);
    set_id(&input.submission.target.target_application_instance_id, 15u);
    set_id(&input.submission.target.device_id, 3u);
    set_id(&input.submission.target.site_domain_id, 16u);
    input.submission.target.binding_epoch = 1u;
    input.submission.target.membership_epoch = 1u;
    input.submission.target.flags =
        NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_SITE;
    input.submission.required_evidence =
        family == NINLIL_FAMILY_EVENT_FACT
            ? NINLIL_EVIDENCE_DURABLY_RECORDED
            : NINLIL_EVIDENCE_APPLIED;
    input.submission.payload_length = 10u;
    input.submission.content_digest_matches = 1u;
    input.submission.idempotency_key.length = 3u;
    input.submission.idempotency_key.bytes[0] = (uint8_t)'k';
    input.submission.idempotency_key.bytes[1] = (uint8_t)'e';
    input.submission.idempotency_key.bytes[2] = (uint8_t)'y';
    set_digest(&input.submission.content_digest, 10u);
    set_digest(&input.submission.canonical_submission_digest, 4u);
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        input.submission.effect_deadline_ms = 5000u;
        input.submission.evidence_grace_ms = 1000u;
        input.submission.generation = 1u;
    } else {
        input.submission.effect_deadline_ms = NINLIL_NO_DEADLINE;
        set_id(&input.submission.event_id, 5u);
    }

    input.caller_key_mapping.state = NINLIL_MODEL_MAPPING_ABSENT;
    input.event_id_mapping.state = NINLIL_MODEL_MAPPING_ABSENT;
    input.clock.state = NINLIL_MODEL_ADMISSION_CLOCK_TRUSTED;
    set_id(&input.clock.clock_epoch_id, 6u);
    input.clock.now_ms = 100u;
    input.authority.fact =
        family == NINLIL_FAMILY_EVENT_FACT
            ? NINLIL_MODEL_ORIGIN_AUTH_ALLOW
            : NINLIL_MODEL_ORIGIN_AUTH_NOT_APPLICABLE;
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        set_id(&input.authority.grant.provider_id, 7u);
        input.authority.grant.provider_revision = 1u;
        set_digest(&input.authority.grant.decision_digest, 8u);
        set_id(&input.authority.grant.grant_id, 9u);
        input.authority.grant.grant_revision = 1u;
        input.authority.grant.clock_epoch_id = input.clock.clock_epoch_id;
        input.authority.grant.evaluated_at_ms = input.clock.now_ms;
        input.authority.grant.expires_at_ms = 86400000u;
        input.authority.grant.max_payload_bytes = 1024u;
        input.authority.grant.max_active_spool_count = 32u;
        input.authority.grant.max_active_spool_bytes = 32768u;
        input.authority.grant.rate_window_ms = 10000u;
        input.authority.grant.max_admissions_per_window = 8u;
        input.authority.grant.max_attempts_per_retry_cycle =
            NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    }
    input.quota.window_is_current = 1u;
    initialize_ledger(&input.resource_ledger);
    return input;
}

static void set_valid_deny(
    ninlil_model_submission_preflight_input_t *input,
    ninlil_reason_t reason,
    ninlil_retry_guidance_t guidance,
    uint64_t delay)
{
    ninlil_id128_t provider_id = input->authority.grant.provider_id;
    uint64_t provider_revision = input->authority.grant.provider_revision;
    ninlil_digest256_t decision_digest =
        input->authority.grant.decision_digest;
    ninlil_id128_t clock_epoch_id = input->clock.clock_epoch_id;
    uint64_t evaluated_at_ms = input->clock.now_ms;

    input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_DENY;
    input->authority.deny_reason = reason;
    input->authority.deny_guidance = guidance;
    input->authority.deny_retry_delay_ms = delay;
    (void)memset(&input->authority.grant, 0, sizeof(input->authority.grant));
    input->authority.grant.provider_id = provider_id;
    input->authority.grant.provider_revision = provider_revision;
    input->authority.grant.decision_digest = decision_digest;
    input->authority.grant.clock_epoch_id = clock_epoch_id;
    input->authority.grant.evaluated_at_ms = evaluated_at_ms;
}

static int public_header_is_valid(const ninlil_submission_result_t *result)
{
    return result->abi_version == NINLIL_ABI_VERSION
        && result->struct_size == sizeof(*result);
}

static int expect_model_invalid(
    const ninlil_model_submission_preflight_input_t *input)
{
    ninlil_model_submission_preflight_result_t result;
    ninlil_model_submission_preflight_result_t zero;

    (void)memset(&result, 0xa5, sizeof(result));
    if (ninlil_model_submission_preflight(input, &result)
        != NINLIL_E_INVALID_ARGUMENT) {
        return 0;
    }
    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(&result, &zero, sizeof(result)) == 0;
}

static int is_rejection(
    const ninlil_model_submission_preflight_result_t *result,
    ninlil_reason_t reason,
    ninlil_retry_guidance_t guidance,
    uint64_t delay)
{
    ninlil_id128_t zero_id;
    ninlil_digest256_t zero_digest;

    (void)memset(&zero_id, 0, sizeof(zero_id));
    (void)memset(&zero_digest, 0, sizeof(zero_digest));
    return result->action == NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL
        && result->api_status == NINLIL_OK
        && public_header_is_valid(&result->public_result)
        && result->public_result.kind == NINLIL_SUBMISSION_REJECTED
        && result->public_result.reason == reason
        && result->public_result.retry_guidance == guidance
        && result->public_result.retry_delay_ms == delay
        && memcmp(
            &result->public_result.transaction_id,
            &zero_id,
            sizeof(zero_id)) == 0
        && memcmp(
            &result->public_result.canonical_submission_digest,
            &zero_digest,
            sizeof(zero_digest)) == 0
        && result->public_result.assurance.abi_version == NINLIL_ABI_VERSION
        && result->public_result.assurance.struct_size
            == sizeof(result->public_result.assurance)
        && result->public_result.assurance.assurance_profile
            == NINLIL_ASSURANCE_NONE;
}

/* M1A-ADM-001/033/037/038, AQ1/AQ10. */
static int test_desired_ready_plan(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_DESIRED_STATE);
    ninlil_model_submission_preflight_result_t result;

    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION);
    REQUIRE(result.api_status == NINLIL_OK);
    REQUIRE(result.public_result.abi_version == 0u);
    REQUIRE(result.admission.transaction_sequence == 1u);
    REQUIRE(result.admission.scheduler_owner_sequence == 1u);
    REQUIRE(result.admission.admitted_at_ms == 100u);
    REQUIRE(result.admission.absolute_effect_deadline_ms == 5100u);
    REQUIRE(result.admission.absolute_evidence_close_ms == 6100u);
    REQUIRE(result.admission.quota.next_inflight_count == 1u);
    REQUIRE(result.admission.quota.next_admissions_in_window == 1u);
    REQUIRE(result.admission.quota.next_payload_bytes_in_window == 10u);
    REQUIRE(result.admission.resources.reserve_request_count == 4u);
    REQUIRE(result.admission.resources.reserve_requests[0].kind
        == NINLIL_RESOURCE_TRANSACTION);
    REQUIRE(result.admission.resources.reserve_requests[1].kind
        == NINLIL_RESOURCE_TARGET);
    REQUIRE(result.admission.resources.reserve_requests[2].kind
        == NINLIL_RESOURCE_OUTBOX_BYTES);
    REQUIRE(result.admission.resources.reserve_requests[2].amount == 10u);
    REQUIRE(result.admission.resources.reserve_requests[3].kind
        == NINLIL_RESOURCE_EVIDENCE);
    REQUIRE(result.admission.resources.reserve_requests[3].amount == 9u);
    REQUIRE(result.admission.resources.committed_ledger.entries[8].used == 1u);
    REQUIRE(result.admission.resources.committed_ledger.entries[8].reserved == 8u);
    REQUIRE(result.admission.idempotency_key.length == 3u);
    REQUIRE(result.admission.idempotency_key.bytes[2] == (uint8_t)'y');
    REQUIRE(result.admission.content_digest.bytes[31] == 10u);
    REQUIRE(result.admission.registered_service.identity.descriptor_revision
        == 1u);
    return 1;
}

/* M1A-ADM-009/013, AQ6. */
static int test_event_ready_plan(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_EVENT_FACT);
    ninlil_model_submission_preflight_result_t result;

    input.last_transaction_sequence = 9u;
    input.last_scheduler_owner_sequence = 11u;
    input.authority.grant.max_payload_bytes = 2048u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION);
    REQUIRE(result.admission.transaction_sequence == 10u);
    REQUIRE(result.admission.scheduler_owner_sequence == 12u);
    REQUIRE(result.admission.absolute_effect_deadline_ms == NINLIL_NO_DEADLINE);
    REQUIRE(result.admission.absolute_evidence_close_ms == NINLIL_NO_DEADLINE);
    REQUIRE(result.admission.deadline_clock_epoch_id.bytes[15] == 0u);
    REQUIRE(result.admission.resources.reserve_request_count == 5u);
    REQUIRE(result.admission.resources.reserve_requests[2].kind
        == NINLIL_RESOURCE_EVENT_SPOOL_COUNT);
    REQUIRE(result.admission.resources.reserve_requests[3].kind
        == NINLIL_RESOURCE_EVENT_SPOOL_BYTES);
    REQUIRE(result.admission.resources.reserve_requests[3].amount == 2570u);
    REQUIRE(result.admission.resources.commit_requests[3].amount == 10u);
    REQUIRE(result.admission.resources.committed_ledger.entries[6].used == 10u);
    REQUIRE(result.admission.resources.committed_ledger.entries[6].reserved
        == NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES);
    REQUIRE(result.admission.quota.next_event_active_spool_count == 1u);
    REQUIRE(result.admission.quota.next_event_active_spool_bytes == 2570u);
    REQUIRE(result.admission.grant.grant_id.bytes[15] == 9u);
    return 1;
}

/* M1A-ADM-002/010/020/035, RF4/RF10. */
static int test_validation_and_direction_precedence(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_DESIRED_STATE);
    ninlil_model_submission_preflight_result_t result;

    input.service.local_side = NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER;
    input.caller_key_mapping.state = (ninlil_model_mapping_state_t)99;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(is_rejection(
        &result,
        NINLIL_REASON_UNSUPPORTED_DIRECTION,
        NINLIL_RETRY_MODIFIED,
        0u));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.target_count = 2u;
    input.submission.target.abi_version = 0u;
    (void)memset(
        &input.submission.canonical_submission_digest,
        0,
        sizeof(input.submission.canonical_submission_digest));
    input.caller_key_mapping.state = (ninlil_model_mapping_state_t)99;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(is_rejection(
        &result,
        NINLIL_REASON_TARGET_COUNT_UNSUPPORTED,
        NINLIL_RETRY_MODIFIED,
        0u));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.schema_major = 2u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_INVALID_SCHEMA);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.payload_length = 1025u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason
        == NINLIL_REASON_INVALID_PAYLOAD_LENGTH);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.content_digest_matches = 0u;
    input.submission.target.abi_version = 0u;
    (void)memset(
        &input.submission.canonical_submission_digest,
        0,
        sizeof(input.submission.canonical_submission_digest));
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL);
    REQUIRE(result.api_status == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(result.public_result.assurance.abi_version == 0u);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.submission.effect_deadline_ms = 5u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason
        == NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.required_evidence = NINLIL_EVIDENCE_VERIFIED;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_EVIDENCE_UNSUPPORTED);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.idempotency_key.length = 0u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    return 1;
}

/* M1A-ADM-003/004/019/021/025/026/028/030, ADR-0002. */
static int test_idempotency_and_early_exit(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_DESIRED_STATE);
    ninlil_model_submission_preflight_result_t result;
    ninlil_model_existing_admission_t existing =
        make_existing(NINLIL_FAMILY_DESIRED_STATE, 10u, 4u);

    input.caller_key_mapping.state = NINLIL_MODEL_MAPPING_MATCH;
    input.caller_key_mapping.record_verified = 1u;
    input.caller_key_mapping.existing = existing;
    input.clock.state = (ninlil_model_admission_clock_state_t)99;
    input.last_transaction_sequence = UINT64_MAX;
    input.authority.fact = (ninlil_model_origin_authority_fact_t)99;
    (void)memset(&input.resource_ledger, 0xa5, sizeof(input.resource_ledger));
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);
    REQUIRE(result.public_result.transaction_id.bytes[15] == 10u);
    REQUIRE(result.public_result.assurance.assurance_profile
        == NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.caller_key_mapping.state = NINLIL_MODEL_MAPPING_MISMATCH;
    input.caller_key_mapping.record_verified = 1u;
    input.caller_key_mapping.existing =
        make_existing(NINLIL_FAMILY_DESIRED_STATE, 11u, 12u);
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.kind
        == NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT);
    REQUIRE(result.public_result.transaction_id.bytes[15] == 11u);
    REQUIRE(result.public_result.canonical_submission_digest.bytes[31] == 12u);
    REQUIRE(result.public_result.assurance.assurance_profile
        == NINLIL_ASSURANCE_NONE);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.caller_key_mapping.state = NINLIL_MODEL_MAPPING_MATCH;
    input.caller_key_mapping.record_verified = 1u;
    input.caller_key_mapping.existing =
        make_existing(NINLIL_FAMILY_EVENT_FACT, 20u, 4u);
    input.event_id_mapping.state = NINLIL_MODEL_MAPPING_MATCH;
    input.event_id_mapping.record_verified = 1u;
    input.event_id_mapping.existing = input.caller_key_mapping.existing;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_ALREADY_ADMITTED);

    input.event_id_mapping.existing =
        make_existing(NINLIL_FAMILY_EVENT_FACT, 21u, 4u);
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.kind
        == NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT);
    REQUIRE(result.public_result.transaction_id.bytes[15] == 20u);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.event_id_mapping.state = NINLIL_MODEL_MAPPING_MISMATCH;
    input.event_id_mapping.record_verified = 1u;
    input.event_id_mapping.existing =
        make_existing(NINLIL_FAMILY_EVENT_FACT, 22u, 23u);
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.transaction_id.bytes[15] == 22u);
    return 1;
}

static int test_mapping_storage_failure(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_DESIRED_STATE);
    ninlil_model_submission_preflight_result_t result;

    input.caller_key_mapping.state = NINLIL_MODEL_MAPPING_STORAGE_FAILURE;
    input.caller_key_mapping.failure_status = NINLIL_E_STORAGE_CORRUPT;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(result.public_result.reason == NINLIL_REASON_NONE);
    REQUIRE(result.public_result.assurance.abi_version == 0u);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.event_id_mapping.state = NINLIL_MODEL_MAPPING_STORAGE_FAILURE;
    input.event_id_mapping.failure_status = NINLIL_E_STORAGE;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_STORAGE);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);
    return 1;
}

/* M1A-ADM-031/038, AQ8/AQ10. */
static int test_counter_precedence(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_EVENT_FACT);
    ninlil_model_submission_preflight_result_t result;

    input.last_transaction_sequence = UINT64_MAX;
    input.last_scheduler_owner_sequence = UINT64_MAX;
    input.authority.fact = (ninlil_model_origin_authority_fact_t)99;
    (void)memset(&input.resource_ledger, 0xa5, sizeof(input.resource_ledger));
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(is_rejection(
        &result,
        NINLIL_REASON_COUNTER_EXHAUSTED,
        NINLIL_RETRY_OPERATOR_ACTION,
        0u));

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.last_scheduler_owner_sequence = UINT64_MAX;
    input.authority.fact = (ninlil_model_origin_authority_fact_t)99;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_COUNTER_EXHAUSTED);
    return 1;
}

/* M1A-ADM-014..018, AQ5/AQ8. */
static int test_authority_results(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_EVENT_FACT);
    ninlil_model_submission_preflight_result_t result;

    set_valid_deny(
        &input,
        NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_OPERATOR_ACTION,
        0u);
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(is_rejection(
        &result,
        NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_OPERATOR_ACTION,
        0u));

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.authority.fact = NINLIL_MODEL_ORIGIN_AUTH_TEMPORARY_FAILURE;
    (void)memset(&input.authority.grant, 0, sizeof(input.authority.grant));
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_WOULD_BLOCK);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);

    input.authority.fact =
        NINLIL_MODEL_ORIGIN_AUTH_PERMANENT_OR_INVALID;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.authority.grant.grant_id.bytes[15] = 0u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    set_valid_deny(
        &input,
        NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_SAME_AFTER,
        0u);
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    set_valid_deny(
        &input,
        NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_OPERATOR_ACTION,
        0u);
    (void)memset(
        &input.authority.grant.provider_id,
        0,
        sizeof(input.authority.grant.provider_id));
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    set_valid_deny(
        &input,
        NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_OPERATOR_ACTION,
        0u);
    input.authority.grant.evaluated_at_ms += 1u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    set_valid_deny(
        &input,
        NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_OPERATOR_ACTION,
        0u);
    input.authority.grant.max_payload_bytes = 1u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);
    return 1;
}

static int test_clock_results(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_DESIRED_STATE);
    ninlil_model_submission_preflight_result_t result;
    ninlil_model_submission_preflight_result_t zero;

    input.clock.state =
        NINLIL_MODEL_ADMISSION_CLOCK_TEMPORARY_OR_UNCERTAIN;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_CLOCK_UNCERTAIN);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);

    input.clock.state =
        NINLIL_MODEL_ADMISSION_CLOCK_PERMANENT_OR_INVALID;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    (void)memset(&input.clock.clock_epoch_id, 0, sizeof(input.clock.clock_epoch_id));
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.clock.state = (ninlil_model_admission_clock_state_t)99;
    (void)memset(&result, 0xa5, sizeof(result));
    REQUIRE(ninlil_model_submission_preflight(&input, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&zero, 0, sizeof(zero));
    REQUIRE(memcmp(&result, &zero, sizeof(result)) == 0);
    return 1;
}

/* AQ2/AQ3/AQ4/AQ8: first exhausted guard wins with exact delay. */
static int test_quota_and_grant_precedence(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_EVENT_FACT);
    ninlil_model_submission_preflight_result_t result;

    input.clock.now_ms = 9999u;
    input.authority.grant.evaluated_at_ms = input.clock.now_ms;
    input.quota.inflight_count = 32u;
    input.quota.admissions_in_window = 8u;
    input.submission.payload_length = 1025u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_INVALID_PAYLOAD_LENGTH);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.clock.now_ms = 9999u;
    input.authority.grant.evaluated_at_ms = input.clock.now_ms;
    input.quota.inflight_count = 32u;
    input.quota.admissions_in_window = 8u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_CAPACITY_EXHAUSTED);

    input.quota.inflight_count = 0u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_RATE_EXHAUSTED);
    REQUIRE(result.public_result.retry_delay_ms == 1u);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.event_grant_usage.active_spool_count = 32u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_GRANT_LIMIT_EXCEEDED);
    REQUIRE(result.public_result.retry_delay_ms == 0u);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.service.max_admissions_per_window = 20u;
    input.quota.admissions_in_window = 8u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.public_result.reason == NINLIL_REASON_RATE_EXHAUSTED);
    REQUIRE(result.public_result.retry_delay_ms == 9900u);

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.service.max_admissions_per_window = 20u;
    input.authority.grant.max_admissions_per_window = 1u;
    input.quota.window_is_current = 0u;
    input.quota.admissions_in_window = 999u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION);
    REQUIRE(result.admission.quota.next_admissions_in_window == 1u);
    return 1;
}

/* M1A-ADM-005: block metadata must commit before public rejection. */
static int test_capacity_block_handshake(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_DESIRED_STATE);
    ninlil_model_submission_preflight_result_t result;

    input.resource_ledger.entries[1].limit = 0u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_CAPACITY_BLOCK_COMMIT_REQUIRED);
    REQUIRE(result.public_result.abi_version == 0u);
    REQUIRE(result.capacity_block.failing_kind == NINLIL_RESOURCE_TRANSACTION);
    REQUIRE(result.capacity_block.next_ledger.entries[1].blocked == 1u);

    input.resource_ledger = result.capacity_block.next_ledger;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(is_rejection(
        &result,
        NINLIL_REASON_CAPACITY_EXHAUSTED,
        NINLIL_RETRY_SAME_AFTER,
        0u));
    return 1;
}

static int test_invalid_and_deterministic(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_DESIRED_STATE);
    ninlil_model_submission_preflight_result_t first;
    ninlil_model_submission_preflight_result_t second;
    ninlil_model_submission_preflight_result_t zero;

    REQUIRE(ninlil_model_submission_preflight(&input, &first) == NINLIL_OK);
    REQUIRE(ninlil_model_submission_preflight(&input, &second) == NINLIL_OK);
    REQUIRE(memcmp(&first, &second, sizeof(first)) == 0);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.schema_major = 2u;
    (void)memset(&first, 0xa5, sizeof(first));
    REQUIRE(ninlil_model_submission_preflight(&input, &first)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&zero, 0, sizeof(zero));
    REQUIRE(memcmp(&first, &zero, sizeof(first)) == 0);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.family = (ninlil_family_t)99u;
    (void)memset(&first, 0xa5, sizeof(first));
    REQUIRE(ninlil_model_submission_preflight(&input, &first)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&zero, 0, sizeof(zero));
    REQUIRE(memcmp(&first, &zero, sizeof(first)) == 0);

    REQUIRE(ninlil_model_submission_preflight(NULL, &first)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&first, &zero, sizeof(first)) == 0);
    REQUIRE(ninlil_model_submission_preflight(&input, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    return 1;
}

static int test_target_identity_validation(void)
{
    ninlil_model_submission_preflight_input_t input;

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    (void)memset(
        &input.submission.target.target_runtime_id,
        0,
        sizeof(input.submission.target.target_runtime_id));
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    (void)memset(
        &input.submission.target.target_application_instance_id,
        0,
        sizeof(input.submission.target.target_application_instance_id));
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.target.flags |= (uint32_t)1u << 8;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.target.flags &= ~NINLIL_TARGET_HAS_DEVICE;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    (void)memset(
        &input.submission.target.site_domain_id,
        0,
        sizeof(input.submission.target.site_domain_id));
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.target.binding_epoch = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.target.membership_epoch = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    set_id(&input.submission.target.installation_id, 17u);
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.target.reserved_zero = 1u;
    REQUIRE(expect_model_invalid(&input));
    return 1;
}

static int test_source_and_text_identity_validation(void)
{
    ninlil_model_submission_preflight_input_t input;
    ninlil_model_submission_preflight_result_t result;

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    (void)memset(
        &input.service.source.local_identity,
        0,
        sizeof(input.service.source.local_identity));
    input.service.source.local_identity.abi_version = NINLIL_ABI_VERSION;
    input.service.source.local_identity.struct_size =
        (uint16_t)sizeof(input.service.source.local_identity);
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.source.local_identity.abi_version = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.source.local_identity.flags &=
        ~NINLIL_LOCAL_IDENTITY_HAS_DEVICE;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.source.local_identity.binding_epoch = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.source.local_identity.membership_epoch = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.source.local_identity.reserved_zero = 1u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.namespace_id.length = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.namespace_id.bytes[0] = (uint8_t)'O';
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.namespace_id.bytes[3] = (uint8_t)'_';
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.namespace_id.bytes[
        input.service.identity.namespace_id.length] = (uint8_t)'x';
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.service_id.bytes[0] = (uint8_t)'_';
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.service_id.bytes[1] = (uint8_t)'/';
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.identity.schema_id.bytes[1] = (uint8_t)'A';
    REQUIRE(expect_model_invalid(&input));
    return 1;
}

static int test_digest_typed_presence(void)
{
    ninlil_model_submission_preflight_input_t input =
        make_input(NINLIL_FAMILY_EVENT_FACT);
    ninlil_model_submission_preflight_result_t result;

    (void)memset(
        input.service.identity.descriptor_digest.bytes,
        0,
        sizeof(input.service.identity.descriptor_digest.bytes));
    (void)memset(
        input.submission.content_digest.bytes,
        0,
        sizeof(input.submission.content_digest.bytes));
    (void)memset(
        input.submission.canonical_submission_digest.bytes,
        0,
        sizeof(input.submission.canonical_submission_digest.bytes));
    (void)memset(
        input.authority.grant.decision_digest.bytes,
        0,
        sizeof(input.authority.grant.decision_digest.bytes));
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION);

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.content_digest.algorithm = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.submission.canonical_submission_digest.reserved_zero = 1u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_EVENT_FACT);
    input.authority.grant.decision_digest.algorithm = 0u;
    REQUIRE(ninlil_model_submission_preflight(&input, &result) == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_DEGRADED);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);
    return 1;
}

static int test_service_evidence_mask_shape(void)
{
    ninlil_model_submission_preflight_input_t input;

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.supported_evidence_mask = 0u;
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.supported_evidence_mask |=
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_NONE);
    REQUIRE(expect_model_invalid(&input));

    input = make_input(NINLIL_FAMILY_DESIRED_STATE);
    input.service.supported_evidence_mask |= (uint32_t)1u << 31;
    REQUIRE(expect_model_invalid(&input));
    return 1;
}

int main(void)
{
    int passed = 1;

    passed &= test_desired_ready_plan();
    passed &= test_event_ready_plan();
    passed &= test_validation_and_direction_precedence();
    passed &= test_idempotency_and_early_exit();
    passed &= test_mapping_storage_failure();
    passed &= test_counter_precedence();
    passed &= test_authority_results();
    passed &= test_clock_results();
    passed &= test_quota_and_grant_precedence();
    passed &= test_capacity_block_handshake();
    passed &= test_invalid_and_deterministic();
    passed &= test_target_identity_validation();
    passed &= test_source_and_text_identity_validation();
    passed &= test_digest_typed_presence();
    passed &= test_service_evidence_mask_shape();
    return passed != 0 ? 0 : 1;
}
