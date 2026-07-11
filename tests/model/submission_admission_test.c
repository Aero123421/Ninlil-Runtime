#include "submission_admission.h"

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

static void set_text(ninlil_text_id_t *text, const char *value)
{
    size_t length = strlen(value);

    (void)memset(text, 0, sizeof(*text));
    text->length = (uint8_t)length;
    (void)memcpy(text->bytes, value, length);
}

static void add_request(
    ninlil_model_capacity_batch_request_t *requests,
    uint32_t *count,
    ninlil_resource_kind_t kind,
    uint64_t amount)
{
    if (amount == 0u) {
        return;
    }
    requests[*count].kind = kind;
    requests[*count].amount = amount;
    *count += 1u;
}

static void make_resource_plan(
    ninlil_model_admission_plan_t *plan,
    ninlil_family_t family,
    uint32_t payload_length,
    uint32_t max_evidence)
{
    ninlil_model_capacity_limits_t limits;
    ninlil_model_capacity_batch_input_t input;
    ninlil_model_capacity_batch_result_t result;
    uint32_t index;

    (void)memset(&limits, 0, sizeof(limits));
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        limits.values[index] = 10000u;
    }
    (void)ninlil_model_resource_ledger_init(
        &limits, &plan->resources.reserved_ledger);

    add_request(
        plan->resources.reserve_requests,
        &plan->resources.reserve_request_count,
        NINLIL_RESOURCE_TRANSACTION,
        1u);
    add_request(
        plan->resources.reserve_requests,
        &plan->resources.reserve_request_count,
        NINLIL_RESOURCE_TARGET,
        1u);
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        add_request(
            plan->resources.reserve_requests,
            &plan->resources.reserve_request_count,
            NINLIL_RESOURCE_OUTBOX_BYTES,
            payload_length);
    } else {
        add_request(
            plan->resources.reserve_requests,
            &plan->resources.reserve_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
            1u);
        add_request(
            plan->resources.reserve_requests,
            &plan->resources.reserve_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
            (uint64_t)payload_length
                + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES);
    }
    add_request(
        plan->resources.reserve_requests,
        &plan->resources.reserve_request_count,
        NINLIL_RESOURCE_EVIDENCE,
        (uint64_t)max_evidence + 1u);

    add_request(
        plan->resources.commit_requests,
        &plan->resources.commit_request_count,
        NINLIL_RESOURCE_TRANSACTION,
        1u);
    add_request(
        plan->resources.commit_requests,
        &plan->resources.commit_request_count,
        NINLIL_RESOURCE_TARGET,
        1u);
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        add_request(
            plan->resources.commit_requests,
            &plan->resources.commit_request_count,
            NINLIL_RESOURCE_OUTBOX_BYTES,
            payload_length);
    } else {
        add_request(
            plan->resources.commit_requests,
            &plan->resources.commit_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
            1u);
        add_request(
            plan->resources.commit_requests,
            &plan->resources.commit_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
            payload_length);
    }
    add_request(
        plan->resources.commit_requests,
        &plan->resources.commit_request_count,
        NINLIL_RESOURCE_EVIDENCE,
        1u);

    (void)memset(&input, 0, sizeof(input));
    input.current = plan->resources.reserved_ledger;
    input.operation = NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK;
    input.request_count = plan->resources.reserve_request_count;
    for (index = 0u; index < input.request_count; ++index) {
        input.requests[index] = plan->resources.reserve_requests[index];
    }
    (void)ninlil_model_capacity_batch_transition(&input, &result);
    plan->resources.reserved_ledger = result.next;

    (void)memset(&input, 0, sizeof(input));
    input.current = plan->resources.reserved_ledger;
    input.operation = NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED;
    input.request_count = plan->resources.commit_request_count;
    for (index = 0u; index < input.request_count; ++index) {
        input.requests[index] = plan->resources.commit_requests[index];
    }
    (void)ninlil_model_capacity_batch_transition(&input, &result);
    plan->resources.committed_ledger = result.next;
}

static ninlil_model_admission_plan_t make_plan(
    ninlil_family_t family,
    uint32_t payload_length)
{
    ninlil_model_admission_plan_t plan;

    (void)memset(&plan, 0, sizeof(plan));
    plan.family = family;
    plan.registered_service.family = family;
    plan.registered_service.local_side =
        NINLIL_MODEL_LOCAL_SUBMISSION_SENDER;
    plan.registered_service.source.abi_version = NINLIL_ABI_VERSION;
    plan.registered_service.source.struct_size =
        (uint16_t)sizeof(plan.registered_service.source);
    set_id(&plan.registered_service.source.runtime_id, 1u);
    set_id(&plan.registered_service.source.application_instance_id, 2u);
    plan.registered_service.source.local_identity.abi_version =
        NINLIL_ABI_VERSION;
    plan.registered_service.source.local_identity.struct_size =
        (uint16_t)sizeof(plan.registered_service.source.local_identity);
    plan.registered_service.identity.abi_version = NINLIL_ABI_VERSION;
    plan.registered_service.identity.struct_size =
        (uint16_t)sizeof(plan.registered_service.identity);
    set_text(&plan.registered_service.identity.namespace_id, "org.ninlil");
    set_text(&plan.registered_service.identity.service_id, "service");
    set_text(&plan.registered_service.identity.schema_id, "schema");
    plan.registered_service.identity.descriptor_revision = 1u;
    set_digest(&plan.registered_service.identity.descriptor_digest, 3u);
    plan.registered_service.identity.schema_major = 1u;
    plan.registered_service.identity.family = family;
    plan.registered_service.schema_major = 1u;
    plan.registered_service.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    plan.registered_service.logical_payload_limit = 1024u;
    plan.registered_service.inflight_limit = 32u;
    plan.registered_service.admission_window_ms = 10000u;
    plan.registered_service.max_admissions_per_window = 20u;
    plan.registered_service.max_payload_bytes_per_window = 20480u;
    plan.registered_service.max_evidence_per_target = 8u;
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        plan.registered_service.minimum_deadline_ms = 5000u;
        plan.registered_service.maximum_deadline_ms = 5000u;
        plan.registered_service.maximum_evidence_grace_ms = 1000u;
    } else {
        plan.registered_service.minimum_deadline_ms = NINLIL_NO_DEADLINE;
        plan.registered_service.maximum_deadline_ms = NINLIL_NO_DEADLINE;
    }
    plan.source = plan.registered_service.source;
    plan.service = plan.registered_service.identity;
    plan.target.abi_version = NINLIL_ABI_VERSION;
    plan.target.struct_size = (uint16_t)sizeof(plan.target);
    set_id(&plan.target.target_runtime_id, 4u);
    set_id(&plan.target.target_application_instance_id, 5u);
    plan.idempotency_key.length = 3u;
    plan.idempotency_key.bytes[0] = (uint8_t)'k';
    plan.idempotency_key.bytes[1] = (uint8_t)'e';
    plan.idempotency_key.bytes[2] = (uint8_t)'y';
    set_digest(&plan.content_digest, 6u);
    set_digest(&plan.canonical_submission_digest, 7u);
    plan.required_evidence = family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_EVIDENCE_DURABLY_RECORDED
        : NINLIL_EVIDENCE_APPLIED;
    plan.payload_length = payload_length;
    plan.transaction_sequence = 1u;
    plan.scheduler_owner_sequence = 1u;
    set_id(&plan.admission_clock_epoch_id, 8u);
    plan.admitted_at_ms = 100u;
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        plan.generation = 1u;
        plan.deadline_clock_epoch_id = plan.admission_clock_epoch_id;
        plan.absolute_effect_deadline_ms = 5100u;
        plan.absolute_evidence_close_ms = 6100u;
    } else {
        set_id(&plan.event_id, 9u);
        plan.absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
        plan.absolute_evidence_close_ms = NINLIL_NO_DEADLINE;
        set_id(&plan.grant.provider_id, 10u);
        plan.grant.provider_revision = 1u;
        set_digest(&plan.grant.decision_digest, 11u);
        set_id(&plan.grant.grant_id, 12u);
        plan.grant.grant_revision = 1u;
        plan.grant.clock_epoch_id = plan.admission_clock_epoch_id;
        plan.grant.evaluated_at_ms = 100u;
        plan.grant.expires_at_ms = 10000u;
        plan.grant.max_payload_bytes = 1024u;
        plan.grant.max_active_spool_count = 32u;
        plan.grant.max_active_spool_bytes = 32768u;
        plan.grant.rate_window_ms = 10000u;
        plan.grant.max_admissions_per_window = 20u;
        plan.grant.max_attempts_per_retry_cycle =
            NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    }
    plan.quota.clock_epoch_id = plan.admission_clock_epoch_id;
    plan.quota.next_inflight_count = 1u;
    plan.quota.next_admissions_in_window = 1u;
    plan.quota.next_payload_bytes_in_window = payload_length;
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        plan.quota.next_event_active_spool_count = 1u;
        plan.quota.next_event_active_spool_bytes =
            (uint64_t)payload_length
            + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES;
    }
    make_resource_plan(
        &plan, family, payload_length,
        plan.registered_service.max_evidence_per_target);
    return plan;
}

static ninlil_model_descriptor_contract_extension_t make_descriptor(
    ninlil_family_t family)
{
    ninlil_model_descriptor_contract_extension_t descriptor;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    descriptor.direction = family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_DIRECTION_UPLINK : NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_AUTHORITY_ORIGIN_WITH_GRANT
        : NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_APPLY_APPLICATION_DEDUP : NINLIL_APPLY_IDEMPOTENT;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.target_limit = 1u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 1000u;
    descriptor.required_dedup_window_ms = 86400000u;
    return descriptor;
}

static ninlil_model_id_allocation_input_t make_allocation_input(
    ninlil_family_t family,
    uint32_t payload_length)
{
    ninlil_model_id_allocation_input_t input;
    uint32_t index;

    (void)memset(&input, 0, sizeof(input));
    input.preflight_plan = make_plan(family, payload_length);
    input.payload.length = payload_length;
    input.payload.content_verified = 1u;
    input.payload.verified_content_digest = input.preflight_plan.content_digest;
    for (index = 0u; index < payload_length; ++index) {
        input.payload.bytes[index] = (uint8_t)(index + 1u);
    }
    input.descriptor_contract = make_descriptor(family);
    return input;
}

static void set_draw(
    ninlil_model_transaction_id_draw_t *draw,
    uint32_t ordinal,
    ninlil_model_entropy_draw_state_t entropy,
    uint8_t candidate,
    ninlil_model_transaction_collision_state_t collision)
{
    (void)memset(draw, 0, sizeof(*draw));
    draw->ordinal = ordinal;
    draw->entropy_state = entropy;
    if (candidate != 0u) {
        set_id(&draw->candidate, candidate);
    }
    draw->collision_state = collision;
}

static int expect_allocation_invalid(
    const ninlil_model_id_allocation_input_t *input)
{
    ninlil_model_id_allocation_result_t result;
    ninlil_model_id_allocation_result_t zero;

    (void)memset(&result, 0xa5, sizeof(result));
    if (ninlil_model_reduce_transaction_id_allocation(input, &result)
        != NINLIL_E_INVALID_ARGUMENT) {
        return 0;
    }
    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(&result, &zero, sizeof(result)) == 0;
}

/* TXID1_FOURTH_VALID and immutable FULL write-set construction. */
static int test_fourth_valid_command(void)
{
    ninlil_model_id_allocation_input_t input =
        make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    ninlil_model_id_allocation_result_t result;

    REQUIRE(ninlil_model_reduce_transaction_id_allocation(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_ID_ALLOCATION_NEEDS_DRAW);
    REQUIRE(result.next_draw_ordinal == 1u);

    input.draw_count = 4u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 0u,
        NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED);
    set_draw(
        &input.draws[1], 2u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 20u,
        NINLIL_MODEL_TRANSACTION_ID_COLLISION);
    set_draw(
        &input.draws[2], 3u, NINLIL_MODEL_ENTROPY_DRAW_PARTIAL, 21u,
        NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED);
    set_draw(
        &input.draws[3], 4u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 22u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    REQUIRE(ninlil_model_reduce_transaction_id_allocation(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT);
    REQUIRE(result.draws_consumed == 4u);
    REQUIRE(result.health_clear_entropy_transaction_id == 1u);
    REQUIRE(result.public_result.abi_version == 0u);
    REQUIRE(result.write_set.durability == NINLIL_DURABILITY_FULL);
    REQUIRE(result.write_set.transaction_id.bytes[15] == 22u);
    REQUIRE(result.write_set.initial_queue_kind
        == NINLIL_MODEL_INITIAL_COMMAND_OUTBOX);
    REQUIRE(result.write_set.initial_family_snapshot.family_state
        == NINLIL_MODEL_INITIAL_DESIRED_TARGET_READY);
    REQUIRE(result.write_set.reservation_manifest.evidence_summary_used == 1u);
    REQUIRE(result.write_set.reservation_manifest.evidence_raw_reserved == 8u);
    REQUIRE(result.write_set.reservation_manifest.command_cancel_slots == 1u);
    REQUIRE(result.write_set.descriptor.contract.target_limit == 1u);
    REQUIRE(result.write_set.payload.bytes[2] == 3u);
    REQUIRE(result.write_set.caller_mapping.scope
        .source_application_instance_id.bytes[15] == 2u);
    REQUIRE(result.write_set.caller_mapping.scope.namespace_id.length
        == input.preflight_plan.service.namespace_id.length);
    return 1;
}

/* Event mapping, bound grant, HELD_READY/cycle 1 and management reservation. */
static int test_event_write_set(void)
{
    ninlil_model_id_allocation_input_t input =
        make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    ninlil_model_id_allocation_result_t result;

    input.draw_count = 1u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 30u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    REQUIRE(ninlil_model_reduce_transaction_id_allocation(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action
        == NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT);
    REQUIRE(result.write_set.event_mapping_present == 1u);
    REQUIRE(result.write_set.grant_snapshot_present == 1u);
    REQUIRE(result.write_set.initial_family_snapshot.family_state
        == NINLIL_MODEL_INITIAL_EVENT_HELD_READY);
    REQUIRE(result.write_set.initial_family_snapshot.retry_cycle_id == 1u);
    REQUIRE(result.write_set.initial_family_snapshot.attempts_in_cycle == 0u);
    REQUIRE(result.write_set.initial_family_snapshot.spool_revision == 1u);
    REQUIRE(result.write_set.reservation_manifest.event_resume_slots == 8u);
    REQUIRE(result.write_set.reservation_manifest.event_resume_slot_bytes == 256u);
    REQUIRE(result.write_set.reservation_manifest.event_discard_slots == 1u);
    REQUIRE(result.write_set.reservation_manifest.event_discard_slot_bytes == 512u);
    REQUIRE(result.write_set.reservation_manifest.event_management_total_bytes
        == 2560u);
    REQUIRE(result.write_set.event_mapping.scope.service_id.length
        == input.preflight_plan.service.service_id.length);
    REQUIRE(result.write_set.grant_snapshot.source.application_instance_id
        .bytes[15] == 2u);
    REQUIRE(result.write_set.grant_snapshot.target.target_runtime_id.bytes[15]
        == 4u);
    return 1;
}

/* TXID2_FOUR_INVALID. */
static int test_four_invalid_entropy(void)
{
    ninlil_model_id_allocation_input_t input =
        make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    ninlil_model_id_allocation_result_t result;

    input.draw_count = 4u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_TEMPORARY_FAILURE,
        0u, NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED);
    set_draw(
        &input.draws[1], 2u, NINLIL_MODEL_ENTROPY_DRAW_PARTIAL, 1u,
        NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED);
    set_draw(
        &input.draws[2], 3u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 0u,
        NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED);
    set_draw(
        &input.draws[3], 4u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 2u,
        NINLIL_MODEL_TRANSACTION_ID_COLLISION);
    REQUIRE(ninlil_model_reduce_transaction_id_allocation(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.action == NINLIL_MODEL_ID_ALLOCATION_TERMINAL);
    REQUIRE(result.api_status == NINLIL_E_ENTROPY);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(result.public_result.reason == NINLIL_REASON_NONE);
    REQUIRE(result.public_result.assurance.abi_version == 0u);
    REQUIRE(result.health_degraded == 1u);
    REQUIRE(result.health_add_cause == NINLIL_REASON_OUTCOME_UNKNOWN);
    REQUIRE(result.write_set.durability == 0u);
    return 1;
}

/* TXID3_STORAGE_LOOKUP_FAILURE and health intent. */
static int test_lookup_failure_matrix(void)
{
    static const struct {
        ninlil_model_transaction_collision_state_t collision;
        ninlil_status_t status;
        ninlil_reason_t health;
    } cases[] = {
        { NINLIL_MODEL_TRANSACTION_LOOKUP_BUSY, NINLIL_E_WOULD_BLOCK,
          NINLIL_REASON_NONE },
        { NINLIL_MODEL_TRANSACTION_LOOKUP_IO_ERROR, NINLIL_E_STORAGE,
          NINLIL_REASON_STORAGE_IO },
        { NINLIL_MODEL_TRANSACTION_LOOKUP_CORRUPT,
          NINLIL_E_STORAGE_CORRUPT, NINLIL_REASON_STORAGE_IO }
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        ninlil_model_id_allocation_input_t input =
            make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
        ninlil_model_id_allocation_result_t result;

        input.draw_count = 1u;
        set_draw(
            &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 40u,
            cases[index].collision);
        REQUIRE(ninlil_model_reduce_transaction_id_allocation(&input, &result)
            == NINLIL_OK);
        REQUIRE(result.action == NINLIL_MODEL_ID_ALLOCATION_TERMINAL);
        REQUIRE(result.api_status == cases[index].status);
        REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);
        REQUIRE(result.health_add_cause == cases[index].health);
        REQUIRE(result.next_draw_ordinal == 0u);
    }
    return 1;
}

static int test_allocation_invalid_shapes(void)
{
    ninlil_model_id_allocation_input_t input =
        make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);

    input.payload.content_verified = 0u;
    input.draw_count = 1u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 50u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.payload.verified_content_digest.bytes[31] ^= 1u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.descriptor_contract.target_limit = 2u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.draw_count = 1u;
    set_draw(
        &input.draws[0], 2u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 50u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.draw_count = 2u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 50u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    set_draw(
        &input.draws[1], 2u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 51u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    REQUIRE(expect_allocation_invalid(&input));
    return 1;
}

/* Every preflight-plan fact is revalidated before the first entropy draw. */
static int test_plan_semantic_validation_before_draw(void)
{
    ninlil_model_id_allocation_input_t input;

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.preflight_plan.quota.clock_epoch_id.bytes[15] ^= 1u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.preflight_plan.quota.window_started_at_ms = 1u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.preflight_plan.quota.next_event_active_spool_count = 1u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    input.preflight_plan.quota.next_event_active_spool_count = 33u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    input.preflight_plan.quota.next_event_active_spool_bytes = 32769u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    (void)memset(
        &input.preflight_plan.grant.provider_id,
        0,
        sizeof(input.preflight_plan.grant.provider_id));
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    input.preflight_plan.grant.max_payload_bytes = 2u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    input.preflight_plan.grant.retry_delay_ms = 1u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    (void)memset(
        &input.preflight_plan.target.target_runtime_id,
        0,
        sizeof(input.preflight_plan.target.target_runtime_id));
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.preflight_plan.service.namespace_id.bytes[0] = (uint8_t)'O';
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.preflight_plan.absolute_effect_deadline_ms = 99u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.preflight_plan.absolute_effect_deadline_ms = 5099u;
    input.preflight_plan.absolute_evidence_close_ms = 6099u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    input.preflight_plan.absolute_evidence_close_ms = 6101u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    input.preflight_plan.resources.reserved_ledger.entries[1].reserved += 1u;
    REQUIRE(expect_allocation_invalid(&input));

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    input.preflight_plan.resources.committed_ledger.entries[1].used += 1u;
    REQUIRE(expect_allocation_invalid(&input));
    return 1;
}

static ninlil_model_admission_write_set_t make_write_set(ninlil_family_t family)
{
    ninlil_model_id_allocation_input_t input =
        make_allocation_input(family, 3u);
    ninlil_model_id_allocation_result_t result;

    input.draw_count = 1u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 60u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    (void)ninlil_model_reduce_transaction_id_allocation(&input, &result);
    return result.write_set;
}

static int expect_commit_invalid(const ninlil_model_admission_commit_input_t *input)
{
    ninlil_model_admission_commit_result_t result;
    ninlil_model_admission_commit_result_t zero;

    (void)memset(&result, 0xa5, sizeof(result));
    if (ninlil_model_reduce_admission_commit(input, &result)
        != NINLIL_E_INVALID_ARGUMENT) {
        return 0;
    }
    (void)memset(&zero, 0, sizeof(zero));
    return memcmp(&result, &zero, sizeof(result)) == 0;
}

static int test_commit_matrix(void)
{
    static const struct {
        ninlil_model_admission_commit_state_t state;
        ninlil_status_t status;
        ninlil_submission_kind_t kind;
        ninlil_reason_t reason;
        ninlil_reason_t health;
    } cases[] = {
        { NINLIL_MODEL_ADMISSION_COMMIT_NO_SPACE, NINLIL_OK,
          NINLIL_SUBMISSION_REJECTED, NINLIL_REASON_CAPACITY_EXHAUSTED,
          NINLIL_REASON_NONE },
        { NINLIL_MODEL_ADMISSION_COMMIT_BUSY, NINLIL_E_WOULD_BLOCK,
          NINLIL_SUBMISSION_INVALID, NINLIL_REASON_NONE,
          NINLIL_REASON_NONE },
        { NINLIL_MODEL_ADMISSION_COMMIT_IO_ERROR, NINLIL_E_STORAGE,
          NINLIL_SUBMISSION_INVALID, NINLIL_REASON_NONE,
          NINLIL_REASON_STORAGE_IO },
        { NINLIL_MODEL_ADMISSION_COMMIT_CORRUPT,
          NINLIL_E_STORAGE_CORRUPT, NINLIL_SUBMISSION_INVALID,
          NINLIL_REASON_NONE, NINLIL_REASON_STORAGE_IO }
    };
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        ninlil_model_admission_commit_input_t input;
        ninlil_model_admission_commit_result_t result;

        (void)memset(&input, 0, sizeof(input));
        input.write_set = make_write_set(NINLIL_FAMILY_DESIRED_STATE);
        input.commit_state = cases[index].state;
        REQUIRE(ninlil_model_reduce_admission_commit(&input, &result)
            == NINLIL_OK);
        REQUIRE(result.api_status == cases[index].status);
        REQUIRE(result.public_result.kind == cases[index].kind);
        REQUIRE(result.public_result.reason == cases[index].reason);
        REQUIRE(result.health_add_cause == cases[index].health);
        REQUIRE(result.ownership
            == NINLIL_MODEL_ADMISSION_OWNERSHIP_NOT_ESTABLISHED);
        REQUIRE(result.durable_write_set_present == 0u);
        REQUIRE(result.recovery_probe_present == 0u);
        REQUIRE(result.recovery_action
            == NINLIL_MODEL_ADMISSION_RECOVERY_NONE);
        REQUIRE(result.journal_operation_id.bytes[15] == 0u);
        REQUIRE(result.staged_write_set_present == 0u);
    }
    return 1;
}

static int test_commit_ok_and_unknown(void)
{
    ninlil_model_admission_commit_input_t input;
    ninlil_model_admission_commit_result_t result;

    (void)memset(&input, 0, sizeof(input));
    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_OK;
    REQUIRE(ninlil_model_reduce_admission_commit(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_OK);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(result.public_result.transaction_id.bytes[15] == 60u);
    REQUIRE(result.public_result.assurance.origin_grant_snapshot_committed == 1u);
    REQUIRE(result.ownership == NINLIL_MODEL_ADMISSION_OWNERSHIP_ESTABLISHED);
    REQUIRE(result.durable_write_set_present == 1u);
    REQUIRE(result.recovery_required == 0u);
    REQUIRE(result.recovery_action == NINLIL_MODEL_ADMISSION_RECOVERY_NONE);

    input.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_UNKNOWN;
    REQUIRE(ninlil_model_reduce_admission_commit(&input, &result)
        == NINLIL_OK);
    REQUIRE(result.api_status == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(result.public_result.kind == NINLIL_SUBMISSION_INVALID);
    REQUIRE(result.public_result.reason == NINLIL_REASON_NONE);
    REQUIRE(result.ownership == NINLIL_MODEL_ADMISSION_OWNERSHIP_UNRESOLVED);
    REQUIRE(result.durable_write_set_present == 0u);
    REQUIRE(result.recovery_required == 1u);
    REQUIRE(result.recovery_action
        == NINLIL_MODEL_ADMISSION_RECOVERY_FENCE_AND_REOPEN_JOURNAL);
    REQUIRE(result.journal_operation_id.bytes[15] == 60u);
    REQUIRE(result.health_add_cause == NINLIL_REASON_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(result.recovery_probe_present == 1u);
    REQUIRE(result.recovery_probe.transaction_id.bytes[15] == 60u);
    REQUIRE(result.recovery_probe.event_id_present == 1u);
    REQUIRE(result.recovery_probe.event_id.bytes[15] == 9u);
    REQUIRE(result.staged_write_set_present == 1u);
    REQUIRE(result.staged_write_set_for_reconcile.transaction_id.bytes[15]
        == 60u);
    return 1;
}

static int test_commit_write_set_tamper_and_determinism(void)
{
    ninlil_model_admission_commit_input_t input;
    ninlil_model_admission_commit_result_t first;
    ninlil_model_admission_commit_result_t second;

    (void)memset(&input, 0, sizeof(input));
    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_OK;
    REQUIRE(ninlil_model_reduce_admission_commit(&input, &first) == NINLIL_OK);
    REQUIRE(ninlil_model_reduce_admission_commit(&input, &second) == NINLIL_OK);
    REQUIRE(memcmp(&first, &second, sizeof(first)) == 0);

    input.write_set.committed_quota.next_inflight_count += 1u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.write_set.committed_resource_ledger.entries[1].used += 1u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.write_set.descriptor.registered_service.inflight_limit += 1u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.write_set.grant_snapshot.target.target_runtime_id.bytes[15] ^= 1u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.write_set.reservation_manifest.event_resume_slots = 7u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.write_set.initial_family_snapshot.delivery_possible = 1u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.write_set.transaction_record_revision = 2u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_EVENT_FACT);
    input.write_set.initial_family_snapshot.spool_revision = 2u;
    REQUIRE(expect_commit_invalid(&input));

    input.write_set = make_write_set(NINLIL_FAMILY_DESIRED_STATE);
    input.write_set.event_mapping.transaction_id.bytes[15] = 1u;
    REQUIRE(expect_commit_invalid(&input));
    return 1;
}

static int test_zero_length_payloads(void)
{
    ninlil_family_t families[] = {
        NINLIL_FAMILY_DESIRED_STATE,
        NINLIL_FAMILY_EVENT_FACT
    };
    size_t index;

    for (index = 0u; index < sizeof(families) / sizeof(families[0]); ++index) {
        ninlil_model_id_allocation_input_t input =
            make_allocation_input(families[index], 0u);
        ninlil_model_id_allocation_result_t result;
        ninlil_model_admission_commit_input_t commit_input;
        ninlil_model_admission_commit_result_t commit_result;

        input.draw_count = 1u;
        set_draw(
            &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 70u,
            NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
        REQUIRE(ninlil_model_reduce_transaction_id_allocation(&input, &result)
            == NINLIL_OK);
        REQUIRE(result.action
            == NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT);
        REQUIRE(result.write_set.payload.length == 0u);
        REQUIRE(result.write_set.payload.content_verified == 1u);
        REQUIRE(result.write_set.payload.verified_content_digest.bytes[31]
            == input.preflight_plan.content_digest.bytes[31]);
        REQUIRE(result.write_set.transaction_record_revision == 1u);
        REQUIRE(result.write_set.initial_family_snapshot.reason
            == NINLIL_REASON_NONE);
        REQUIRE(result.write_set.initial_family_snapshot.highest_evidence
            == NINLIL_EVIDENCE_NONE);
        REQUIRE(result.write_set.initial_family_snapshot.latest_evidence
            == NINLIL_EVIDENCE_NONE);
        REQUIRE(result.write_set.initial_family_snapshot.effect_certainty
            == NINLIL_EFFECT_CERTAINTY_NONE);
        REQUIRE(result.write_set.initial_family_snapshot.dispatch_fenced == 0u);
        REQUIRE(result.write_set.initial_family_snapshot.cumulative_attempts
            == 0u);
        REQUIRE(result.write_set.initial_family_snapshot.timer_present == 0u);
        REQUIRE(result.write_set.initial_family_snapshot.delivery_possible
            == 0u);

        if (families[index] == NINLIL_FAMILY_DESIRED_STATE) {
            REQUIRE(input.preflight_plan.resources.reserve_request_count == 3u);
            REQUIRE(input.preflight_plan.resources.commit_request_count == 3u);
            REQUIRE(result.write_set.initial_queue_kind
                == NINLIL_MODEL_INITIAL_COMMAND_OUTBOX);
        } else {
            REQUIRE(input.preflight_plan.resources.reserve_request_count == 5u);
            REQUIRE(input.preflight_plan.resources.commit_request_count == 4u);
            REQUIRE(input.preflight_plan.resources.committed_ledger.entries[6]
                .used == 0u);
            REQUIRE(input.preflight_plan.resources.committed_ledger.entries[6]
                .reserved
                == NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES);
            REQUIRE(result.write_set.grant_snapshot.decision.retry_delay_ms
                == 0u);
        }

        (void)memset(&commit_input, 0, sizeof(commit_input));
        commit_input.write_set = result.write_set;
        commit_input.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_OK;
        REQUIRE(ninlil_model_reduce_admission_commit(
            &commit_input, &commit_result) == NINLIL_OK);
        REQUIRE(commit_result.api_status == NINLIL_OK);
        REQUIRE(commit_result.public_result.kind
            == NINLIL_SUBMISSION_ADMITTED_READY);
        REQUIRE(commit_result.public_result.canonical_submission_digest
            .bytes[31]
            == input.preflight_plan.canonical_submission_digest.bytes[31]);
        REQUIRE(commit_result.public_result.assurance.descriptor_snapshot_fixed
            == 1u);
        REQUIRE(commit_result.public_result.assurance.local_journal_committed
            == 1u);
        REQUIRE(commit_result.public_result.assurance.local_capacity_reserved
            == 1u);
        REQUIRE(commit_result.durable_write_set.payload.length == 0u);

        commit_input.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_UNKNOWN;
        REQUIRE(ninlil_model_reduce_admission_commit(
            &commit_input, &commit_result) == NINLIL_OK);
        REQUIRE(commit_result.api_status
            == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        REQUIRE(commit_result.ownership
            == NINLIL_MODEL_ADMISSION_OWNERSHIP_UNRESOLVED);
        REQUIRE(commit_result.staged_write_set_present == 1u);
        REQUIRE(commit_result.staged_write_set_for_reconcile.payload.length
            == 0u);
    }
    return 1;
}

/* Schema major zero is valid when the registered service and plan agree. */
static int test_schema_major_zero_allocation_and_commit(void)
{
    ninlil_model_id_allocation_input_t input =
        make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    ninlil_model_id_allocation_result_t allocation;
    ninlil_model_admission_commit_input_t commit_input;
    ninlil_model_admission_commit_result_t commit_result;

    input.preflight_plan.registered_service.identity.schema_major = 0u;
    input.preflight_plan.registered_service.schema_major = 0u;
    input.preflight_plan.registered_service.schema_minor_min = 0u;
    input.preflight_plan.registered_service.schema_minor_max = 1u;
    input.preflight_plan.service.schema_major = 0u;
    input.preflight_plan.service.schema_minor = 1u;
    input.preflight_plan.registered_service.identity.schema_minor = 1u;
    input.draw_count = 1u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 71u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);

    REQUIRE(ninlil_model_reduce_transaction_id_allocation(
        &input, &allocation) == NINLIL_OK);
    REQUIRE(allocation.action
        == NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT);
    REQUIRE(allocation.write_set.plan.service.schema_major == 0u);
    REQUIRE(allocation.write_set.descriptor.registered_service
        .identity.schema_minor == 1u);

    (void)memset(&commit_input, 0, sizeof(commit_input));
    commit_input.write_set = allocation.write_set;
    commit_input.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_OK;
    REQUIRE(ninlil_model_reduce_admission_commit(
        &commit_input, &commit_result) == NINLIL_OK);
    REQUIRE(commit_result.api_status == NINLIL_OK);
    REQUIRE(commit_result.public_result.kind
        == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(commit_result.durable_write_set.plan.service.schema_major == 0u);
    return 1;
}

static int test_family_specific_descriptor_attempt_budget(void)
{
    ninlil_model_id_allocation_input_t input =
        make_allocation_input(NINLIL_FAMILY_DESIRED_STATE, 3u);
    ninlil_model_id_allocation_result_t allocation;
    ninlil_model_admission_commit_input_t commit_input;
    ninlil_model_admission_commit_result_t commit_result;

    input.descriptor_contract.max_attempts_per_target_per_cycle = 1u;
    input.draw_count = 1u;
    set_draw(
        &input.draws[0], 1u, NINLIL_MODEL_ENTROPY_DRAW_FULL, 72u,
        NINLIL_MODEL_TRANSACTION_ID_UNIQUE);
    REQUIRE(ninlil_model_reduce_transaction_id_allocation(
        &input, &allocation) == NINLIL_OK);
    REQUIRE(allocation.action
        == NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT);
    REQUIRE(allocation.write_set.descriptor.contract
        .max_attempts_per_target_per_cycle == 1u);

    (void)memset(&commit_input, 0, sizeof(commit_input));
    commit_input.write_set = allocation.write_set;
    commit_input.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_OK;
    REQUIRE(ninlil_model_reduce_admission_commit(
        &commit_input, &commit_result) == NINLIL_OK);
    REQUIRE(commit_result.public_result.kind
        == NINLIL_SUBMISSION_ADMITTED_READY);
    REQUIRE(commit_result.durable_write_set.descriptor.contract
        .max_attempts_per_target_per_cycle == 1u);

    input = make_allocation_input(NINLIL_FAMILY_EVENT_FACT, 3u);
    input.descriptor_contract.max_attempts_per_target_per_cycle = 7u;
    REQUIRE(expect_allocation_invalid(&input));
    return 1;
}

int main(void)
{
    int passed = 1;

    passed &= test_fourth_valid_command();
    passed &= test_event_write_set();
    passed &= test_four_invalid_entropy();
    passed &= test_lookup_failure_matrix();
    passed &= test_allocation_invalid_shapes();
    passed &= test_plan_semantic_validation_before_draw();
    passed &= test_commit_matrix();
    passed &= test_commit_ok_and_unknown();
    passed &= test_commit_write_set_tamper_and_determinism();
    passed &= test_zero_length_payloads();
    passed &= test_schema_major_zero_allocation_and_commit();
    passed &= test_family_specific_descriptor_attempt_budget();
    return passed != 0 ? 0 : 1;
}
