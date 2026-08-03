#include "domain_store_codec.h"
#include "runtime_internal.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_event_mgmt.h"
#include "runtime_v1_transaction_codec.h"

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

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static void set_id(ninlil_id128_t *id, uint8_t tag)
{
    uint32_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        id->bytes[index] = (uint8_t)(tag + index);
    }
}

static void set_digest(ninlil_digest256_t *digest, uint8_t tag)
{
    uint32_t index;

    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    for (index = 0u; index < sizeof(digest->bytes); ++index) {
        digest->bytes[index] = (uint8_t)(tag + index);
    }
}

static void set_text(ninlil_text_id_t *text, const char *value)
{
    size_t length = strlen(value);

    (void)memset(text, 0, sizeof(*text));
    text->length = (uint8_t)length;
    (void)memcpy(text->bytes, value, length);
}

static void set_max_text(ninlil_text_id_t *text)
{
    (void)memset(text, 0, sizeof(*text));
    text->length = NINLIL_MAX_TEXT_ID_BYTES;
    (void)memset(text->bytes, 'a', sizeof(text->bytes));
}

static void fill_target(ninlil_rt_target_slot_t *target, uint8_t tag)
{
    (void)memset(target, 0, sizeof(*target));
    target->in_use = 1u;
    target->pending_dispatch = 1u;
    target->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    set_header(
        &target->target.abi_version,
        &target->target.struct_size,
        sizeof(target->target));
    set_id(&target->target.target_runtime_id, tag);
    set_id(&target->target.target_application_instance_id, (uint8_t)(tag + 0x10u));
    target->target.flags = NINLIL_TARGET_HAS_DEVICE
        | NINLIL_TARGET_HAS_INSTALLATION
        | NINLIL_TARGET_HAS_SITE;
    set_id(&target->target.device_id, (uint8_t)(tag + 0x20u));
    set_id(&target->target.installation_id, (uint8_t)(tag + 0x30u));
    set_id(&target->target.site_domain_id, (uint8_t)(tag + 0x40u));
    target->target.binding_epoch = 7u;
    target->target.membership_epoch = 9u;
    target->outcome = NINLIL_OUTCOME_NONE;
    target->reason = NINLIL_REASON_NONE;
    target->latest_evidence = NINLIL_EVIDENCE_NONE;
    target->deadline_verdict = NINLIL_DEADLINE_PENDING;
    target->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
}

static void fill_valid_transaction(ninlil_rt_transaction_slot_t *transaction)
{
    (void)memset(transaction, 0, sizeof(*transaction));
    transaction->in_use = 1u;
    transaction->origin_admission = 1u;
    transaction->has_late_evidence = 0u;
    set_id(&transaction->transaction_id, 0x10u);
    set_id(&transaction->attempt_ids[0], 0x20u);
    set_id(&transaction->attempt_ids[1], 0x30u);
    transaction->attempt_id = transaction->attempt_ids[1];
    transaction->attempt_prepared = 1u;
    transaction->attempt_count = 2u;
    transaction->attempt_target_indices[0] = 0u;
    transaction->attempt_target_indices[1] = 1u;
    transaction->active_target_index = 1u;
    set_id(&transaction->service_app_id, 0x40u);

    set_header(
        &transaction->source.abi_version,
        &transaction->source.struct_size,
        sizeof(transaction->source));
    set_id(&transaction->source.runtime_id, 0x60u);
    set_id(&transaction->source.application_instance_id, 0x70u);
    set_header(
        &transaction->source.local_identity.abi_version,
        &transaction->source.local_identity.struct_size,
        sizeof(transaction->source.local_identity));
    transaction->source.local_identity.flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&transaction->source.local_identity.device_id, 0x80u);
    set_id(&transaction->source.local_identity.installation_id, 0x90u);
    set_id(&transaction->source.local_identity.site_domain_id, 0xa0u);
    transaction->source.local_identity.binding_epoch = 11u;
    transaction->source.local_identity.membership_epoch = 12u;

    set_header(
        &transaction->service.abi_version,
        &transaction->service.struct_size,
        sizeof(transaction->service));
    set_text(&transaction->service.namespace_id, "org.ninlil.test");
    set_text(&transaction->service.service_id, "display_state");
    set_text(&transaction->service.schema_id, "display-v1");
    transaction->service.descriptor_revision = 13u;
    set_digest(&transaction->service.descriptor_digest, 0xb0u);
    transaction->service.schema_major = 1u;
    transaction->service.schema_minor = 2u;
    transaction->service.family = NINLIL_FAMILY_DESIRED_STATE;
    set_digest(&transaction->content_digest, 0xc0u);
    transaction->idempotency_key_length = 3u;
    transaction->idempotency_key[0] = (uint8_t)'k';
    transaction->idempotency_key[1] = (uint8_t)'e';
    transaction->idempotency_key[2] = (uint8_t)'y';
    set_digest(&transaction->canonical_submission_digest, 0xc1u);

    transaction->family = NINLIL_FAMILY_DESIRED_STATE;
    transaction->required_evidence = NINLIL_EVIDENCE_APPLIED;
    transaction->latest_evidence = NINLIL_EVIDENCE_APPLIED;
    transaction->application_result_kind =
        NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    transaction->application_disposition = NINLIL_DISPOSITION_NONE;
    transaction->application_result_reason = NINLIL_REASON_NONE;
    transaction->application_effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NONE;
    transaction->application_retry_guidance = NINLIL_RETRY_NEVER;
    transaction->application_evidence_length = 5u;
    (void)memcpy(transaction->application_evidence, "proof", 5u);
    transaction->evidence_recorded = 0u;
    transaction->deadline_verdict = NINLIL_DEADLINE_PENDING;
    transaction->transaction_sequence = 42u;
    transaction->record_revision = 7u;
    transaction->reason = NINLIL_REASON_TRANSPORT_RETRY;
    transaction->pending_dispatch = 1u;
    transaction->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    transaction->delivery_count = 0u;
    transaction->token_state = NINLIL_RT_TOKEN_NONE;
    transaction->spool_revision = 0u;
    transaction->retry_budget =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - 1u;
    transaction->cumulative_attempts = 2u;
    transaction->next_retry_ms = 300u;
    set_id(&transaction->next_retry_clock_epoch_id, 0xe0u);
    transaction->effect_deadline_ms = 9000u;
    transaction->evidence_grace_ms = 1000u;
    set_id(&transaction->admission_clock_epoch_id, 0x15u);
    set_id(&transaction->deadline_clock_epoch_id, 0x25u);
    transaction->generation = 5u;
    transaction->resume_op_count = 0u;
    transaction->payload_length = 6u;
    transaction->inline_payload_length = 6u;
    (void)memcpy(transaction->owned_payload, "ninlil", 6u);
    transaction->semantic_priority = 8u;
    transaction->bearer_route = 1u;
    transaction->reservation_active = 1u;
    transaction->reservation_evidence_units = 4u;
    transaction->admitted_at_ms = 50u;
    transaction->attempt_receipt_timeout_ms = 1000u;
    transaction->retry_backoff_ms = 100u;
    transaction->last_bearer_availability_epoch = 6u;
    transaction->last_consumed_bearer_availability_epoch = 5u;
    transaction->ordered_input_sequence = 8u;

    set_header(
        &transaction->assurance.abi_version,
        &transaction->assurance.struct_size,
        sizeof(transaction->assurance));
    transaction->assurance.assurance_profile =
        NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL;
    transaction->assurance.submission_validated = 1u;
    transaction->assurance.target_roster_fixed = 1u;
    transaction->assurance.descriptor_snapshot_fixed = 1u;
    transaction->assurance.local_journal_committed = 1u;
    transaction->assurance.local_capacity_reserved = 1u;
    transaction->assurance.idempotency_mapping_committed = 1u;
    transaction->assurance.origin_grant_snapshot_committed = 1u;

    transaction->bound_target_count = 2u;
    fill_target(&transaction->bound_targets[0], 0x55u);
    fill_target(&transaction->bound_targets[1], 0x65u);
    transaction->bound_targets[0].evidence_recorded = 1u;
    transaction->bound_targets[0].terminal = 1u;
    transaction->bound_targets[0].pending_dispatch = 0u;
    transaction->bound_targets[0].delivery_phase =
        NINLIL_RT_DELIVERY_OUTCOME;
    transaction->bound_targets[0].latest_evidence =
        NINLIL_EVIDENCE_APPLIED;
    transaction->bound_targets[0].deadline_verdict =
        NINLIL_DEADLINE_MET;
    transaction->bound_targets[0].outcome = NINLIL_OUTCOME_SATISFIED;
    transaction->bound_targets[0].reason =
        NINLIL_REASON_REQUIRED_EVIDENCE_MET;
    transaction->bound_targets[0].retry_budget =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE - 1u;
    transaction->bound_targets[0].attempt_in_cycle = 1u;
    transaction->bound_targets[0].cumulative_attempts = 1u;
    transaction->bound_targets[1].attempt_prepared = 1u;
    transaction->bound_targets[1].active_attempt_id =
        transaction->attempt_ids[1];
    transaction->bound_targets[1].delivery_phase =
        transaction->delivery_phase;
    transaction->bound_targets[1].reason = NINLIL_REASON_NONE;
    transaction->bound_targets[1].retry_budget =
        transaction->retry_budget;
    transaction->bound_targets[1].attempt_in_cycle = 1u;
    transaction->bound_targets[1].cumulative_attempts = 1u;
    transaction->bound_targets[1].next_retry_ms =
        transaction->next_retry_ms;
    transaction->bound_targets[1].next_retry_clock_epoch_id =
        transaction->next_retry_clock_epoch_id;
}

static void set_mfdt_sender_correlation(
    ninlil_rt_transaction_slot_t *transaction)
{
    uint32_t target_index;
    uint32_t byte_index;

    for (target_index = 0u;
         target_index < transaction->bound_target_count;
         ++target_index) {
        for (byte_index = 0u; byte_index < 16u; ++byte_index) {
            transaction->bound_targets[target_index]
                    .mfdt_transfer_id[byte_index] =
                (uint8_t)(0xc0u + target_index * 16u + byte_index);
        }
        transaction->bound_targets[target_index].mfdt_target_ordinal =
            target_index;
    }
}

static void fill_initial_multi_target_mfdt_transaction(
    ninlil_rt_transaction_slot_t *transaction)
{
    ninlil_rt_target_slot_t *first;

    fill_valid_transaction(transaction);
    transaction->bearer_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
    transaction->payload_length =
        NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES + 1u;
    transaction->inline_payload_length = 0u;
    (void)memset(
        transaction->owned_payload, 0, sizeof(transaction->owned_payload));
    set_mfdt_sender_correlation(transaction);
    transaction->active_target_index = 0u;
    transaction->attempt_id = transaction->attempt_ids[0];

    first = &transaction->bound_targets[0];
    first->terminal = 0u;
    first->pending_dispatch = transaction->pending_dispatch;
    first->attempt_prepared = 1u;
    first->active_attempt_id = transaction->attempt_ids[0];
    first->delivery_phase = transaction->delivery_phase;
    first->outcome = NINLIL_OUTCOME_NONE;
    first->retry_budget = transaction->retry_budget;
    first->next_retry_ms = transaction->next_retry_ms;
    first->next_retry_clock_epoch_id =
        transaction->next_retry_clock_epoch_id;
}

static uint32_t load_u32_be(const uint8_t *value)
{
    return ((uint32_t)value[0] << 24)
        | ((uint32_t)value[1] << 16)
        | ((uint32_t)value[2] << 8)
        | (uint32_t)value[3];
}

static void store_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void store_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56u);
    out[1] = (uint8_t)(value >> 48u);
    out[2] = (uint8_t)(value >> 40u);
    out[3] = (uint8_t)(value >> 32u);
    out[4] = (uint8_t)(value >> 24u);
    out[5] = (uint8_t)(value >> 16u);
    out[6] = (uint8_t)(value >> 8u);
    out[7] = (uint8_t)value;
}

static void refresh_crc(uint8_t *record, uint32_t length)
{
    uint32_t crc = ninlil_model_domain_crc32c(record, length - 4u);

    store_u32_be(&record[length - 4u], crc);
}

static uint32_t find_unique_bytes(
    const uint8_t *haystack,
    uint32_t haystack_length,
    const uint8_t *needle,
    uint32_t needle_length)
{
    uint32_t found = UINT32_MAX;
    uint32_t matches = 0u;
    uint32_t offset;

    if (needle_length == 0u || haystack_length < needle_length) {
        return UINT32_MAX;
    }
    for (offset = 0u;
         offset <= haystack_length - needle_length;
         ++offset) {
        if (memcmp(&haystack[offset], needle, needle_length) == 0) {
            found = offset;
            matches += 1u;
        }
    }
    return matches == 1u ? found : UINT32_MAX;
}

static void fill_active_inbound_token(
    ninlil_rt_transaction_slot_t *transaction,
    uint64_t generation)
{
    fill_valid_transaction(transaction);
    transaction->origin_admission = 0u;
    transaction->has_late_evidence = 0u;
    transaction->latest_evidence = NINLIL_EVIDENCE_NONE;
    transaction->application_result_kind = 0u;
    transaction->application_result_reason = NINLIL_REASON_NONE;
    transaction->application_evidence_length = 0u;
    transaction->evidence_recorded = 0u;
    transaction->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    transaction->delivery_count = generation;
    transaction->token_state = NINLIL_RT_TOKEN_ACTIVE;
    transaction->deferred_wait = 0u;
    set_id(&transaction->token_clock_epoch_id, 0xd0u);
    transaction->token_generation = generation;
    transaction->delivery_started_at_ms = 100u;
    transaction->application_completion_timeout_ms = 100u;
    transaction->token_expires_at_ms = 200u;
}

static int output_unchanged_after_failure(
    ninlil_bytes_view_t record,
    ninlil_status_t expected)
{
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t output;
    ninlil_rt_transaction_slot_t sentinel;
    ninlil_status_t status;

    (void)memset(&scratch, 0x5au, sizeof(scratch));
    (void)memset(&output, 0xa5u, sizeof(output));
    sentinel = output;
    status = ninlil_rt_v1_transaction_record_decode(
        record, &scratch, &output);
    return status == expected
        && memcmp(&output, &sentinel, sizeof(output)) == 0;
}

static int test_transaction_roundtrip_and_known_bytes(void)
{
    ninlil_rt_transaction_slot_t source;
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t decoded;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t reencoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t encoded_length = 0u;
    uint32_t reencoded_length = 0u;

    fill_valid_transaction(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    REQUIRE(encoded[0] == 0x4eu && encoded[1] == 0x54u
        && encoded[2] == 0x53u && encoded[3] == 0x33u);
    REQUIRE(encoded[4] == 0u && encoded[5] == 1u);
    REQUIRE(encoded[6] == 0u && encoded[7] == 2u);
    REQUIRE(load_u32_be(&encoded[8]) == encoded_length - 20u);
    REQUIRE(load_u32_be(&encoded[12]) == 0u);
    REQUIRE(load_u32_be(&encoded[encoded_length - 4u])
        == ninlil_model_domain_crc32c(encoded, encoded_length - 4u));
    /* Body includes durable idempotency key + canonical submission digest. */
    REQUIRE(encoded_length
        <= NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES);

    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){encoded, encoded_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.transaction_sequence == source.transaction_sequence);
    REQUIRE(decoded.record_revision == source.record_revision);
    REQUIRE(decoded.attempt_count == source.attempt_count);
    REQUIRE(decoded.application_evidence_length
        == source.application_evidence_length);
    REQUIRE(decoded.payload_length == source.payload_length);
    REQUIRE(decoded.inline_payload_length == source.inline_payload_length);
    REQUIRE(decoded.bound_target_count == source.bound_target_count);
    REQUIRE(decoded.idempotency_key_length == source.idempotency_key_length);
    REQUIRE(memcmp(
                decoded.idempotency_key,
                source.idempotency_key,
                source.idempotency_key_length)
        == 0);
    REQUIRE(memcmp(
                decoded.canonical_submission_digest.bytes,
                source.canonical_submission_digest.bytes,
                32u)
        == 0);
    REQUIRE(memcmp(
                decoded.owned_payload,
                source.owned_payload,
                source.inline_payload_length)
        == 0);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &decoded,
                reencoded,
                (uint32_t)sizeof(reencoded),
                &reencoded_length)
        == NINLIL_OK);
    REQUIRE(reencoded_length == encoded_length);
    REQUIRE(memcmp(encoded, reencoded, encoded_length) == 0);
    return 0;
}

static int test_transaction_rejects_invalid_semantics_before_encoding(void)
{
    ninlil_rt_transaction_slot_t source;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t encoded_length = UINT32_MAX;

    fill_valid_transaction(&source);
    source.attempt_ids[1] = source.attempt_ids[0];
    source.attempt_id = source.attempt_ids[1];
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_valid_transaction(&source);
    (void)memset(
        source.content_digest.bytes, 0, sizeof(source.content_digest.bytes));
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_valid_transaction(&source);
    source.service.namespace_id.bytes[0] = 'A';
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_valid_transaction(&source);
    source.bearer_route = 0u;
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_valid_transaction(&source);
    (void)memset(
        &source.service_app_id, 0, sizeof(source.service_app_id));
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_valid_transaction(&source);
    source.application_retry_guidance = NINLIL_RETRY_MODIFIED;
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_valid_transaction(&source);
    source.application_result_kind = NINLIL_APP_RESULT_DISPOSITION;
    source.application_disposition = NINLIL_DISPOSITION_APPLICATION_BUSY;
    source.application_result_reason = NINLIL_REASON_RECEIVER_UNAVAILABLE;
    source.application_effect_certainty =
        NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    source.application_retry_guidance = NINLIL_RETRY_SAME_AFTER;
    source.application_retry_delay_ms = NINLIL_M1A_MAX_RETRY_DELAY_MS;
    source.application_evidence_length = 0u;
    encoded_length = 0u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    REQUIRE(encoded_length != 0u);
    source.application_retry_delay_ms =
        NINLIL_M1A_MAX_RETRY_DELAY_MS + 1u;
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);
    return 0;
}

static int test_evidence_counter_saturation_shape(void)
{
    ninlil_rt_transaction_slot_t source;
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t decoded;
    uint8_t flag_zero_record[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t flag_one_record[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t invalid_record[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t flag_zero_length = 0u;
    uint32_t flag_one_length = 0u;
    uint32_t invalid_length = 0u;
    uint32_t flag_offset = UINT32_MAX;
    uint32_t difference_count = 0u;
    uint32_t index;

    /* Reaching MAX is legal while the sticky saturation flag is still zero. */
    fill_valid_transaction(&source);
    source.bound_targets[1].valid_evidence_count = UINT64_MAX;
    source.bound_targets[1].evidence_counter_saturated = 0u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                flag_zero_record,
                (uint32_t)sizeof(flag_zero_record),
                &flag_zero_length)
        == NINLIL_OK);
    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){flag_zero_record, flag_zero_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.bound_targets[1].valid_evidence_count == UINT64_MAX);
    REQUIRE(decoded.bound_targets[1].evidence_counter_saturated == 0u);

    /* Once an increment at MAX is attempted, flag one is valid and sticky. */
    source.bound_targets[1].evidence_counter_saturated = 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                flag_one_record,
                (uint32_t)sizeof(flag_one_record),
                &flag_one_length)
        == NINLIL_OK);
    REQUIRE(flag_one_length == flag_zero_length);
    for (index = 0u; index < flag_zero_length - 4u; ++index) {
        if (flag_zero_record[index] != flag_one_record[index]) {
            difference_count += 1u;
            flag_offset = index;
        }
    }
    REQUIRE(difference_count == 1u);
    REQUIRE(flag_zero_record[flag_offset] == 0u);
    REQUIRE(flag_one_record[flag_offset] == 1u);
    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){flag_one_record, flag_one_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.bound_targets[1].valid_evidence_count == UINT64_MAX);
    REQUIRE(decoded.bound_targets[1].evidence_counter_saturated == 1u);

    /* Flag one without any MAX counter is neither encodable nor recoverable. */
    fill_valid_transaction(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                invalid_record,
                (uint32_t)sizeof(invalid_record),
                &invalid_length)
        == NINLIL_OK);
    REQUIRE(invalid_length == flag_zero_length);
    invalid_record[flag_offset] = 1u;
    refresh_crc(invalid_record, invalid_length);
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){invalid_record, invalid_length},
        NINLIL_E_STORAGE_CORRUPT));

    source.bound_targets[1].evidence_counter_saturated = 1u;
    invalid_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                invalid_record,
                (uint32_t)sizeof(invalid_record),
                &invalid_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(invalid_length == 0u);
    return 0;
}

static int test_nts3_delivery_token_matrix_is_shared_by_encode_and_decode(void)
{
    static const uint64_t generation = UINT64_C(0x1122334455667788);
    ninlil_rt_transaction_slot_t source;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t mutated[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t generation_bytes[8];
    uint32_t encoded_length = 0u;
    uint32_t index;
    uint32_t generation_match[2] = {UINT32_MAX, UINT32_MAX};
    uint32_t generation_match_count = 0u;

    fill_active_inbound_token(&source, generation);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);

    source.token_generation += 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                mutated,
                (uint32_t)sizeof(mutated),
                &index)
        == NINLIL_E_INVALID_ARGUMENT);
    fill_active_inbound_token(&source, generation);
    source.deferred_wait = 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                mutated,
                (uint32_t)sizeof(mutated),
                &index)
        == NINLIL_E_INVALID_ARGUMENT);
    fill_active_inbound_token(&source, generation);
    source.delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                mutated,
                (uint32_t)sizeof(mutated),
                &index)
        == NINLIL_E_INVALID_ARGUMENT);
    fill_active_inbound_token(&source, generation);
    source.token_state = NINLIL_RT_TOKEN_CONSUMED;
    (void)memset(
        &source.token_clock_epoch_id, 0, sizeof(source.token_clock_epoch_id));
    source.delivery_started_at_ms = 0u;
    source.token_expires_at_ms = 0u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                mutated,
                (uint32_t)sizeof(mutated),
                &index)
        == NINLIL_E_INVALID_ARGUMENT);
    fill_active_inbound_token(&source, generation);
    source.token_state = NINLIL_RT_TOKEN_EXPIRED;
    source.delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                mutated,
                (uint32_t)sizeof(mutated),
                &index)
        == NINLIL_E_INVALID_ARGUMENT);
    fill_active_inbound_token(&source, generation);
    source.token_state = NINLIL_RT_TOKEN_CONSUMED;
    source.delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                mutated,
                (uint32_t)sizeof(mutated),
                &index)
        == NINLIL_OK);
    source.application_result_kind =
        NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    source.latest_evidence = NINLIL_EVIDENCE_APPLIED;
    source.evidence_recorded = 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                mutated,
                (uint32_t)sizeof(mutated),
                &index)
        == NINLIL_E_INVALID_ARGUMENT);

    store_u64_be(generation_bytes, generation);
    for (index = 0u; index + sizeof(generation_bytes) <= encoded_length;
         ++index) {
        if (memcmp(
                &encoded[index],
                generation_bytes,
                sizeof(generation_bytes)) == 0) {
            REQUIRE(generation_match_count < 2u);
            generation_match[generation_match_count] = index;
            generation_match_count += 1u;
        }
    }
    REQUIRE(generation_match_count == 2u);
    (void)memcpy(mutated, encoded, encoded_length);
    mutated[generation_match[1] + 7u] ^= 0x01u;
    refresh_crc(mutated, encoded_length);
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_STORAGE_CORRUPT));
    return 0;
}

static int test_transaction_rejects_malformed_without_output_mutation(void)
{
    ninlil_rt_transaction_slot_t source;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t mutated[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t legacy[46];
    uint32_t encoded_length = 0u;
    uint32_t index;
    uint32_t match = UINT32_MAX;
    uint32_t match_count = 0u;

    fill_valid_transaction(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);

    (void)memcpy(mutated, encoded, encoded_length);
    mutated[encoded_length / 2u] ^= 0x80u;
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_STORAGE_CORRUPT));
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){encoded, encoded_length - 1u},
        NINLIL_E_STORAGE_CORRUPT));
    (void)memcpy(mutated, encoded, encoded_length);
    mutated[encoded_length] = 0u;
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length + 1u},
        NINLIL_E_STORAGE_CORRUPT));

    (void)memcpy(mutated, encoded, encoded_length);
    mutated[4] = 0u;
    mutated[5] = 2u;
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_UNSUPPORTED));

    (void)memcpy(mutated, encoded, encoded_length);
    mutated[6] = 0u;
    mutated[7] = 1u;
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_UNSUPPORTED));
    REQUIRE(ninlil_rt_v1_transaction_record_validate_envelope(
                (ninlil_bytes_view_t){mutated, encoded_length})
        == NINLIL_E_UNSUPPORTED);

    (void)memcpy(mutated, encoded, encoded_length);
    mutated[6] = 0u;
    mutated[7] = 3u;
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_UNSUPPORTED));
    REQUIRE(ninlil_rt_v1_transaction_record_validate_envelope(
                (ninlil_bytes_view_t){mutated, encoded_length})
        == NINLIL_E_UNSUPPORTED);

    (void)memcpy(mutated, encoded, encoded_length);
    mutated[12] = 1u;
    refresh_crc(mutated, encoded_length);
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_STORAGE_CORRUPT));

    for (index = 16u; index + 4u <= encoded_length - 4u; ++index) {
        if (encoded[index] == 0u && encoded[index + 1u] == 0u
            && encoded[index + 2u] == 0u
            && encoded[index + 3u]
                == (uint8_t)NINLIL_REASON_TRANSPORT_RETRY) {
            match = index;
            match_count += 1u;
        }
    }
    REQUIRE(match_count == 1u);
    (void)memcpy(mutated, encoded, encoded_length);
    mutated[match + 3u] = 67u;
    refresh_crc(mutated, encoded_length);
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_STORAGE_CORRUPT));

    (void)memset(legacy, 0, sizeof(legacy));
    legacy[0] = 0x4eu;
    legacy[1] = 0x54u;
    legacy[2] = 0x53u;
    legacy[3] = 0x32u;
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){legacy, sizeof(legacy)},
        NINLIL_E_UNSUPPORTED));
    legacy[2] = 0x58u;
    legacy[3] = 0x33u;
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){legacy, sizeof(legacy)},
        NINLIL_E_UNSUPPORTED));

    (void)memset(legacy, 0xa5, 33u);
    REQUIRE(ninlil_rt_v1_transaction_record_validate_envelope(
                (ninlil_bytes_view_t){legacy, 33u})
        != NINLIL_OK);
    (void)memset(legacy, 0x5a, sizeof(legacy));
    REQUIRE(ninlil_rt_v1_transaction_record_validate_envelope(
                (ninlil_bytes_view_t){legacy, sizeof(legacy)})
        != NINLIL_OK);
    return 0;
}

static int test_unused_storage_does_not_change_canonical_bytes(void)
{
    ninlil_rt_transaction_slot_t left;
    ninlil_rt_transaction_slot_t right;
    uint8_t left_bytes[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t right_bytes[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t left_length = 0u;
    uint32_t right_length = 0u;

    fill_valid_transaction(&left);
    right = left;
    (void)memset(
        &left.attempt_ids[left.attempt_count],
        0xa5,
        sizeof(left.attempt_ids)
            - left.attempt_count * sizeof(left.attempt_ids[0]));
    (void)memset(
        &right.attempt_ids[right.attempt_count],
        0x5a,
        sizeof(right.attempt_ids)
            - right.attempt_count * sizeof(right.attempt_ids[0]));
    (void)memset(
        &left.application_evidence[left.application_evidence_length],
        0xa5,
        sizeof(left.application_evidence)
            - left.application_evidence_length);
    (void)memset(
        &right.application_evidence[right.application_evidence_length],
        0x5a,
        sizeof(right.application_evidence)
            - right.application_evidence_length);
    (void)memset(
        &left.service.namespace_id.bytes[
            left.service.namespace_id.length],
        0xa5,
        sizeof(left.service.namespace_id.bytes)
            - left.service.namespace_id.length);
    (void)memset(
        &right.service.namespace_id.bytes[
            right.service.namespace_id.length],
        0x5a,
        sizeof(right.service.namespace_id.bytes)
            - right.service.namespace_id.length);
    (void)memset(
        &left.service.service_id.bytes[left.service.service_id.length],
        0xa5,
        sizeof(left.service.service_id.bytes)
            - left.service.service_id.length);
    (void)memset(
        &right.service.service_id.bytes[right.service.service_id.length],
        0x5a,
        sizeof(right.service.service_id.bytes)
            - right.service.service_id.length);
    (void)memset(
        &left.service.schema_id.bytes[left.service.schema_id.length],
        0xa5,
        sizeof(left.service.schema_id.bytes)
            - left.service.schema_id.length);
    (void)memset(
        &right.service.schema_id.bytes[right.service.schema_id.length],
        0x5a,
        sizeof(right.service.schema_id.bytes)
            - right.service.schema_id.length);
    (void)memset(
        &left.owned_payload[left.inline_payload_length],
        0xa5,
        sizeof(left.owned_payload) - left.inline_payload_length);
    (void)memset(
        &right.owned_payload[right.inline_payload_length],
        0x5a,
        sizeof(right.owned_payload) - right.inline_payload_length);
    (void)memset(
        &left.bound_targets[left.bound_target_count],
        0xa5,
        sizeof(left.bound_targets)
            - left.bound_target_count * sizeof(left.bound_targets[0]));
    (void)memset(
        &right.bound_targets[right.bound_target_count],
        0x5a,
        sizeof(right.bound_targets)
            - right.bound_target_count * sizeof(right.bound_targets[0]));
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &left,
                left_bytes,
                (uint32_t)sizeof(left_bytes),
                &left_length)
        == NINLIL_OK);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &right,
                right_bytes,
                (uint32_t)sizeof(right_bytes),
                &right_length)
        == NINLIL_OK);
    REQUIRE(left_length == right_length);
    REQUIRE(memcmp(left_bytes, right_bytes, left_length) == 0);
    return 0;
}

static void fill_maximum_owned_transaction(
    ninlil_rt_transaction_slot_t *source)
{
    uint32_t index;

    fill_valid_transaction(source);
    source->attempt_count = NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN;
    source->cumulative_attempts = source->attempt_count;
    for (index = 0u; index < source->attempt_count; ++index) {
        set_id(&source->attempt_ids[index], (uint8_t)(0x20u + index));
        source->attempt_target_indices[index] =
            (uint8_t)(index / NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);
    }
    source->attempt_id =
        source->attempt_ids[source->attempt_count - 1u];
    source->active_target_index =
        NINLIL_RT_V1_MAX_TARGETS_PER_TXN - 1u;
    source->retry_budget = 0u;
    set_max_text(&source->service.namespace_id);
    set_max_text(&source->service.service_id);
    set_max_text(&source->service.schema_id);
    source->idempotency_key_length = NINLIL_MAX_IDEMPOTENCY_BYTES;
    (void)memset(
        source->idempotency_key,
        0x6bu,
        sizeof(source->idempotency_key));
    source->application_evidence_length = NINLIL_MAX_EVIDENCE_BYTES;
    (void)memset(
        source->application_evidence,
        0xa5,
        sizeof(source->application_evidence));
    source->payload_length = NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES;
    source->inline_payload_length = NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES;
    (void)memset(
        source->owned_payload, 0x5a, sizeof(source->owned_payload));
    source->bound_target_count = NINLIL_RT_V1_MAX_TARGETS_PER_TXN;
    for (index = 0u; index < source->bound_target_count; ++index) {
        fill_target(
            &source->bound_targets[index],
            (uint8_t)(0x55u + index));
        source->bound_targets[index].retry_budget = 0u;
        source->bound_targets[index].attempt_in_cycle =
            NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
        source->bound_targets[index].cumulative_attempts =
            NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
        source->bound_targets[index].has_late_evidence = 1u;
        source->bound_targets[index].evidence_counter_saturated = 1u;
        source->bound_targets[index].last_evidence_fingerprint_valid = 1u;
        (void)memset(
            source->bound_targets[index]
                .last_evidence_material_fingerprint,
            (int)(0x90u + index),
            sizeof(source->bound_targets[index]
                .last_evidence_material_fingerprint));
        source->bound_targets[index].latest_evidence_ingress_sequence =
            UINT64_MAX;
        source->bound_targets[index].valid_evidence_count = UINT64_MAX;
        source->bound_targets[index].duplicate_evidence_count = UINT64_MAX;
        source->bound_targets[index].raw_evidence_overflow_count =
            UINT64_MAX;
        source->bound_targets[index].late_evidence_count = UINT64_MAX;
        if (index + 1u < source->bound_target_count) {
            source->bound_targets[index].terminal = 1u;
            source->bound_targets[index].pending_dispatch = 0u;
            source->bound_targets[index].delivery_phase =
                NINLIL_RT_DELIVERY_OUTCOME;
            source->bound_targets[index].outcome =
                index == 0u
                ? NINLIL_OUTCOME_SATISFIED
                : NINLIL_OUTCOME_FAILED_DEFINITIVE;
            source->bound_targets[index].reason =
                index == 0u
                ? NINLIL_REASON_REQUIRED_EVIDENCE_MET
                : NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT;
            if (index == 0u) {
                source->bound_targets[index].evidence_recorded = 1u;
                source->bound_targets[index].latest_evidence =
                    NINLIL_EVIDENCE_APPLIED;
                source->bound_targets[index].deadline_verdict =
                    NINLIL_DEADLINE_MET;
            }
        }
    }
    source->bound_targets[source->bound_target_count - 1u]
        .attempt_prepared = 1u;
    source->bound_targets[source->bound_target_count - 1u]
        .active_attempt_id = source->attempt_id;
    source->bound_targets[source->bound_target_count - 1u]
        .delivery_phase = source->delivery_phase;
    source->bound_targets[source->bound_target_count - 1u]
        .reason = source->reason;
    source->bound_targets[source->bound_target_count - 1u]
        .next_retry_ms = source->next_retry_ms;
    source->bound_targets[source->bound_target_count - 1u]
        .next_retry_clock_epoch_id = source->next_retry_clock_epoch_id;
}

static int test_maximum_owned_fields_fit_bounded_record(void)
{
    ninlil_rt_transaction_slot_t source;
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t decoded;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t too_small[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t encoded_length = 0u;

    fill_maximum_owned_transaction(&source);

    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    REQUIRE(encoded_length == 4031u);
    {
        uint32_t too_small_length = UINT32_MAX;

        REQUIRE(ninlil_rt_v1_transaction_record_encode(
                    &source,
                    too_small,
                    encoded_length - 1u,
                    &too_small_length)
            == NINLIL_E_BUFFER_TOO_SMALL);
        REQUIRE(too_small_length == 0u);
    }
    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){encoded, encoded_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.attempt_count
        == NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN);
    REQUIRE(decoded.application_evidence_length
        == NINLIL_MAX_EVIDENCE_BYTES);
    REQUIRE(decoded.payload_length
        == NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES);
    REQUIRE(decoded.inline_payload_length
        == NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES);
    REQUIRE(decoded.bound_target_count
        == NINLIL_RT_V1_MAX_TARGETS_PER_TXN);
    REQUIRE(memcmp(
                decoded.bound_targets[0].mfdt_transfer_id,
                (uint8_t[16]){0u},
                16u)
        == 0);
    REQUIRE(decoded.bound_targets[0].mfdt_target_ordinal == 0u);
    return 0;
}

static int test_mfdt_logical_length_is_not_inline_length(void)
{
    static const uint32_t logical_lengths[] = {927u, 32768u};
    ninlil_rt_transaction_slot_t source;
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t decoded;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t encoded_length;
    uint32_t length_index;

    for (length_index = 0u;
         length_index < sizeof(logical_lengths) / sizeof(logical_lengths[0]);
         ++length_index) {
        fill_valid_transaction(&source);
        source.payload_length = logical_lengths[length_index];
        source.inline_payload_length = 0u;
        source.bearer_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
        (void)memset(
            source.owned_payload, 0, sizeof(source.owned_payload));
        set_mfdt_sender_correlation(&source);
        encoded_length = 0u;
        REQUIRE(ninlil_rt_v1_transaction_record_encode(
                    &source,
                    encoded,
                    (uint32_t)sizeof(encoded),
                    &encoded_length)
            == NINLIL_OK);
        (void)memset(&scratch, 0, sizeof(scratch));
        (void)memset(&decoded, 0, sizeof(decoded));
        REQUIRE(ninlil_rt_v1_transaction_record_decode(
                    (ninlil_bytes_view_t){encoded, encoded_length},
                    &scratch,
                    &decoded)
            == NINLIL_OK);
        REQUIRE(decoded.payload_length == logical_lengths[length_index]);
        REQUIRE(decoded.inline_payload_length == 0u);
        REQUIRE(decoded.bearer_route
            == NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1);
        REQUIRE(memcmp(
                    decoded.owned_payload,
                    source.owned_payload,
                    sizeof(decoded.owned_payload))
            == 0);
    }

    fill_valid_transaction(&source);
    source.inline_payload_length = source.payload_length - 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);

    fill_valid_transaction(&source);
    source.payload_length = NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES;
    source.inline_payload_length = 0u;
    source.bearer_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
    (void)memset(source.owned_payload, 0, sizeof(source.owned_payload));
    set_mfdt_sender_correlation(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);

    source.payload_length = NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES + 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);

    source.payload_length = 927u;
    source.inline_payload_length = 1u;
    source.owned_payload[0] = 0x5au;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);

    fill_valid_transaction(&source);
    source.payload_length = 32768u;
    source.inline_payload_length = 0u;
    source.bearer_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
    (void)memset(source.owned_payload, 0, sizeof(source.owned_payload));
    set_mfdt_sender_correlation(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    for (length_index = 16u; length_index + 8u < encoded_length;
         ++length_index) {
        if (load_u32_be(&encoded[length_index]) == 32768u
            && load_u32_be(&encoded[length_index + 4u]) == 0u) {
            store_u32_be(&encoded[length_index + 4u], 1u);
            refresh_crc(encoded, encoded_length);
            REQUIRE(output_unchanged_after_failure(
                (ninlil_bytes_view_t){encoded, encoded_length},
                NINLIL_E_STORAGE_CORRUPT));
            return 0;
        }
    }
    REQUIRE(0);
    return 1;
}

/*
 * Controller-side EventFact first ingress (origin_admission=0) as produced by
 * commit_received_message_copy for uplink APPLICATION. docs/12 / ADR-0024:
 * product "latest_state" is EventFact; durable encode requires
 * deadline_verdict == NOT_APPLICABLE. Leaving the zero default PENDING is the
 * exact INVALID_ARGUMENT that fails controller runtime_step after wire recv.
 */
static void fill_event_fact_receiver_first_ingress(
    ninlil_rt_transaction_slot_t *snapshot)
{
    (void)memset(snapshot, 0, sizeof(*snapshot));
    snapshot->in_use = 1u;
    snapshot->origin_admission = 0u;
    set_id(&snapshot->transaction_id, 0xc0u);
    set_id(&snapshot->attempt_id, 0x6au);
    set_id(&snapshot->service_app_id, 0x70u);
    set_id(&snapshot->event_id, 0xe7u);
    set_header(
        &snapshot->source.abi_version,
        &snapshot->source.struct_size,
        sizeof(snapshot->source));
    set_id(&snapshot->source.runtime_id, 0x21u);
    set_id(&snapshot->source.application_instance_id, 0x81u);
    set_header(
        &snapshot->source.local_identity.abi_version,
        &snapshot->source.local_identity.struct_size,
        sizeof(snapshot->source.local_identity));
    set_header(
        &snapshot->service.abi_version,
        &snapshot->service.struct_size,
        sizeof(snapshot->service));
    set_text(&snapshot->service.namespace_id, "org.ninlil.examples");
    set_text(&snapshot->service.service_id, "latest-state");
    set_text(&snapshot->service.schema_id, "latest-state");
    snapshot->service.descriptor_revision = 1u;
    set_digest(&snapshot->service.descriptor_digest, 0x31u);
    snapshot->service.schema_major = 1u;
    snapshot->service.family = NINLIL_FAMILY_EVENT_FACT;
    set_digest(&snapshot->content_digest, 0x39u);
    snapshot->family = NINLIL_FAMILY_EVENT_FACT;
    snapshot->required_evidence = NINLIL_EVIDENCE_APPLIED;
    snapshot->deadline_verdict = NINLIL_DEADLINE_NOT_APPLICABLE;
    snapshot->transaction_sequence = 1u;
    snapshot->record_revision = 1u;
    snapshot->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    snapshot->pending_dispatch = 1u;
    snapshot->ingress_pending = 1u;
    snapshot->spool_revision = 1u;
    snapshot->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    snapshot->retry_cycle_id = 1u;
    snapshot->effect_deadline_ms = NINLIL_NO_DEADLINE;
    snapshot->evidence_grace_ms = 0u;
    snapshot->generation = 0u;
    snapshot->semantic_priority = 3u;
    snapshot->bearer_route = 1u;
    snapshot->ordered_input_sequence = 1u;
    set_id(&snapshot->admission_clock_epoch_id, 0xa0u);
    snapshot->admitted_at_ms = 1u;
    snapshot->attempt_receipt_timeout_ms = 1000u;
    snapshot->retry_backoff_ms = 100u;
    snapshot->application_completion_timeout_ms = 60000u;
    snapshot->payload_length = 4u;
    snapshot->inline_payload_length = 4u;
    (void)memcpy(snapshot->owned_payload, "occ", 4u);
    snapshot->bound_target_count = 1u;
    snapshot->bound_targets[0].in_use = 1u;
    snapshot->bound_targets[0].pending_dispatch = 1u;
    set_header(
        &snapshot->bound_targets[0].target.abi_version,
        &snapshot->bound_targets[0].target.struct_size,
        sizeof(snapshot->bound_targets[0].target));
    set_id(&snapshot->bound_targets[0].target.target_runtime_id, 0x10u);
    set_id(
        &snapshot->bound_targets[0].target.target_application_instance_id,
        0x70u);
    set_header(
        &snapshot->assurance.abi_version,
        &snapshot->assurance.struct_size,
        sizeof(snapshot->assurance));
}

static int test_event_fact_receiver_ingress_encode_requires_deadline_na(void)
{
    ninlil_rt_transaction_slot_t snapshot;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t encoded_length = UINT32_MAX;

    fill_event_fact_receiver_first_ingress(&snapshot);
    /*
     * Zero-initialized / PENDING is the pre-fix controller ingress bug:
     * transaction_record_encode fails → runtime_step returns INVALID_ARGUMENT
     * before delivery callback / reverse receipt (scenario7 + lab uplink).
     */
    snapshot.deadline_verdict = NINLIL_DEADLINE_PENDING;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &snapshot,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    snapshot.deadline_verdict = NINLIL_DEADLINE_NOT_APPLICABLE;
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &snapshot,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    REQUIRE(encoded_length > 0u);
    return 0;
}

static int test_nts3_schema12_mfdt_target_correlation(void)
{
    enum {
        NTS3_SCHEMA11_TARGET_BYTES = 289,
        NTS3_MFDT_TARGET_SUFFIX_BYTES = 20,
        NTS3_MFDT_WORST_CASE_BYTES = 3185,
        NTS3_NON_MFDT_WORST_CASE_BYTES = 4031
    };
    ninlil_rt_transaction_slot_t source;
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t decoded;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t mutated[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint8_t too_small[NTS3_MFDT_WORST_CASE_BYTES - 1u];
    uint8_t too_small_before[NTS3_MFDT_WORST_CASE_BYTES - 1u];
    uint32_t suffix_offsets[NINLIL_RT_V1_MAX_TARGETS_PER_TXN];
    uint32_t first_runtime_offset;
    uint32_t first_target_offset;
    uint32_t encoded_length = 0u;
    uint32_t too_small_length = UINT32_MAX;
    uint32_t index;

    fill_maximum_owned_transaction(&source);
    source.payload_length = NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    source.inline_payload_length = 0u;
    source.bearer_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
    (void)memset(source.owned_payload, 0, sizeof(source.owned_payload));
    set_mfdt_sender_correlation(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    REQUIRE(encoded_length == NTS3_MFDT_WORST_CASE_BYTES);
    REQUIRE(encoded[6] == 0u && encoded[7] == 2u);

    (void)memset(too_small, 0xa5, sizeof(too_small));
    (void)memcpy(too_small_before, too_small, sizeof(too_small));
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                too_small,
                (uint32_t)sizeof(too_small),
                &too_small_length)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(too_small_length == 0u);
    REQUIRE(memcmp(too_small, too_small_before, sizeof(too_small)) == 0);

    first_runtime_offset = find_unique_bytes(
        encoded,
        encoded_length,
        source.bound_targets[0].target.target_runtime_id.bytes,
        16u);
    REQUIRE(first_runtime_offset != UINT32_MAX);
    REQUIRE(first_runtime_offset >= 10u);
    first_target_offset = first_runtime_offset - 10u;
    for (index = 0u; index < source.bound_target_count; ++index) {
        uint32_t target_offset = first_target_offset
            + index
                * (NTS3_SCHEMA11_TARGET_BYTES
                    + NTS3_MFDT_TARGET_SUFFIX_BYTES);

        REQUIRE(memcmp(
                    &encoded[target_offset + 10u],
                    source.bound_targets[index].target.target_runtime_id.bytes,
                    16u)
            == 0);
        suffix_offsets[index] = target_offset + NTS3_SCHEMA11_TARGET_BYTES;
        REQUIRE(memcmp(
                    &encoded[suffix_offsets[index]],
                    source.bound_targets[index].mfdt_transfer_id,
                    16u)
            == 0);
        REQUIRE(load_u32_be(&encoded[suffix_offsets[index] + 16u]) == index);
        if (index + 1u < source.bound_target_count) {
            REQUIRE(memcmp(
                        &encoded[suffix_offsets[index]
                            + NTS3_MFDT_TARGET_SUFFIX_BYTES + 10u],
                        source.bound_targets[index + 1u]
                            .target.target_runtime_id.bytes,
                        16u)
                == 0);
        }
    }
    REQUIRE(encoded[suffix_offsets[source.bound_target_count - 1u]
            + NTS3_MFDT_TARGET_SUFFIX_BYTES]
        == source.idempotency_key_length);

    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){encoded, encoded_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    for (index = 0u; index < source.bound_target_count; ++index) {
        REQUIRE(memcmp(
                    decoded.bound_targets[index].mfdt_transfer_id,
                    source.bound_targets[index].mfdt_transfer_id,
                    16u)
            == 0);
        REQUIRE(decoded.bound_targets[index].mfdt_target_ordinal == index);
    }

    source.bound_targets[1].mfdt_target_ordinal = 0u;
    too_small_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &too_small_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(too_small_length == 0u);
    set_mfdt_sender_correlation(&source);
    (void)memset(source.bound_targets[0].mfdt_transfer_id, 0, 16u);
    too_small_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &too_small_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(too_small_length == 0u);

    set_mfdt_sender_correlation(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    (void)memcpy(mutated, encoded, encoded_length);
    store_u32_be(&mutated[suffix_offsets[2] + 16u], 0u);
    refresh_crc(mutated, encoded_length);
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_STORAGE_CORRUPT));
    (void)memcpy(mutated, encoded, encoded_length);
    (void)memset(&mutated[suffix_offsets[0]], 0, 16u);
    refresh_crc(mutated, encoded_length);
    REQUIRE(output_unchanged_after_failure(
        (ninlil_bytes_view_t){mutated, encoded_length},
        NINLIL_E_STORAGE_CORRUPT));

    fill_event_fact_receiver_first_ingress(&source);
    source.payload_length = 927u;
    source.inline_payload_length = 0u;
    source.bearer_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
    (void)memset(source.owned_payload, 0, sizeof(source.owned_payload));
    for (index = 0u; index < 16u; ++index) {
        source.bound_targets[0].mfdt_transfer_id[index] =
            (uint8_t)(0xe0u + index);
    }
    source.bound_targets[0].mfdt_target_ordinal = 3u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){encoded, encoded_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.bound_target_count == 1u);
    REQUIRE(decoded.bound_targets[0].mfdt_target_ordinal == 3u);
    REQUIRE(memcmp(
                decoded.bound_targets[0].mfdt_transfer_id,
                source.bound_targets[0].mfdt_transfer_id,
                16u)
        == 0);
    source.bound_targets[0].mfdt_target_ordinal = 4u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);

    fill_maximum_owned_transaction(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    REQUIRE(encoded_length == NTS3_NON_MFDT_WORST_CASE_BYTES);
    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){encoded, encoded_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    for (index = 0u; index < decoded.bound_target_count; ++index) {
        REQUIRE(memcmp(
                    decoded.bound_targets[index].mfdt_transfer_id,
                    (uint8_t[16]){0u},
                    16u)
            == 0);
        REQUIRE(decoded.bound_targets[index].mfdt_target_ordinal == 0u);
    }
    source.bound_targets[0].mfdt_transfer_id[15] = 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    source.bound_targets[0].mfdt_transfer_id[15] = 0u;
    source.bound_targets[0].mfdt_target_ordinal = 1u;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_nts3_mfdt_initial_multi_target_attempt_history(void)
{
    ninlil_rt_transaction_slot_t source;
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t decoded;
    ninlil_id128_t swap_id;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t encoded_length = UINT32_MAX;

    fill_initial_multi_target_mfdt_transaction(&source);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    (void)memset(&scratch, 0, sizeof(scratch));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_transaction_record_decode(
                (ninlil_bytes_view_t){encoded, encoded_length},
                &scratch,
                &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.active_target_index == 0u);
    REQUIRE(memcmp(
                decoded.attempt_id.bytes,
                decoded.attempt_ids[0].bytes,
                sizeof(decoded.attempt_id.bytes))
        == 0);
    REQUIRE(decoded.attempt_target_indices[0] == 0u);
    REQUIRE(decoded.attempt_target_indices[1] == 1u);

    /* A target-local-consistent reorder must not bypass canonical admission. */
    fill_initial_multi_target_mfdt_transaction(&source);
    swap_id = source.attempt_ids[0];
    source.attempt_ids[0] = source.attempt_ids[1];
    source.attempt_ids[1] = swap_id;
    source.attempt_target_indices[0] = 1u;
    source.attempt_target_indices[1] = 0u;
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_initial_multi_target_mfdt_transaction(&source);
    source.attempt_target_indices[1] = 0u;
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_initial_multi_target_mfdt_transaction(&source);
    source.bound_targets[1].active_attempt_id = source.attempt_ids[0];
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);

    fill_initial_multi_target_mfdt_transaction(&source);
    source.attempt_id = source.attempt_ids[1];
    encoded_length = UINT32_MAX;
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(encoded_length == 0u);
    return 0;
}

static int test_small_marker_codecs(void)
{
    uint8_t reservation[NINLIL_RT_V1_RESERVATION_MARKER_BYTES];
    uint8_t event[NINLIL_RT_V1_EVENT_OPERATION_MARKER_BYTES];
    ninlil_id128_t operation_id;
    uint32_t payload_length = 0u;
    ninlil_rt_v1_bearer_route_t route =
        NINLIL_RT_V1_BEARER_ROUTE_SIMULATED;

    REQUIRE(ninlil_rt_v1_reservation_marker_encode(
                123u, NINLIL_RT_V1_BEARER_ROUTE_U6, reservation)
        == NINLIL_OK);
    REQUIRE(memcmp(reservation, "NRV1", 4u) == 0);
    REQUIRE(reservation[4] == 0u && reservation[5] == 1u);
    REQUIRE(load_u32_be(&reservation[8]) == 123u);
    REQUIRE(reservation[12] == NINLIL_RT_V1_BEARER_ROUTE_U6);
    REQUIRE(ninlil_rt_v1_reservation_marker_decode(
                (ninlil_bytes_view_t){reservation, sizeof(reservation)},
                &payload_length,
                &route)
        == NINLIL_OK);
    REQUIRE(payload_length == 123u);
    REQUIRE(route == NINLIL_RT_V1_BEARER_ROUTE_U6);
    reservation[14] = 1u;
    refresh_crc(reservation, sizeof(reservation));
    payload_length = 456u;
    route = NINLIL_RT_V1_BEARER_ROUTE_SIMULATED;
    REQUIRE(ninlil_rt_v1_reservation_marker_decode(
                (ninlil_bytes_view_t){reservation, sizeof(reservation)},
                &payload_length,
                &route)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(payload_length == 456u);
    REQUIRE(route == NINLIL_RT_V1_BEARER_ROUTE_SIMULATED);

    set_id(&operation_id, 0x77u);
    REQUIRE(ninlil_rt_v1_event_operation_marker_encode(
                NINLIL_RT_V1_EVENT_RESUME_PREFIX,
                &operation_id,
                NINLIL_RESUME_OPERATOR_OVERRIDE,
                9u,
                event)
        == NINLIL_OK);
    REQUIRE(memcmp(event, "NER1", 4u) == 0);
    REQUIRE(ninlil_rt_v1_event_operation_marker_validate(
                NINLIL_RT_V1_EVENT_RESUME_PREFIX,
                (ninlil_bytes_view_t){event, sizeof(event)})
        == NINLIL_OK);
    event[24] = 0xffu;
    refresh_crc(event, sizeof(event));
    REQUIRE(ninlil_rt_v1_event_operation_marker_validate(
                NINLIL_RT_V1_EVENT_RESUME_PREFIX,
                (ninlil_bytes_view_t){event, sizeof(event)})
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

int main(void)
{
    REQUIRE(test_transaction_roundtrip_and_known_bytes() == 0);
    REQUIRE(
        test_transaction_rejects_invalid_semantics_before_encoding() == 0);
    REQUIRE(test_evidence_counter_saturation_shape() == 0);
    REQUIRE(
        test_nts3_delivery_token_matrix_is_shared_by_encode_and_decode() == 0);
    REQUIRE(
        test_transaction_rejects_malformed_without_output_mutation() == 0);
    REQUIRE(test_unused_storage_does_not_change_canonical_bytes() == 0);
    REQUIRE(test_maximum_owned_fields_fit_bounded_record() == 0);
    REQUIRE(test_mfdt_logical_length_is_not_inline_length() == 0);
    REQUIRE(
        test_event_fact_receiver_ingress_encode_requires_deadline_na() == 0);
    REQUIRE(test_nts3_schema12_mfdt_target_correlation() == 0);
    REQUIRE(test_nts3_mfdt_initial_multi_target_attempt_history() == 0);
    REQUIRE(test_small_marker_codecs() == 0);
    (void)fprintf(stderr, "v1_transaction_codec_test ok\n");
    return 0;
}
