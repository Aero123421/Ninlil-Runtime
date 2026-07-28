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
}

static void fill_valid_transaction(ninlil_rt_transaction_slot_t *transaction)
{
    (void)memset(transaction, 0, sizeof(*transaction));
    transaction->in_use = 1u;
    transaction->origin_admission = 1u;
    transaction->has_late_evidence = 1u;
    set_id(&transaction->transaction_id, 0x10u);
    set_id(&transaction->attempt_ids[0], 0x20u);
    set_id(&transaction->attempt_ids[1], 0x30u);
    transaction->attempt_id = transaction->attempt_ids[1];
    transaction->attempt_prepared = 1u;
    transaction->attempt_count = 2u;
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
    transaction->evidence_recorded = 1u;
    transaction->deadline_verdict = NINLIL_DEADLINE_PENDING;
    transaction->transaction_sequence = 42u;
    transaction->record_revision = 7u;
    transaction->reason = NINLIL_REASON_TRANSPORT_RETRY;
    transaction->pending_dispatch = 1u;
    transaction->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    transaction->delivery_count = 0u;
    transaction->token_state = NINLIL_RT_TOKEN_NONE;
    transaction->spool_revision = 0u;
    transaction->retry_budget = 2u;
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
    (void)memcpy(transaction->owned_payload, "ninlil", 6u);
    transaction->semantic_priority = 8u;
    transaction->bearer_route = 1u;
    transaction->reservation_active = 1u;
    transaction->reservation_evidence_units = 4u;
    transaction->admitted_at_ms = 50u;
    transaction->attempt_receipt_timeout_ms = 1000u;
    transaction->retry_backoff_ms = 100u;
    set_id(&transaction->send_observed_clock_epoch_id, 0x45u);
    transaction->send_observed_at_ms = 75u;
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
    REQUIRE(encoded[6] == 0u && encoded[7] == 0u);
    REQUIRE(load_u32_be(&encoded[8]) == encoded_length - 20u);
    REQUIRE(load_u32_be(&encoded[12]) == 0u);
    REQUIRE(load_u32_be(&encoded[encoded_length - 4u])
        == ninlil_model_domain_crc32c(encoded, encoded_length - 4u));
    REQUIRE(encoded_length == 1284u);
    REQUIRE(load_u32_be(&encoded[encoded_length - 4u]) == 0x61448434u);

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
    REQUIRE(decoded.bound_target_count == source.bound_target_count);
    REQUIRE(memcmp(
                decoded.owned_payload,
                source.owned_payload,
                source.payload_length)
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
        &left.owned_payload[left.payload_length],
        0xa5,
        sizeof(left.owned_payload) - left.payload_length);
    (void)memset(
        &right.owned_payload[right.payload_length],
        0x5a,
        sizeof(right.owned_payload) - right.payload_length);
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

static int test_maximum_owned_fields_fit_bounded_record(void)
{
    ninlil_rt_transaction_slot_t source;
    ninlil_rt_transaction_slot_t scratch;
    ninlil_rt_transaction_slot_t decoded;
    uint8_t encoded[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t encoded_length = 0u;
    uint32_t index;

    fill_valid_transaction(&source);
    source.attempt_count = NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN;
    source.cumulative_attempts = source.attempt_count;
    for (index = 0u; index < source.attempt_count; ++index) {
        set_id(&source.attempt_ids[index], (uint8_t)(0x20u + index));
    }
    source.attempt_id =
        source.attempt_ids[source.attempt_count - 1u];
    set_max_text(&source.service.namespace_id);
    set_max_text(&source.service.service_id);
    set_max_text(&source.service.schema_id);
    source.application_evidence_length = NINLIL_MAX_EVIDENCE_BYTES;
    (void)memset(
        source.application_evidence,
        0xa5,
        sizeof(source.application_evidence));
    source.payload_length = NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES;
    (void)memset(
        source.owned_payload, 0x5a, sizeof(source.owned_payload));
    source.bound_target_count = NINLIL_RT_V1_MAX_TARGETS_PER_TXN;
    for (index = 0u; index < source.bound_target_count; ++index) {
        fill_target(
            &source.bound_targets[index],
            (uint8_t)(0x55u + index));
    }

    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &source,
                encoded,
                (uint32_t)sizeof(encoded),
                &encoded_length)
        == NINLIL_OK);
    REQUIRE(encoded_length
        <= NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES);
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
    REQUIRE(decoded.bound_target_count
        == NINLIL_RT_V1_MAX_TARGETS_PER_TXN);
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
    REQUIRE(
        test_nts3_delivery_token_matrix_is_shared_by_encode_and_decode() == 0);
    REQUIRE(
        test_transaction_rejects_malformed_without_output_mutation() == 0);
    REQUIRE(test_unused_storage_does_not_change_canonical_bytes() == 0);
    REQUIRE(test_maximum_owned_fields_fit_bounded_record() == 0);
    REQUIRE(test_small_marker_codecs() == 0);
    (void)fprintf(stderr, "v1_transaction_codec_test ok\n");
    return 0;
}
