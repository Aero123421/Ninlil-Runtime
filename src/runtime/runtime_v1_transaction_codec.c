#include "runtime_v1_transaction_codec.h"

#include "domain_store_codec.h"
#include "runtime_internal.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TX_RECORD_MAGIC_0 0x4eu
#define TX_RECORD_MAGIC_1 0x54u
#define TX_RECORD_MAGIC_2 0x53u
#define TX_RECORD_MAGIC_3 0x33u

typedef struct tx_writer {
    uint8_t *bytes;
    uint32_t capacity;
    uint32_t position;
    uint32_t failed;
} tx_writer_t;

typedef struct tx_reader {
    const uint8_t *bytes;
    uint32_t limit;
    uint32_t position;
    uint32_t failed;
} tx_reader_t;

static void encode_u16_be_at(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void encode_u32_be_at(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint16_t decode_u16_be_at(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t decode_u32_be_at(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24)
        | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8)
        | (uint32_t)in[3];
}

static void writer_bytes(tx_writer_t *writer, const uint8_t *bytes, uint32_t length)
{
    if (writer->failed != 0u
        || length > writer->capacity
        || writer->position > writer->capacity - length
        || (length != 0u && bytes == NULL)) {
        writer->failed = 1u;
        return;
    }
    if (length != 0u) {
        (void)memcpy(&writer->bytes[writer->position], bytes, length);
    }
    writer->position += length;
}

static void writer_u8(tx_writer_t *writer, uint8_t value)
{
    writer_bytes(writer, &value, 1u);
}

static void writer_u16(tx_writer_t *writer, uint16_t value)
{
    uint8_t bytes[2];

    encode_u16_be_at(bytes, value);
    writer_bytes(writer, bytes, sizeof(bytes));
}

static void writer_u32(tx_writer_t *writer, uint32_t value)
{
    uint8_t bytes[4];

    encode_u32_be_at(bytes, value);
    writer_bytes(writer, bytes, sizeof(bytes));
}

static void writer_u64(tx_writer_t *writer, uint64_t value)
{
    uint8_t bytes[8];

    bytes[0] = (uint8_t)(value >> 56);
    bytes[1] = (uint8_t)(value >> 48);
    bytes[2] = (uint8_t)(value >> 40);
    bytes[3] = (uint8_t)(value >> 32);
    bytes[4] = (uint8_t)(value >> 24);
    bytes[5] = (uint8_t)(value >> 16);
    bytes[6] = (uint8_t)(value >> 8);
    bytes[7] = (uint8_t)value;
    writer_bytes(writer, bytes, sizeof(bytes));
}

static void reader_bytes(tx_reader_t *reader, uint8_t *out, uint32_t length)
{
    if (reader->failed != 0u
        || length > reader->limit
        || reader->position > reader->limit - length
        || (length != 0u && out == NULL)) {
        reader->failed = 1u;
        return;
    }
    if (length != 0u) {
        (void)memcpy(out, &reader->bytes[reader->position], length);
    }
    reader->position += length;
}

static uint8_t reader_u8(tx_reader_t *reader)
{
    uint8_t value = 0u;

    reader_bytes(reader, &value, 1u);
    return value;
}

static uint16_t reader_u16(tx_reader_t *reader)
{
    uint8_t bytes[2] = {0u, 0u};

    reader_bytes(reader, bytes, sizeof(bytes));
    return decode_u16_be_at(bytes);
}

static uint32_t reader_u32(tx_reader_t *reader)
{
    uint8_t bytes[4] = {0u, 0u, 0u, 0u};

    reader_bytes(reader, bytes, sizeof(bytes));
    return decode_u32_be_at(bytes);
}

static uint64_t reader_u64(tx_reader_t *reader)
{
    uint8_t bytes[8] = {0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u};

    reader_bytes(reader, bytes, sizeof(bytes));
    return ((uint64_t)bytes[0] << 56)
        | ((uint64_t)bytes[1] << 48)
        | ((uint64_t)bytes[2] << 40)
        | ((uint64_t)bytes[3] << 32)
        | ((uint64_t)bytes[4] << 24)
        | ((uint64_t)bytes[5] << 16)
        | ((uint64_t)bytes[6] << 8)
        | (uint64_t)bytes[7];
}

static void writer_id(tx_writer_t *writer, const ninlil_id128_t *id)
{
    writer_bytes(writer, id->bytes, sizeof(id->bytes));
}

static void reader_id(tx_reader_t *reader, ninlil_id128_t *id)
{
    reader_bytes(reader, id->bytes, sizeof(id->bytes));
}

static void writer_digest(tx_writer_t *writer, const ninlil_digest256_t *digest)
{
    writer_u16(writer, digest->algorithm);
    writer_bytes(writer, digest->bytes, sizeof(digest->bytes));
}

static void reader_digest(tx_reader_t *reader, ninlil_digest256_t *digest)
{
    digest->algorithm = reader_u16(reader);
    digest->reserved_zero = 0u;
    reader_bytes(reader, digest->bytes, sizeof(digest->bytes));
}

static void writer_text_id(tx_writer_t *writer, const ninlil_text_id_t *text)
{
    writer_u8(writer, text->length);
    writer_bytes(writer, text->bytes, text->length);
}

static void reader_text_id(tx_reader_t *reader, ninlil_text_id_t *text)
{
    uint8_t length = reader_u8(reader);

    if (length > NINLIL_MAX_TEXT_ID_BYTES) {
        reader->failed = 1u;
        return;
    }
    text->length = length;
    reader_bytes(reader, text->bytes, length);
}

static void writer_local_identity(
    tx_writer_t *writer,
    const ninlil_local_identity_t *identity)
{
    writer_id(writer, &identity->device_id);
    writer_id(writer, &identity->installation_id);
    writer_id(writer, &identity->site_domain_id);
    writer_u64(writer, identity->binding_epoch);
    writer_u64(writer, identity->membership_epoch);
    writer_u32(writer, identity->flags);
}

static void reader_local_identity(
    tx_reader_t *reader,
    ninlil_local_identity_t *identity)
{
    identity->abi_version = NINLIL_ABI_VERSION;
    identity->struct_size = (uint16_t)sizeof(*identity);
    reader_id(reader, &identity->device_id);
    reader_id(reader, &identity->installation_id);
    reader_id(reader, &identity->site_domain_id);
    identity->binding_epoch = reader_u64(reader);
    identity->membership_epoch = reader_u64(reader);
    identity->flags = reader_u32(reader);
    identity->reserved_zero = 0u;
}

static void writer_party(tx_writer_t *writer, const ninlil_party_t *party)
{
    writer_id(writer, &party->runtime_id);
    writer_id(writer, &party->application_instance_id);
    writer_local_identity(writer, &party->local_identity);
}

static void reader_party(tx_reader_t *reader, ninlil_party_t *party)
{
    party->abi_version = NINLIL_ABI_VERSION;
    party->struct_size = (uint16_t)sizeof(*party);
    reader_id(reader, &party->runtime_id);
    reader_id(reader, &party->application_instance_id);
    reader_local_identity(reader, &party->local_identity);
}

static void writer_service(
    tx_writer_t *writer,
    const ninlil_service_identity_t *service)
{
    writer_text_id(writer, &service->namespace_id);
    writer_text_id(writer, &service->service_id);
    writer_text_id(writer, &service->schema_id);
    writer_u64(writer, service->descriptor_revision);
    writer_digest(writer, &service->descriptor_digest);
    writer_u16(writer, service->schema_major);
    writer_u16(writer, service->schema_minor);
    writer_u32(writer, service->family);
}

static void reader_service(
    tx_reader_t *reader,
    ninlil_service_identity_t *service)
{
    service->abi_version = NINLIL_ABI_VERSION;
    service->struct_size = (uint16_t)sizeof(*service);
    reader_text_id(reader, &service->namespace_id);
    reader_text_id(reader, &service->service_id);
    reader_text_id(reader, &service->schema_id);
    service->descriptor_revision = reader_u64(reader);
    reader_digest(reader, &service->descriptor_digest);
    service->schema_major = reader_u16(reader);
    service->schema_minor = reader_u16(reader);
    service->family = reader_u32(reader);
}

static void writer_target(
    tx_writer_t *writer,
    const ninlil_rt_target_slot_t *slot)
{
    writer_u8(writer, slot->in_use);
    writer_u8(writer, slot->evidence_recorded);
    writer_u8(writer, slot->pending_dispatch);
    writer_id(writer, &slot->target.target_runtime_id);
    writer_id(writer, &slot->target.target_application_instance_id);
    writer_id(writer, &slot->target.device_id);
    writer_id(writer, &slot->target.installation_id);
    writer_id(writer, &slot->target.site_domain_id);
    writer_u64(writer, slot->target.binding_epoch);
    writer_u64(writer, slot->target.membership_epoch);
    writer_u32(writer, slot->target.flags);
    writer_u32(writer, slot->outcome);
    writer_u32(writer, slot->reason);
}

static void reader_target(
    tx_reader_t *reader,
    ninlil_rt_target_slot_t *slot)
{
    slot->in_use = reader_u8(reader);
    slot->evidence_recorded = reader_u8(reader);
    slot->pending_dispatch = reader_u8(reader);
    slot->reserved_zero = 0u;
    slot->target.abi_version = NINLIL_ABI_VERSION;
    slot->target.struct_size = (uint16_t)sizeof(slot->target);
    reader_id(reader, &slot->target.target_runtime_id);
    reader_id(reader, &slot->target.target_application_instance_id);
    reader_id(reader, &slot->target.device_id);
    reader_id(reader, &slot->target.installation_id);
    reader_id(reader, &slot->target.site_domain_id);
    slot->target.binding_epoch = reader_u64(reader);
    slot->target.membership_epoch = reader_u64(reader);
    slot->target.flags = reader_u32(reader);
    slot->target.reserved_zero = 0u;
    slot->outcome = reader_u32(reader);
    slot->reason = reader_u32(reader);
}

static void writer_retry_summary(
    tx_writer_t *writer,
    const ninlil_rt_event_retry_summary_t *summary)
{
    writer_u64(writer, summary->retry_cycle_id);
    writer_u32(writer, summary->attempt_count);
    writer_u32(writer, summary->delivery_possible_any);
    writer_u32(writer, summary->last_reason);
    writer_id(writer, &summary->last_observed_clock_epoch_id);
    writer_u64(writer, summary->last_observed_at_ms);
}

static void reader_retry_summary(
    tx_reader_t *reader,
    ninlil_rt_event_retry_summary_t *summary)
{
    summary->retry_cycle_id = reader_u64(reader);
    summary->attempt_count = reader_u32(reader);
    summary->delivery_possible_any = reader_u32(reader);
    summary->last_reason = reader_u32(reader);
    summary->reserved_zero = 0u;
    reader_id(reader, &summary->last_observed_clock_epoch_id);
    summary->last_observed_at_ms = reader_u64(reader);
}

static void writer_assurance(
    tx_writer_t *writer,
    const ninlil_admission_assurance_t *assurance)
{
    writer_u32(writer, assurance->assurance_profile);
    writer_u32(writer, assurance->submission_validated);
    writer_u32(writer, assurance->target_roster_fixed);
    writer_u32(writer, assurance->descriptor_snapshot_fixed);
    writer_u32(writer, assurance->local_journal_committed);
    writer_u32(writer, assurance->local_capacity_reserved);
    writer_u32(writer, assurance->idempotency_mapping_committed);
    writer_u32(writer, assurance->origin_grant_snapshot_committed);
    writer_u32(writer, assurance->remote_capacity_reserved);
    writer_u32(writer, assurance->route_feasibility_verified);
    writer_u32(writer, assurance->receive_window_reserved);
    writer_u32(writer, assurance->bearer_capacity_reserved);
    writer_u32(writer, assurance->airtime_reserved);
    writer_u32(writer, assurance->compliance_permit_issued);
}

static void reader_assurance(
    tx_reader_t *reader,
    ninlil_admission_assurance_t *assurance)
{
    assurance->abi_version = NINLIL_ABI_VERSION;
    assurance->struct_size = (uint16_t)sizeof(*assurance);
    assurance->assurance_profile = reader_u32(reader);
    assurance->submission_validated = reader_u32(reader);
    assurance->target_roster_fixed = reader_u32(reader);
    assurance->descriptor_snapshot_fixed = reader_u32(reader);
    assurance->local_journal_committed = reader_u32(reader);
    assurance->local_capacity_reserved = reader_u32(reader);
    assurance->idempotency_mapping_committed = reader_u32(reader);
    assurance->origin_grant_snapshot_committed = reader_u32(reader);
    assurance->remote_capacity_reserved = reader_u32(reader);
    assurance->route_feasibility_verified = reader_u32(reader);
    assurance->receive_window_reserved = reader_u32(reader);
    assurance->bearer_capacity_reserved = reader_u32(reader);
    assurance->airtime_reserved = reader_u32(reader);
    assurance->compliance_permit_issued = reader_u32(reader);
    assurance->reserved_zero = 0u;
}

static int boolean_u32(uint32_t value)
{
    return value <= 1u;
}

static int family_valid(ninlil_family_t family)
{
    switch (family) {
    case NINLIL_FAMILY_EVENT_FACT:
    case NINLIL_FAMILY_DESIRED_STATE:
    case NINLIL_FAMILY_LATEST_STATE_RESERVED:
    case NINLIL_FAMILY_MEASUREMENT_RESERVED:
    case NINLIL_FAMILY_TRANSFER_RESERVED:
    case NINLIL_FAMILY_CONFIG_RESERVED:
    case NINLIL_FAMILY_NETWORK_CONTROL_RESERVED:
        return 1;
    default:
        return 0;
    }
}

static int reason_valid(ninlil_reason_t reason)
{
    switch (reason) {
    case NINLIL_REASON_NONE:
    case NINLIL_REASON_UNSUPPORTED_FAMILY:
    case NINLIL_REASON_UNSUPPORTED_SELECTOR:
    case NINLIL_REASON_TARGET_COUNT_UNSUPPORTED:
    case NINLIL_REASON_INVALID_SCHEMA:
    case NINLIL_REASON_INVALID_PAYLOAD_LENGTH:
    case NINLIL_REASON_INVALID_CONTENT_DIGEST:
    case NINLIL_REASON_DEADLINE_INVALID:
    case NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED:
    case NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID:
    case NINLIL_REASON_EVIDENCE_UNSUPPORTED:
    case NINLIL_REASON_CAPACITY_EXHAUSTED:
    case NINLIL_REASON_MODIFICATION_REQUIRED:
    case NINLIL_REASON_IDEMPOTENCY_CONFLICT:
    case NINLIL_REASON_GRANT_INVALID:
    case NINLIL_REASON_GRANT_EXPIRED:
    case NINLIL_REASON_GRANT_LIMIT_EXCEEDED:
    case NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE:
    case NINLIL_REASON_STORAGE_IO:
    case NINLIL_REASON_STORAGE_COMMIT_UNKNOWN:
    case NINLIL_REASON_CLOCK_UNCERTAIN:
    case NINLIL_REASON_RATE_EXHAUSTED:
    case NINLIL_REASON_TARGET_UNAUTHORIZED:
    case NINLIL_REASON_CALLBACK_CONTRACT:
    case NINLIL_REASON_UNSUPPORTED_DIRECTION:
    case NINLIL_REASON_REQUIRED_EVIDENCE_MET:
    case NINLIL_REASON_REQUIRED_EVIDENCE_LATE:
    case NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH:
    case NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING:
    case NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING:
    case NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT:
    case NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED:
    case NINLIL_REASON_EVENT_RECEIPT_TIMEOUT:
    case NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT:
    case NINLIL_REASON_BEARER_UNAVAILABLE:
    case NINLIL_REASON_CAPACITY_UNAVAILABLE:
    case NINLIL_REASON_COUNTER_EXHAUSTED:
    case NINLIL_REASON_STALE_AVAILABILITY_EPOCH:
    case NINLIL_REASON_RESUME_CONFLICT:
    case NINLIL_REASON_STALE_SPOOL_REVISION:
    case NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT:
    case NINLIL_REASON_DISCARD_CONFLICT:
    case NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH:
    case NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE:
    case NINLIL_REASON_EVENT_FACT_IMMUTABLE:
    case NINLIL_REASON_TRANSPORT_RETRY:
    case NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE:
    case NINLIL_REASON_APPLICATION_FAILED:
    case NINLIL_REASON_OUTCOME_UNKNOWN:
    case NINLIL_REASON_RECEIVER_UNAVAILABLE:
    case NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT:
    case NINLIL_REASON_RECONCILE_RETRY_LATER:
    case NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION:
    case NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT:
        return 1;
    default:
        return 0;
    }
}

static int evidence_valid(ninlil_evidence_stage_t value)
{
    switch (value) {
    case NINLIL_EVIDENCE_NONE:
    case NINLIL_EVIDENCE_RECEIVED:
    case NINLIL_EVIDENCE_DURABLY_RECORDED:
    case NINLIL_EVIDENCE_APPLIED:
    case NINLIL_EVIDENCE_VERIFIED:
        return 1;
    default:
        return 0;
    }
}

static int application_result_kind_valid(
    ninlil_application_result_kind_t value)
{
    return value == 0u
        || value == NINLIL_APP_RESULT_POSITIVE_EVIDENCE
        || value == NINLIL_APP_RESULT_DISPOSITION;
}

static int disposition_valid(ninlil_disposition_t value)
{
    switch (value) {
    case NINLIL_DISPOSITION_NONE:
    case NINLIL_DISPOSITION_RETRY_LATER:
    case NINLIL_DISPOSITION_INVALID_PAYLOAD:
    case NINLIL_DISPOSITION_UNSUPPORTED_SCHEMA:
    case NINLIL_DISPOSITION_UNAUTHORIZED_SERVICE:
    case NINLIL_DISPOSITION_STALE_NOT_APPLIED:
    case NINLIL_DISPOSITION_APPLICATION_BUSY:
    case NINLIL_DISPOSITION_APPLY_FAILED:
    case NINLIL_DISPOSITION_VERIFY_FAILED:
    case NINLIL_DISPOSITION_CAPACITY_EXHAUSTED:
    case NINLIL_DISPOSITION_OUTCOME_UNKNOWN:
        return 1;
    default:
        return 0;
    }
}

static int effect_certainty_valid(ninlil_effect_certainty_t value)
{
    return value == NINLIL_EFFECT_CERTAINTY_NONE
        || value == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
        || value == NINLIL_EFFECT_CERTAINTY_POSSIBLE;
}

static int retry_guidance_valid(ninlil_retry_guidance_t value)
{
    return value == NINLIL_RETRY_NEVER
        || value == NINLIL_RETRY_SAME_AFTER
        || value == NINLIL_RETRY_MODIFIED
        || value == NINLIL_RETRY_OPERATOR_ACTION;
}

static int deadline_verdict_valid(ninlil_deadline_verdict_t value)
{
    return value == NINLIL_DEADLINE_PENDING
        || value == NINLIL_DEADLINE_MET
        || value == NINLIL_DEADLINE_MISSED
        || value == NINLIL_DEADLINE_INDETERMINATE
        || value == NINLIL_DEADLINE_NOT_APPLICABLE;
}

static int cancel_kind_valid(ninlil_cancel_kind_t value)
{
    return value == 0u
        || value == NINLIL_CANCEL_FENCED_BEFORE_DISPATCH
        || value == NINLIL_CANCEL_PENDING_REMOTE_FENCE
        || value == NINLIL_CANCEL_TOO_LATE_EFFECT_POSSIBLE
        || value == NINLIL_CANCEL_ALREADY_TERMINAL;
}

static int outcome_valid(ninlil_outcome_t value)
{
    return value == NINLIL_OUTCOME_NONE
        || value == NINLIL_OUTCOME_SATISFIED
        || value == NINLIL_OUTCOME_EXPIRED
        || value == NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT
        || value == NINLIL_OUTCOME_FAILED_DEFINITIVE
        || value == NINLIL_OUTCOME_UNKNOWN
        || value == NINLIL_OUTCOME_SUPERSEDED_RESERVED;
}

static int delivery_phase_valid(ninlil_rt_delivery_phase_t value)
{
    return value == NINLIL_RT_DELIVERY_NONE
        || value == NINLIL_RT_DELIVERY_QUEUED
        || value == NINLIL_RT_DELIVERY_STARTED
        || value == NINLIL_RT_DELIVERY_EVIDENCED
        || value == NINLIL_RT_DELIVERY_OUTCOME
        || value == NINLIL_RT_DELIVERY_PARKED
        || value == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED;
}

static int token_state_valid(ninlil_rt_token_state_t value)
{
    return value == NINLIL_RT_TOKEN_NONE
        || value == NINLIL_RT_TOKEN_ACTIVE
        || value == NINLIL_RT_TOKEN_CONSUMED
        || value == NINLIL_RT_TOKEN_EXPIRED
        || value == NINLIL_RT_TOKEN_RECOVERY_REQUIRED;
}

static int event_park_cause_valid(ninlil_event_park_cause_t value)
{
    return value == NINLIL_EVENT_PARK_CAUSE_NONE
        || value == NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT
        || value == NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE
        || value == NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLE
        || value == NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATION
        || value == NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED;
}

static int bearer_route_valid(uint8_t value)
{
    return value == 1u || value == 2u;
}

static int digest_valid(const ninlil_digest256_t *digest)
{
    uint32_t index;
    int nonzero = 0;

    if (digest->reserved_zero != 0u
        || digest->algorithm != NINLIL_DIGEST_SHA256) {
        return 0;
    }
    for (index = 0u; index < sizeof(digest->bytes); ++index) {
        if (digest->bytes[index] != 0u) {
            nonzero = 1;
        }
    }
    return nonzero;
}

static int id_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int id_zero(const ninlil_id128_t *id)
{
    return !id_nonzero(id);
}

/*
 * NTS3 persists only callback-stable truth.  deferred_wait is deliberately
 * process-local; every durable token row carries the closed N/timer tuple.
 */
static int delivery_token_tuple_valid(
    const ninlil_rt_transaction_slot_t *transaction)
{
    const uint64_t n = transaction->delivery_count;
    const int none = transaction->token_state == NINLIL_RT_TOKEN_NONE;
    const int active =
        transaction->token_state == NINLIL_RT_TOKEN_ACTIVE;
    const int consumed =
        transaction->token_state == NINLIL_RT_TOKEN_CONSUMED;
    const int expired =
        transaction->token_state == NINLIL_RT_TOKEN_EXPIRED;
    const int recovery =
        transaction->token_state
            == NINLIL_RT_TOKEN_RECOVERY_REQUIRED;

    if (transaction->deferred_wait != 0u
        || transaction->token_generation != n) {
        return 0;
    }
    if (none) {
        return n == 0u
            && id_zero(&transaction->token_clock_epoch_id)
            && transaction->delivery_started_at_ms == 0u
            && transaction->token_expires_at_ms == 0u
            /*
             * Locally-originated send state does not issue an application
             * callback token.  Inbound NONE is restricted to pre-callback
             * queue/park states.
             */
            && (transaction->origin_admission != 0u
                || transaction->delivery_phase
                    == NINLIL_RT_DELIVERY_NONE
                || transaction->delivery_phase
                    == NINLIL_RT_DELIVERY_QUEUED
                || transaction->delivery_phase
                    == NINLIL_RT_DELIVERY_PARKED);
    }
    if (n == 0u || !(active || consumed || expired || recovery)
        || !id_nonzero(&transaction->token_clock_epoch_id)
        || transaction->application_completion_timeout_ms == 0u
        || transaction->application_completion_timeout_ms
            > NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS
        || transaction->delivery_started_at_ms
            > UINT64_MAX
                - transaction->application_completion_timeout_ms
        || transaction->token_expires_at_ms
            != transaction->delivery_started_at_ms
                + transaction->application_completion_timeout_ms) {
        return 0;
    }
    if (active) {
        return transaction->origin_admission == 0u
            && transaction->delivery_phase
                == NINLIL_RT_DELIVERY_STARTED;
    }
    if (expired || recovery) {
        return transaction->origin_admission == 0u
            && transaction->delivery_phase
                == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED;
    }
    if (transaction->origin_admission != 0u) {
        return 0;
    }
    if (transaction->delivery_phase == NINLIL_RT_DELIVERY_QUEUED) {
        return transaction->application_result_kind == 0u
            && transaction->application_evidence_length == 0u
            && transaction->evidence_recorded == 0u
            && transaction->outcome_recorded == 0u
            && transaction->outcome == NINLIL_OUTCOME_NONE;
    }
    return transaction->delivery_phase == NINLIL_RT_DELIVERY_EVIDENCED
        || transaction->delivery_phase == NINLIL_RT_DELIVERY_OUTCOME;
}

static int event_retry_history_valid(
    const ninlil_rt_transaction_slot_t *transaction)
{
    uint64_t represented_attempts = transaction->attempt_in_cycle;
    uint64_t expected_cycle_id;
    uint32_t index;

    if (transaction->retry_summary_count
            > NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS
        || transaction->attempt_in_cycle
            > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || transaction->attempt_in_cycle != transaction->attempt_count
        || transaction->older_retry_delivery_possible_any > 1u
        || !reason_valid(transaction->older_retry_last_reason)) {
        return 0;
    }
    if (transaction->older_retry_cycle_count == 0u) {
        if (transaction->older_retry_attempt_count != 0u
            || transaction->older_retry_delivery_possible_any != 0u
            || transaction->older_retry_last_reason != NINLIL_REASON_NONE
            || id_nonzero(
                &transaction->older_retry_last_observed_clock_epoch_id)
            || transaction->older_retry_last_observed_at_ms != 0u) {
            return 0;
        }
    } else if (transaction->older_retry_cycle_count > UINT64_MAX - 1u) {
        return 0;
    }
    expected_cycle_id = transaction->older_retry_cycle_count + 1u;
    represented_attempts += transaction->older_retry_attempt_count;
    for (index = 0u; index < NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS; ++index) {
        const ninlil_rt_event_retry_summary_t *summary =
            &transaction->retry_summaries[index];

        if (index >= transaction->retry_summary_count) {
            if (summary->retry_cycle_id != 0u
                || summary->attempt_count != 0u
                || summary->delivery_possible_any != 0u
                || summary->last_reason != NINLIL_REASON_NONE
                || summary->reserved_zero != 0u
                || id_nonzero(&summary->last_observed_clock_epoch_id)
                || summary->last_observed_at_ms != 0u) {
                return 0;
            }
            continue;
        }
        if (summary->retry_cycle_id != expected_cycle_id
            || summary->attempt_count
                > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
            || summary->delivery_possible_any > 1u
            || !reason_valid(summary->last_reason)
            || summary->reserved_zero != 0u
            || represented_attempts
                > UINT64_MAX - summary->attempt_count) {
            return 0;
        }
        represented_attempts += summary->attempt_count;
        expected_cycle_id += 1u;
    }
    return transaction->retry_cycle_id == expected_cycle_id
        && transaction->resume_op_count < transaction->retry_cycle_id
        && represented_attempts == transaction->cumulative_attempts;
}

static int family_retry_history_valid(
    const ninlil_rt_transaction_slot_t *transaction)
{
    uint32_t index;

    if (transaction->retry_budget
        > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE) {
        return 0;
    }
    if (transaction->family == NINLIL_FAMILY_EVENT_FACT) {
        return transaction->retry_cycle_id != 0u
            && event_retry_history_valid(transaction);
    }
    for (index = 0u;
         index < NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS;
         ++index) {
        const ninlil_rt_event_retry_summary_t *summary =
            &transaction->retry_summaries[index];

        if (summary->retry_cycle_id != 0u
            || summary->attempt_count != 0u
            || summary->delivery_possible_any != 0u
            || summary->last_reason != NINLIL_REASON_NONE
            || summary->reserved_zero != 0u
            || id_nonzero(&summary->last_observed_clock_epoch_id)
            || summary->last_observed_at_ms != 0u) {
            return 0;
        }
    }
    return transaction->retry_cycle_id == 0u
        && transaction->attempt_in_cycle == 0u
        && transaction->retry_summary_count == 0u
        && transaction->older_retry_cycle_count == 0u
        && transaction->older_retry_attempt_count == 0u
        && transaction->older_retry_delivery_possible_any == 0u
        && transaction->older_retry_last_reason == NINLIL_REASON_NONE
        && !id_nonzero(
            &transaction->older_retry_last_observed_clock_epoch_id)
        && transaction->older_retry_last_observed_at_ms == 0u
        && transaction->cumulative_attempts == transaction->attempt_count;
}

static int header_current(uint16_t abi_version, uint16_t struct_size, size_t size)
{
    return abi_version == NINLIL_ABI_VERSION
        && (size_t)struct_size >= size;
}

static int text_id_valid(const ninlil_text_id_t *text, int namespace_grammar)
{
    uint32_t index;

    if (text->length == 0u || text->length > sizeof(text->bytes)
        || !((text->bytes[0] >= (uint8_t)'a'
                && text->bytes[0] <= (uint8_t)'z')
            || (text->bytes[0] >= (uint8_t)'0'
                && text->bytes[0] <= (uint8_t)'9'))) {
        return 0;
    }
    for (index = 1u; index < text->length; ++index) {
        uint8_t value = text->bytes[index];
        int lower_or_digit =
            (value >= (uint8_t)'a' && value <= (uint8_t)'z')
            || (value >= (uint8_t)'0' && value <= (uint8_t)'9');

        if (!lower_or_digit && value != (uint8_t)'.'
            && value != (uint8_t)'-'
            && (namespace_grammar != 0 || value != (uint8_t)'_')) {
            return 0;
        }
    }
    return 1;
}

static int identity_presence_valid(
    uint32_t flags,
    const ninlil_id128_t *device,
    const ninlil_id128_t *installation,
    const ninlil_id128_t *site,
    uint64_t binding_epoch,
    uint64_t membership_epoch)
{
    int has_device = (flags & NINLIL_TARGET_HAS_DEVICE) != 0u;
    int has_installation =
        (flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u;
    int has_site = (flags & NINLIL_TARGET_HAS_SITE) != 0u;

    return (flags
            & ~(NINLIL_TARGET_HAS_DEVICE
                | NINLIL_TARGET_HAS_INSTALLATION
                | NINLIL_TARGET_HAS_SITE)) == 0u
        && id_nonzero(device) == has_device
        && id_nonzero(installation) == has_installation
        && id_nonzero(site) == has_site
        && (binding_epoch != 0u) == (has_device || has_installation)
        && (membership_epoch != 0u) == has_site;
}

static int party_valid(const ninlil_party_t *party)
{
    return header_current(
            party->abi_version, party->struct_size, sizeof(*party))
        && id_nonzero(&party->runtime_id)
        && id_nonzero(&party->application_instance_id)
        && header_current(
            party->local_identity.abi_version,
            party->local_identity.struct_size,
            sizeof(party->local_identity))
        && party->local_identity.reserved_zero == 0u
        && identity_presence_valid(
            party->local_identity.flags,
            &party->local_identity.device_id,
            &party->local_identity.installation_id,
            &party->local_identity.site_domain_id,
            party->local_identity.binding_epoch,
            party->local_identity.membership_epoch);
}

static int service_valid(const ninlil_service_identity_t *service)
{
    return header_current(
            service->abi_version, service->struct_size, sizeof(*service))
        && text_id_valid(&service->namespace_id, 1)
        && text_id_valid(&service->service_id, 0)
        && text_id_valid(&service->schema_id, 0)
        && service->descriptor_revision != 0u
        && digest_valid(&service->descriptor_digest)
        && service->schema_major != 0u
        && family_valid(service->family);
}

static int family_semantics_valid(
    const ninlil_rt_transaction_slot_t *transaction)
{
    if (transaction->has_late_evidence != 0u
        && (transaction->evidence_recorded == 0u
            || transaction->latest_evidence == NINLIL_EVIDENCE_NONE)) {
        return 0;
    }
    if (transaction->family == NINLIL_FAMILY_EVENT_FACT) {
        return id_nonzero(&transaction->event_id)
            && transaction->generation == 0u
            && !id_nonzero(&transaction->deadline_clock_epoch_id)
            && transaction->effect_deadline_ms == NINLIL_NO_DEADLINE
            && transaction->evidence_grace_ms == 0u
            && transaction->deadline_verdict
                == NINLIL_DEADLINE_NOT_APPLICABLE
            && transaction->cancel_kind == 0u
            && transaction->spool_revision != 0u
            && (transaction->delivery_phase
                    == NINLIL_RT_DELIVERY_PARKED
                ? transaction->event_park_cause
                    != NINLIL_EVENT_PARK_CAUSE_NONE
                : transaction->event_park_cause
                    == NINLIL_EVENT_PARK_CAUSE_NONE)
            && transaction->outcome != NINLIL_OUTCOME_EXPIRED
            && transaction->outcome
                != NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT
            && transaction->outcome
                != NINLIL_OUTCOME_SUPERSEDED_RESERVED
            && (transaction->event_discarded == 0u
                || (transaction->terminal != 0u
                    && transaction->outcome
                        == NINLIL_OUTCOME_FAILED_DEFINITIVE
                    && transaction->reason
                        == NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT))
            && (transaction->resume_op_count == 0u
                ? !id_nonzero(&transaction->last_resume_operation_id)
                : id_nonzero(&transaction->last_resume_operation_id));
    }
    if (transaction->family == NINLIL_FAMILY_DESIRED_STATE) {
        return !id_nonzero(&transaction->event_id)
            && transaction->generation != 0u
            && id_nonzero(&transaction->deadline_clock_epoch_id)
            && transaction->effect_deadline_ms != 0u
            && transaction->effect_deadline_ms < NINLIL_NO_DEADLINE
            && transaction->deadline_verdict
                != NINLIL_DEADLINE_NOT_APPLICABLE
            && transaction->spool_revision == 0u
            && transaction->event_park_cause
                == NINLIL_EVENT_PARK_CAUSE_NONE
            && transaction->event_discarded == 0u
            && transaction->resume_op_count == 0u
            && !id_nonzero(&transaction->last_resume_operation_id)
            && transaction->outcome
                != NINLIL_OUTCOME_SUPERSEDED_RESERVED;
    }
    /*
     * Reserved post-M1a families retain their separately specified family
     * contracts.  This codec closes the two Foundation families without
     * inventing semantics for those reserved values.
     */
    return transaction->spool_revision == 0u
        && transaction->event_park_cause == NINLIL_EVENT_PARK_CAUSE_NONE
        && transaction->event_discarded == 0u
        && transaction->resume_op_count == 0u
        && !id_nonzero(&transaction->last_resume_operation_id);
}

static int attempt_history_valid(
    const ninlil_rt_transaction_slot_t *transaction)
{
    uint32_t left;
    uint32_t right;

    if (transaction->origin_admission == 0u
        && transaction->attempt_prepared == 0u
        && transaction->attempt_count == 0u) {
        return id_nonzero(&transaction->attempt_id);
    }
    for (left = 0u; left < transaction->attempt_count; ++left) {
        if (!id_nonzero(&transaction->attempt_ids[left])) {
            return 0;
        }
        for (right = left + 1u;
             right < transaction->attempt_count;
             ++right) {
            if (memcmp(
                    transaction->attempt_ids[left].bytes,
                    transaction->attempt_ids[right].bytes,
                    sizeof(transaction->attempt_ids[left].bytes)) == 0) {
                return 0;
            }
        }
    }
    if (transaction->attempt_prepared != 0u) {
        return transaction->attempt_count != 0u
            && id_nonzero(&transaction->attempt_id)
            && memcmp(
                transaction->attempt_id.bytes,
                transaction->attempt_ids[
                    transaction->attempt_count - 1u].bytes,
                sizeof(transaction->attempt_id.bytes)) == 0;
    }
    return !id_nonzero(&transaction->attempt_id);
}

static int assurance_valid(const ninlil_admission_assurance_t *assurance)
{
    return (assurance->assurance_profile == NINLIL_ASSURANCE_NONE
            || assurance->assurance_profile
                == NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL)
        && boolean_u32(assurance->submission_validated)
        && boolean_u32(assurance->target_roster_fixed)
        && boolean_u32(assurance->descriptor_snapshot_fixed)
        && boolean_u32(assurance->local_journal_committed)
        && boolean_u32(assurance->local_capacity_reserved)
        && boolean_u32(assurance->idempotency_mapping_committed)
        && boolean_u32(assurance->origin_grant_snapshot_committed)
        && boolean_u32(assurance->remote_capacity_reserved)
        && boolean_u32(assurance->route_feasibility_verified)
        && boolean_u32(assurance->receive_window_reserved)
        && boolean_u32(assurance->bearer_capacity_reserved)
        && boolean_u32(assurance->airtime_reserved)
        && boolean_u32(assurance->compliance_permit_issued)
        && assurance->reserved_zero == 0u;
}

static int target_valid(const ninlil_rt_target_slot_t *slot)
{
    return boolean_u32(slot->in_use)
        && boolean_u32(slot->evidence_recorded)
        && boolean_u32(slot->pending_dispatch)
        && slot->reserved_zero == 0u
        && header_current(
            slot->target.abi_version,
            slot->target.struct_size,
            sizeof(slot->target))
        && id_nonzero(&slot->target.target_runtime_id)
        && id_nonzero(&slot->target.target_application_instance_id)
        && slot->target.reserved_zero == 0u
        && identity_presence_valid(
            slot->target.flags,
            &slot->target.device_id,
            &slot->target.installation_id,
            &slot->target.site_domain_id,
            slot->target.binding_epoch,
            slot->target.membership_epoch)
        && outcome_valid(slot->outcome)
        && reason_valid(slot->reason);
}

static int disposition_tuple_valid(
    ninlil_disposition_t disposition,
    ninlil_effect_certainty_t certainty,
    ninlil_retry_guidance_t guidance,
    ninlil_reason_t reason,
    uint64_t retry_delay_ms)
{
    int retry_delay_valid =
        retry_delay_ms <= NINLIL_M1A_MAX_RETRY_DELAY_MS;

    switch (disposition) {
    case NINLIL_DISPOSITION_RETRY_LATER:
        return certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && guidance == NINLIL_RETRY_SAME_AFTER
            && reason == NINLIL_REASON_RECONCILE_RETRY_LATER
            && retry_delay_valid;
    case NINLIL_DISPOSITION_INVALID_PAYLOAD:
    case NINLIL_DISPOSITION_UNSUPPORTED_SCHEMA:
        return certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && guidance == NINLIL_RETRY_MODIFIED
            && reason == NINLIL_REASON_APPLICATION_FAILED
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_UNAUTHORIZED_SERVICE:
        return certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && guidance == NINLIL_RETRY_MODIFIED
            && reason == NINLIL_REASON_TARGET_UNAUTHORIZED
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_STALE_NOT_APPLIED:
        return certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && guidance == NINLIL_RETRY_NEVER
            && reason == NINLIL_REASON_APPLICATION_FAILED
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_APPLICATION_BUSY:
        return certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && guidance == NINLIL_RETRY_SAME_AFTER
            && reason == NINLIL_REASON_RECEIVER_UNAVAILABLE
            && retry_delay_valid;
    case NINLIL_DISPOSITION_APPLY_FAILED:
        return (certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
                && guidance == NINLIL_RETRY_SAME_AFTER
                && reason == NINLIL_REASON_APPLICATION_FAILED
                && retry_delay_valid)
            || (certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE
                && guidance == NINLIL_RETRY_OPERATOR_ACTION
                && reason == NINLIL_REASON_APPLICATION_FAILED
                && retry_delay_ms == 0u);
    case NINLIL_DISPOSITION_VERIFY_FAILED:
        return certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE
            && guidance == NINLIL_RETRY_OPERATOR_ACTION
            && reason == NINLIL_REASON_APPLICATION_FAILED
            && retry_delay_ms == 0u;
    case NINLIL_DISPOSITION_CAPACITY_EXHAUSTED:
        return certainty == NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN
            && guidance == NINLIL_RETRY_SAME_AFTER
            && reason == NINLIL_REASON_CAPACITY_EXHAUSTED
            && retry_delay_valid;
    case NINLIL_DISPOSITION_OUTCOME_UNKNOWN:
        return certainty == NINLIL_EFFECT_CERTAINTY_POSSIBLE
            && guidance == NINLIL_RETRY_OPERATOR_ACTION
            && reason == NINLIL_REASON_OUTCOME_UNKNOWN
            && retry_delay_ms == 0u;
    default:
        return 0;
    }
}

static int application_result_tuple_valid(
    const ninlil_rt_transaction_slot_t *transaction)
{
    if (transaction->application_result_kind == 0u) {
        int zero_tuple =
            transaction->application_disposition
                == NINLIL_DISPOSITION_NONE
            && transaction->application_result_reason
                == NINLIL_REASON_NONE
            && transaction->application_effect_certainty
                == NINLIL_EFFECT_CERTAINTY_NONE
            && transaction->application_retry_guidance
                == NINLIL_RETRY_NEVER
            && transaction->application_retry_delay_ms == 0u
            && transaction->application_evidence_length == 0u;

        if (zero_tuple) {
            return 1;
        }
        /*
         * Private E_REC tuple.  It deliberately keeps public
         * application_result_kind/disposition at zero while preserving the
         * exact recovery reason/effect/guidance needed by restart and
         * reconciliation.  Completed evidence/outcome must remain zero.
         */
        return transaction->delivery_phase
                == NINLIL_RT_DELIVERY_RECOVERY_REQUIRED
            && transaction->terminal == 0u
            && transaction->evidence_recorded == 0u
            && transaction->outcome_recorded == 0u
            && transaction->latest_evidence == NINLIL_EVIDENCE_NONE
            && transaction->outcome == NINLIL_OUTCOME_NONE
            && transaction->application_disposition
                == NINLIL_DISPOSITION_NONE
            && (transaction->application_result_reason
                    == NINLIL_REASON_APPLICATION_FAILED
                || transaction->application_result_reason
                    == NINLIL_REASON_CALLBACK_CONTRACT
                || transaction->application_result_reason
                    == NINLIL_REASON_COUNTER_EXHAUSTED
                || transaction->application_result_reason
                    == NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT
                || transaction->application_result_reason
                    == NINLIL_REASON_OUTCOME_UNKNOWN)
            && transaction->application_effect_certainty
                == NINLIL_EFFECT_CERTAINTY_POSSIBLE
            && transaction->application_retry_guidance
                == (transaction->application_result_reason
                        == NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT
                    ? NINLIL_RETRY_SAME_AFTER
                    : NINLIL_RETRY_OPERATOR_ACTION)
            && transaction->application_retry_delay_ms == 0u
            && transaction->application_evidence_length == 0u;
    }
    if (transaction->application_result_kind
        == NINLIL_APP_RESULT_POSITIVE_EVIDENCE) {
        return transaction->latest_evidence != NINLIL_EVIDENCE_NONE
            && transaction->latest_evidence
                >= transaction->required_evidence
            && transaction->evidence_recorded == 1u
            && transaction->application_disposition
                == NINLIL_DISPOSITION_NONE
            && transaction->application_result_reason
                == NINLIL_REASON_NONE
            && transaction->application_effect_certainty
                == NINLIL_EFFECT_CERTAINTY_NONE
            && transaction->application_retry_guidance
                == NINLIL_RETRY_NEVER
            && transaction->application_retry_delay_ms == 0u;
    }
    return transaction->application_result_kind
            == NINLIL_APP_RESULT_DISPOSITION
        && transaction->application_evidence_length == 0u
        && disposition_tuple_valid(
            transaction->application_disposition,
            transaction->application_effect_certainty,
            transaction->application_retry_guidance,
            transaction->application_result_reason,
            transaction->application_retry_delay_ms);
}

static int transaction_valid(const ninlil_rt_transaction_slot_t *transaction)
{
    uint32_t index;

    if (transaction == NULL
        || transaction->in_use != 1u
        || !id_nonzero(&transaction->transaction_id)
        || !boolean_u32(transaction->terminal)
        || !boolean_u32(transaction->origin_admission)
        || !boolean_u32(transaction->has_late_evidence)
        || !boolean_u32(transaction->attempt_prepared)
        || transaction->attempt_count > NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN
        || !attempt_history_valid(transaction)
        || !family_retry_history_valid(transaction)
        || !id_nonzero(&transaction->service_app_id)
        || !family_valid(transaction->family)
        || !evidence_valid(transaction->required_evidence)
        || !evidence_valid(transaction->latest_evidence)
        || !application_result_kind_valid(transaction->application_result_kind)
        || !disposition_valid(transaction->application_disposition)
        || !reason_valid(transaction->application_result_reason)
        || !effect_certainty_valid(
            transaction->application_effect_certainty)
        || !retry_guidance_valid(transaction->application_retry_guidance)
        || transaction->application_evidence_length > NINLIL_MAX_EVIDENCE_BYTES
        || !deadline_verdict_valid(transaction->deadline_verdict)
        || transaction->transaction_sequence == 0u
        || transaction->record_revision == 0u
        || !cancel_kind_valid(transaction->cancel_kind)
        || !outcome_valid(transaction->outcome)
        || !reason_valid(transaction->reason)
        || !boolean_u32(transaction->pending_dispatch)
        || !delivery_phase_valid(transaction->delivery_phase)
        || !token_state_valid(transaction->token_state)
        || !boolean_u32(transaction->deferred_wait)
        || !event_park_cause_valid(transaction->event_park_cause)
        || !boolean_u32(transaction->event_discarded)
        || transaction->resume_op_count
            > NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS
        || !boolean_u32(transaction->evidence_recorded)
        || !boolean_u32(transaction->outcome_recorded)
        || transaction->payload_length
            > NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES
        || transaction->last_consumed_bearer_availability_epoch
            > transaction->last_bearer_availability_epoch
        || transaction->semantic_priority > 8u
        || !bearer_route_valid(transaction->bearer_route)
        || !boolean_u32(transaction->reservation_active)
        || !boolean_u32(transaction->send_observation_closed)
        || !boolean_u32(transaction->reverse_receipt_closed)
        || !boolean_u32(transaction->ingress_pending)
        || !boolean_u32(transaction->receipt_pending)
        || transaction->bound_target_count
            > NINLIL_RT_V1_MAX_TARGETS_PER_TXN
        || transaction->bound_target_count == 0u
        || !party_valid(&transaction->source)
        || !service_valid(&transaction->service)
        || transaction->service.family != transaction->family
        || !family_semantics_valid(transaction)
        || !digest_valid(&transaction->content_digest)
        || !assurance_valid(&transaction->assurance)
        || !application_result_tuple_valid(transaction)) {
        return 0;
    }
    if (transaction->terminal != 0u
        && (transaction->outcome_recorded == 0u
            || transaction->outcome == NINLIL_OUTCOME_NONE
            || transaction->pending_dispatch != 0u)) {
        return 0;
    }
    if (!delivery_token_tuple_valid(transaction)) {
        return 0;
    }
    for (index = 0u; index < transaction->bound_target_count; ++index) {
        if (!target_valid(&transaction->bound_targets[index])
            || transaction->bound_targets[index].in_use == 0u) {
            return 0;
        }
    }
    return 1;
}

static void encode_body(
    tx_writer_t *writer,
    const ninlil_rt_transaction_slot_t *transaction)
{
    uint32_t index;

    writer_u32(writer, transaction->in_use);
    writer_u32(writer, transaction->terminal);
    writer_u32(writer, transaction->origin_admission);
    writer_u32(writer, transaction->has_late_evidence);
    writer_id(writer, &transaction->transaction_id);
    writer_id(writer, &transaction->attempt_id);
    writer_u32(writer, transaction->attempt_prepared);
    writer_u32(writer, transaction->attempt_count);
    for (index = 0u; index < transaction->attempt_count; ++index) {
        writer_id(writer, &transaction->attempt_ids[index]);
    }
    writer_id(writer, &transaction->service_app_id);
    writer_id(writer, &transaction->event_id);
    writer_party(writer, &transaction->source);
    writer_service(writer, &transaction->service);
    writer_digest(writer, &transaction->content_digest);
    writer_u32(writer, transaction->family);
    writer_u32(writer, transaction->required_evidence);
    writer_u32(writer, transaction->latest_evidence);
    writer_u32(writer, transaction->application_result_kind);
    writer_u32(writer, transaction->application_disposition);
    writer_u32(writer, transaction->application_result_reason);
    writer_u32(writer, transaction->application_effect_certainty);
    writer_u32(writer, transaction->application_retry_guidance);
    writer_u64(writer, transaction->application_retry_delay_ms);
    writer_u32(writer, transaction->application_evidence_length);
    writer_bytes(
        writer,
        transaction->application_evidence,
        transaction->application_evidence_length);
    writer_u32(writer, transaction->deadline_verdict);
    writer_u64(writer, transaction->transaction_sequence);
    writer_u64(writer, transaction->record_revision);
    writer_u32(writer, transaction->cancel_kind);
    writer_u32(writer, transaction->outcome);
    writer_u32(writer, transaction->reason);
    writer_u32(writer, transaction->pending_dispatch);
    writer_u32(writer, (uint32_t)transaction->delivery_phase);
    writer_u64(writer, transaction->delivery_count);
    writer_u32(writer, (uint32_t)transaction->token_state);
    writer_u32(writer, transaction->deferred_wait);
    writer_id(writer, &transaction->token_clock_epoch_id);
    writer_u64(writer, transaction->token_generation);
    writer_u64(writer, transaction->delivery_started_at_ms);
    writer_u64(writer, transaction->token_expires_at_ms);
    writer_u64(writer, transaction->application_completion_timeout_ms);
    writer_u64(writer, transaction->spool_revision);
    writer_u32(writer, transaction->event_park_cause);
    writer_u32(writer, transaction->event_discarded);
    writer_u32(writer, transaction->retry_budget);
    writer_u64(writer, transaction->retry_cycle_id);
    writer_u32(writer, transaction->attempt_in_cycle);
    writer_u64(writer, transaction->cumulative_attempts);
    writer_u32(writer, transaction->retry_summary_count);
    for (index = 0u;
         index < NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS;
         ++index) {
        writer_retry_summary(writer, &transaction->retry_summaries[index]);
    }
    writer_u64(writer, transaction->older_retry_cycle_count);
    writer_u64(writer, transaction->older_retry_attempt_count);
    writer_u32(writer, transaction->older_retry_delivery_possible_any);
    writer_u32(writer, transaction->older_retry_last_reason);
    writer_id(
        writer,
        &transaction->older_retry_last_observed_clock_epoch_id);
    writer_u64(writer, transaction->older_retry_last_observed_at_ms);
    writer_u64(writer, transaction->next_retry_ms);
    writer_id(writer, &transaction->next_retry_clock_epoch_id);
    writer_u64(writer, transaction->effect_deadline_ms);
    writer_u64(writer, transaction->evidence_grace_ms);
    writer_id(writer, &transaction->admission_clock_epoch_id);
    writer_id(writer, &transaction->deadline_clock_epoch_id);
    writer_u64(writer, transaction->generation);
    writer_u32(writer, transaction->resume_op_count);
    writer_id(writer, &transaction->last_resume_operation_id);
    writer_u32(writer, transaction->evidence_recorded);
    writer_u32(writer, transaction->outcome_recorded);
    writer_u32(writer, transaction->payload_length);
    writer_u8(writer, transaction->semantic_priority);
    writer_u8(writer, transaction->bearer_route);
    writer_u32(writer, transaction->reservation_active);
    writer_u32(writer, transaction->reservation_evidence_units);
    writer_u64(writer, transaction->admitted_at_ms);
    writer_u64(writer, transaction->attempt_receipt_timeout_ms);
    writer_u64(writer, transaction->retry_backoff_ms);
    writer_id(writer, &transaction->send_observed_clock_epoch_id);
    writer_u64(writer, transaction->send_observed_at_ms);
    writer_u64(writer, transaction->last_bearer_availability_epoch);
    writer_u64(
        writer,
        transaction->last_consumed_bearer_availability_epoch);
    writer_u32(writer, transaction->send_observation_closed);
    writer_u32(writer, transaction->reverse_receipt_closed);
    writer_u32(writer, transaction->ingress_pending);
    writer_u32(writer, transaction->receipt_pending);
    writer_u64(writer, transaction->ordered_input_sequence);
    writer_bytes(writer, transaction->owned_payload, transaction->payload_length);
    writer_assurance(writer, &transaction->assurance);
    writer_u32(writer, transaction->bound_target_count);
    for (index = 0u; index < transaction->bound_target_count; ++index) {
        writer_target(writer, &transaction->bound_targets[index]);
    }
}

static void decode_body(
    tx_reader_t *reader,
    ninlil_rt_transaction_slot_t *transaction)
{
    uint32_t index;

    transaction->in_use = reader_u32(reader);
    transaction->terminal = reader_u32(reader);
    transaction->origin_admission = reader_u32(reader);
    transaction->has_late_evidence = reader_u32(reader);
    reader_id(reader, &transaction->transaction_id);
    reader_id(reader, &transaction->attempt_id);
    transaction->attempt_prepared = reader_u32(reader);
    transaction->attempt_count = reader_u32(reader);
    if (transaction->attempt_count > NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN) {
        reader->failed = 1u;
        return;
    }
    for (index = 0u; index < transaction->attempt_count; ++index) {
        reader_id(reader, &transaction->attempt_ids[index]);
    }
    reader_id(reader, &transaction->service_app_id);
    reader_id(reader, &transaction->event_id);
    reader_party(reader, &transaction->source);
    reader_service(reader, &transaction->service);
    reader_digest(reader, &transaction->content_digest);
    transaction->family = reader_u32(reader);
    transaction->required_evidence = reader_u32(reader);
    transaction->latest_evidence = reader_u32(reader);
    transaction->application_result_kind = reader_u32(reader);
    transaction->application_disposition = reader_u32(reader);
    transaction->application_result_reason = reader_u32(reader);
    transaction->application_effect_certainty = reader_u32(reader);
    transaction->application_retry_guidance = reader_u32(reader);
    transaction->application_retry_delay_ms = reader_u64(reader);
    transaction->application_evidence_length = reader_u32(reader);
    if (transaction->application_evidence_length > NINLIL_MAX_EVIDENCE_BYTES) {
        reader->failed = 1u;
        return;
    }
    reader_bytes(
        reader,
        transaction->application_evidence,
        transaction->application_evidence_length);
    transaction->deadline_verdict = reader_u32(reader);
    transaction->transaction_sequence = reader_u64(reader);
    transaction->record_revision = reader_u64(reader);
    transaction->cancel_kind = reader_u32(reader);
    transaction->outcome = reader_u32(reader);
    transaction->reason = reader_u32(reader);
    transaction->pending_dispatch = reader_u32(reader);
    transaction->delivery_phase =
        (ninlil_rt_delivery_phase_t)reader_u32(reader);
    transaction->delivery_count = reader_u64(reader);
    transaction->token_state = (ninlil_rt_token_state_t)reader_u32(reader);
    transaction->deferred_wait = reader_u32(reader);
    reader_id(reader, &transaction->token_clock_epoch_id);
    transaction->token_generation = reader_u64(reader);
    transaction->delivery_started_at_ms = reader_u64(reader);
    transaction->token_expires_at_ms = reader_u64(reader);
    transaction->application_completion_timeout_ms = reader_u64(reader);
    transaction->spool_revision = reader_u64(reader);
    transaction->event_park_cause = reader_u32(reader);
    transaction->event_discarded = reader_u32(reader);
    transaction->retry_budget = reader_u32(reader);
    transaction->retry_cycle_id = reader_u64(reader);
    transaction->attempt_in_cycle = reader_u32(reader);
    transaction->cumulative_attempts = reader_u64(reader);
    transaction->retry_summary_count = reader_u32(reader);
    if (transaction->retry_summary_count
        > NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS) {
        reader->failed = 1u;
        return;
    }
    for (index = 0u;
         index < NINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS;
         ++index) {
        reader_retry_summary(reader, &transaction->retry_summaries[index]);
    }
    transaction->older_retry_cycle_count = reader_u64(reader);
    transaction->older_retry_attempt_count = reader_u64(reader);
    transaction->older_retry_delivery_possible_any = reader_u32(reader);
    transaction->older_retry_last_reason = reader_u32(reader);
    reader_id(
        reader,
        &transaction->older_retry_last_observed_clock_epoch_id);
    transaction->older_retry_last_observed_at_ms = reader_u64(reader);
    transaction->next_retry_ms = reader_u64(reader);
    reader_id(reader, &transaction->next_retry_clock_epoch_id);
    transaction->effect_deadline_ms = reader_u64(reader);
    transaction->evidence_grace_ms = reader_u64(reader);
    reader_id(reader, &transaction->admission_clock_epoch_id);
    reader_id(reader, &transaction->deadline_clock_epoch_id);
    transaction->generation = reader_u64(reader);
    transaction->resume_op_count = reader_u32(reader);
    reader_id(reader, &transaction->last_resume_operation_id);
    transaction->evidence_recorded = reader_u32(reader);
    transaction->outcome_recorded = reader_u32(reader);
    transaction->payload_length = reader_u32(reader);
    if (transaction->payload_length > NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES) {
        reader->failed = 1u;
        return;
    }
    transaction->semantic_priority = reader_u8(reader);
    transaction->bearer_route = reader_u8(reader);
    transaction->reservation_active = reader_u32(reader);
    transaction->reservation_evidence_units = reader_u32(reader);
    transaction->admitted_at_ms = reader_u64(reader);
    transaction->attempt_receipt_timeout_ms = reader_u64(reader);
    transaction->retry_backoff_ms = reader_u64(reader);
    reader_id(reader, &transaction->send_observed_clock_epoch_id);
    transaction->send_observed_at_ms = reader_u64(reader);
    transaction->last_bearer_availability_epoch = reader_u64(reader);
    transaction->last_consumed_bearer_availability_epoch =
        reader_u64(reader);
    transaction->send_observation_closed = reader_u32(reader);
    transaction->reverse_receipt_closed = reader_u32(reader);
    transaction->ingress_pending = reader_u32(reader);
    transaction->receipt_pending = reader_u32(reader);
    transaction->ordered_input_sequence = reader_u64(reader);
    reader_bytes(reader, transaction->owned_payload, transaction->payload_length);
    reader_assurance(reader, &transaction->assurance);
    transaction->bound_target_count = reader_u32(reader);
    if (transaction->bound_target_count > NINLIL_RT_V1_MAX_TARGETS_PER_TXN) {
        reader->failed = 1u;
        return;
    }
    for (index = 0u; index < transaction->bound_target_count; ++index) {
        reader_target(reader, &transaction->bound_targets[index]);
    }
}

ninlil_status_t ninlil_rt_v1_transaction_record_encode(
    const struct ninlil_rt_transaction_slot *transaction,
    uint8_t *out_bytes,
    uint32_t out_capacity,
    uint32_t *out_length)
{
    tx_writer_t writer;
    uint32_t body_length;
    uint32_t crc;

    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (transaction == NULL || out_bytes == NULL || out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (out_capacity < NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
            + NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES
        || out_capacity > NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES
        || !transaction_valid(transaction)) {
        return out_capacity < NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
                + NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES
            ? NINLIL_E_BUFFER_TOO_SMALL
            : NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(out_bytes, 0, out_capacity);
    out_bytes[0] = TX_RECORD_MAGIC_0;
    out_bytes[1] = TX_RECORD_MAGIC_1;
    out_bytes[2] = TX_RECORD_MAGIC_2;
    out_bytes[3] = TX_RECORD_MAGIC_3;
    encode_u16_be_at(&out_bytes[4],
        NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MAJOR);
    encode_u16_be_at(&out_bytes[6],
        NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MINOR);
    writer.bytes = out_bytes;
    writer.capacity = out_capacity;
    writer.position = NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES;
    writer.failed = 0u;
    encode_body(&writer, transaction);
    if (writer.failed != 0u
        || writer.position
            > out_capacity - NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    body_length =
        writer.position - NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES;
    encode_u32_be_at(&out_bytes[8], body_length);
    encode_u32_be_at(&out_bytes[12], 0u);
    crc = ninlil_model_domain_crc32c(out_bytes, writer.position);
    encode_u32_be_at(&out_bytes[writer.position], crc);
    writer.position += NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES;
    *out_length = writer.position;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_transaction_record_decode(
    ninlil_bytes_view_t record,
    struct ninlil_rt_transaction_slot *decode_scratch,
    struct ninlil_rt_transaction_slot *out_transaction)
{
    tx_reader_t reader;
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t body_length;
    uint32_t expected_length;
    uint32_t crc_stored;
    uint32_t crc_computed;

    if (decode_scratch == NULL
        || out_transaction == NULL
        || decode_scratch == out_transaction
        || record.data == NULL
        || record.length
            < NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
                + NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (record.length > NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (record.data[0] != TX_RECORD_MAGIC_0
        || record.data[1] != TX_RECORD_MAGIC_1
        || record.data[2] != TX_RECORD_MAGIC_2
        || record.data[3] != TX_RECORD_MAGIC_3) {
        if (record.length >= 4u
            && record.data[0] == 0x4eu
            && record.data[1] == 0x54u
            && ((record.data[2] == 0x53u
                    && record.data[3] == 0x32u)
                || (record.data[2] == 0x58u
                    && record.data[3] == 0x33u))) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    schema_major = decode_u16_be_at(&record.data[4]);
    schema_minor = decode_u16_be_at(&record.data[6]);
    if (schema_major != NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MAJOR
        || schema_minor != NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MINOR) {
        return NINLIL_E_UNSUPPORTED;
    }
    body_length = decode_u32_be_at(&record.data[8]);
    if (body_length
            > NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES
                - NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
                - NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES
        || decode_u32_be_at(&record.data[12]) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    expected_length = NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
        + body_length
        + NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES;
    if (record.length != expected_length) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    crc_stored = decode_u32_be_at(
        &record.data[record.length
            - NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES]);
    crc_computed = ninlil_model_domain_crc32c(
        record.data,
        record.length - NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES);
    if (crc_stored != crc_computed) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    (void)memset(decode_scratch, 0, sizeof(*decode_scratch));
    reader.bytes = record.data;
    reader.limit =
        NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES + body_length;
    reader.position = NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES;
    reader.failed = 0u;
    decode_body(&reader, decode_scratch);
    if (reader.failed != 0u
        || reader.position != reader.limit
        || !transaction_valid(decode_scratch)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_transaction = *decode_scratch;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_transaction_record_validate_envelope(
    ninlil_bytes_view_t record)
{
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t body_length;
    uint32_t expected_length;
    uint32_t crc_stored;
    uint32_t crc_computed;

    if (record.data == NULL
        || record.length
            < NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
                + NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (record.length > NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (record.data[0] != TX_RECORD_MAGIC_0
        || record.data[1] != TX_RECORD_MAGIC_1
        || record.data[2] != TX_RECORD_MAGIC_2
        || record.data[3] != TX_RECORD_MAGIC_3) {
        if ((record.data[0] == 0x4eu
                && record.data[1] == 0x54u
                && record.data[2] == 0x53u
                && record.data[3] == 0x32u)
            || (record.data[0] == 0x4eu
                && record.data[1] == 0x54u
                && record.data[2] == 0x58u
                && record.data[3] == 0x33u)) {
            return NINLIL_E_UNSUPPORTED;
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    schema_major = decode_u16_be_at(&record.data[4]);
    schema_minor = decode_u16_be_at(&record.data[6]);
    if (schema_major != NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MAJOR
        || schema_minor != NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MINOR) {
        return NINLIL_E_UNSUPPORTED;
    }
    body_length = decode_u32_be_at(&record.data[8]);
    if (body_length
            > NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES
                - NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
                - NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES
        || decode_u32_be_at(&record.data[12]) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    expected_length = NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES
        + body_length
        + NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES;
    if (record.length != expected_length) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    crc_stored = decode_u32_be_at(
        &record.data[record.length
            - NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES]);
    crc_computed = ninlil_model_domain_crc32c(
        record.data,
        record.length - NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES);
    return crc_stored == crc_computed
        ? NINLIL_OK : NINLIL_E_STORAGE_CORRUPT;
}
