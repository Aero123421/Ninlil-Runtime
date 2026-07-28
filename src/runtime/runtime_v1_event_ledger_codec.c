#include "runtime_v1_event_ledger_codec.h"

#include "domain_store_codec.h"

#include <string.h>

#define EVENT_LEDGER_SCHEMA_MAJOR ((uint16_t)1u)
#define EVENT_LEDGER_SCHEMA_MINOR ((uint16_t)0u)
#define EVENT_LEDGER_FIXED_BYTES ((uint32_t)256u)
#define EVENT_LEDGER_CRC_BYTES ((uint32_t)4u)

static const uint8_t EVENT_RESUME_PREIMAGE[] = "NINLIL-M1A-EVENT-RESUME";
static const uint8_t EVENT_DISCARD_PREIMAGE[] = "NINLIL-M1A-EVENT-DISCARD";

static void encode_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void encode_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void encode_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
}

static uint16_t decode_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t decode_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24)
        | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8)
        | (uint32_t)in[3];
}

static uint64_t decode_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56)
        | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40)
        | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24)
        | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8)
        | (uint64_t)in[7];
}

static int id_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;

    if (id == NULL) {
        return 0;
    }
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int bytes_nonzero(const uint8_t *bytes, uint32_t length)
{
    uint32_t index;

    if (bytes == NULL) {
        return 0;
    }
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int metadata_shape_valid(ninlil_bytes_view_t metadata)
{
    return metadata.data != NULL
        && metadata.length >= 1u
        && metadata.length <= NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES;
}

static int resume_reason_valid(uint32_t reason)
{
    return reason == NINLIL_RESUME_CONNECTIVITY_REMEDIATED
        || reason == NINLIL_RESUME_CAPACITY_REMEDIATED
        || reason == NINLIL_RESUME_APPLICATION_REMEDIATED
        || reason == NINLIL_RESUME_OPERATOR_OVERRIDE
        || reason == NINLIL_RESUME_TEST;
}

static int discard_reason_valid(uint32_t reason)
{
    return reason == NINLIL_DISCARD_DEVICE_DECOMMISSIONED
        || reason == NINLIL_DISCARD_INVALID_EVENT
        || reason == NINLIL_DISCARD_OPERATOR_OVERRIDE
        || reason == NINLIL_DISCARD_TEST_CLEANUP;
}

static int resume_result_valid(const ninlil_rt_v1_event_ledger_record_t *record)
{
    return record->replay_result_kind == NINLIL_EVENT_RESUME_ALREADY_RESUMED
        && record->replay_result_reason == NINLIL_REASON_NONE
        && record->replay_retry_cycle_id >= 1u
        && record->replay_spool_released == 0u;
}

static int discard_result_valid(
    const ninlil_rt_v1_event_ledger_record_t *record)
{
    return record->replay_result_kind
            == NINLIL_EVENT_DISCARD_ALREADY_DISCARDED
        && record->replay_result_reason
            == NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT
        && record->replay_retry_cycle_id == 0u
        && record->replay_spool_released == 1u;
}

static int record_digest_matches(
    const ninlil_rt_v1_event_ledger_record_t *record);

static int record_fields_valid(
    const ninlil_rt_v1_event_ledger_record_t *record)
{
    if (record == NULL
        || record->record_revision != 1u
        || record->ordered_sequence == 0u
        || !id_nonzero(&record->transaction_id)
        || !id_nonzero(&record->event_id)
        || !id_nonzero(&record->operation_id)
        || !id_nonzero(&record->actor_id)
        || !bytes_nonzero(
            record->canonical_request_digest, NINLIL_SHA256_BYTES)
        || record->expected_spool_revision == 0u
        || record->expected_spool_revision == UINT64_MAX
        || record->metadata_length < 1u
        || record->metadata_length
            > NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES
        || record->replay_spool_revision
            != record->expected_spool_revision + 1u
        || !record_digest_matches(record)) {
        return 0;
    }
    if (record->operation_kind == NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME) {
        return !id_nonzero(&record->expected_event_id)
            && record->expected_content_digest_algorithm == 0u
            && !bytes_nonzero(
                record->expected_content_digest, NINLIL_SHA256_BYTES)
            && resume_reason_valid(record->request_reason)
            && record->acknowledge_flag == 0u
            && !id_nonzero(&record->audit_clock_epoch_id)
            && record->audit_committed_at_ms == 0u
            && resume_result_valid(record);
    }
    if (record->operation_kind == NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD) {
        return id_nonzero(&record->expected_event_id)
            && memcmp(
                record->event_id.bytes,
                record->expected_event_id.bytes,
                sizeof(record->event_id.bytes)) == 0
            && record->expected_content_digest_algorithm
                == NINLIL_DIGEST_SHA256
            && bytes_nonzero(
                record->expected_content_digest, NINLIL_SHA256_BYTES)
            && discard_reason_valid(record->request_reason)
            && record->acknowledge_flag == 1u
            && id_nonzero(&record->audit_clock_epoch_id)
            && discard_result_valid(record);
    }
    return 0;
}

static ninlil_status_t sha_update(
    ninlil_model_domain_sha256_ctx_t *ctx,
    const uint8_t *bytes,
    uint32_t length)
{
    return ninlil_model_domain_sha256_update(ctx, bytes, length);
}

static ninlil_status_t digest_finish(
    ninlil_model_domain_sha256_ctx_t *ctx,
    uint8_t out_digest[NINLIL_SHA256_BYTES])
{
    ninlil_model_domain_digest_t digest;
    ninlil_status_t status =
        ninlil_model_domain_sha256_final(ctx, &digest);

    if (status == NINLIL_OK) {
        (void)memcpy(out_digest, digest.bytes, sizeof(digest.bytes));
    }
    return status;
}

void ninlil_rt_v1_event_ledger_transaction_prefix(
    uint16_t prefix,
    const ninlil_id128_t *transaction_id,
    uint8_t out_prefix[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES])
{
    if (transaction_id == NULL || out_prefix == NULL) {
        return;
    }
    encode_u16_be(out_prefix, prefix);
    (void)memcpy(
        &out_prefix[2], transaction_id->bytes,
        sizeof(transaction_id->bytes));
}

void ninlil_rt_v1_event_ledger_key(
    uint16_t prefix,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *operation_id,
    uint8_t out_key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES])
{
    if (transaction_id == NULL || operation_id == NULL || out_key == NULL) {
        return;
    }
    ninlil_rt_v1_event_ledger_transaction_prefix(
        prefix, transaction_id, out_key);
    (void)memcpy(
        &out_key[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES],
        operation_id->bytes,
        sizeof(operation_id->bytes));
}

ninlil_status_t ninlil_rt_v1_event_resume_request_digest(
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    uint8_t out_digest[NINLIL_SHA256_BYTES])
{
    ninlil_model_domain_sha256_ctx_t ctx;
    uint8_t integer[8];
    ninlil_status_t status;

    if (transaction_id == NULL || request == NULL || out_digest == NULL
        || !id_nonzero(transaction_id)
        || !id_nonzero(&request->operation_id)
        || !id_nonzero(&request->actor_id)
        || request->expected_spool_revision == 0u
        || !resume_reason_valid(request->resume_reason)
        || !metadata_shape_valid(request->audit_metadata)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = sha_update(
        &ctx, EVENT_RESUME_PREIMAGE,
        (uint32_t)(sizeof(EVENT_RESUME_PREIMAGE) - 1u));
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, transaction_id->bytes, sizeof(transaction_id->bytes));
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->operation_id.bytes,
            sizeof(request->operation_id.bytes));
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->actor_id.bytes, sizeof(request->actor_id.bytes));
    }
    encode_u64_be(integer, request->expected_spool_revision);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 8u);
    }
    encode_u32_be(integer, request->resume_reason);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 4u);
    }
    encode_u32_be(integer, request->audit_metadata.length);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 4u);
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->audit_metadata.data,
            request->audit_metadata.length);
    }
    return status == NINLIL_OK
        ? digest_finish(&ctx, out_digest)
        : status;
}

ninlil_status_t ninlil_rt_v1_event_discard_request_digest(
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    uint8_t out_digest[NINLIL_SHA256_BYTES])
{
    ninlil_model_domain_sha256_ctx_t ctx;
    uint8_t integer[8];
    ninlil_status_t status;

    if (transaction_id == NULL || request == NULL || out_digest == NULL
        || !id_nonzero(transaction_id)
        || !id_nonzero(&request->operation_id)
        || !id_nonzero(&request->actor_id)
        || !id_nonzero(&request->expected_event_id)
        || request->expected_content_digest.algorithm
            != NINLIL_DIGEST_SHA256
        || request->expected_content_digest.reserved_zero != 0u
        || !bytes_nonzero(
            request->expected_content_digest.bytes, NINLIL_SHA256_BYTES)
        || request->expected_spool_revision == 0u
        || !discard_reason_valid(request->discard_reason)
        || request->acknowledge_required_receipt_absent != 1u
        || !metadata_shape_valid(request->audit_metadata)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = sha_update(
        &ctx, EVENT_DISCARD_PREIMAGE,
        (uint32_t)(sizeof(EVENT_DISCARD_PREIMAGE) - 1u));
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, transaction_id->bytes, sizeof(transaction_id->bytes));
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->operation_id.bytes,
            sizeof(request->operation_id.bytes));
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->actor_id.bytes, sizeof(request->actor_id.bytes));
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->expected_event_id.bytes,
            sizeof(request->expected_event_id.bytes));
    }
    encode_u16_be(integer, request->expected_content_digest.algorithm);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 2u);
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->expected_content_digest.bytes,
            NINLIL_SHA256_BYTES);
    }
    encode_u64_be(integer, request->expected_spool_revision);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 8u);
    }
    encode_u32_be(integer, request->discard_reason);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 4u);
    }
    encode_u32_be(
        integer, request->acknowledge_required_receipt_absent);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 4u);
    }
    encode_u32_be(integer, request->audit_metadata.length);
    if (status == NINLIL_OK) {
        status = sha_update(&ctx, integer, 4u);
    }
    if (status == NINLIL_OK) {
        status = sha_update(
            &ctx, request->audit_metadata.data,
            request->audit_metadata.length);
    }
    return status == NINLIL_OK
        ? digest_finish(&ctx, out_digest)
        : status;
}

static int record_digest_matches(
    const ninlil_rt_v1_event_ledger_record_t *record)
{
    uint8_t computed[NINLIL_SHA256_BYTES];
    ninlil_status_t status;

    if (record == NULL) {
        return 0;
    }
    if (record->operation_kind == NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME) {
        ninlil_event_resume_request_t request;

        (void)memset(&request, 0, sizeof(request));
        request.operation_id = record->operation_id;
        request.actor_id = record->actor_id;
        request.expected_spool_revision = record->expected_spool_revision;
        request.resume_reason = record->request_reason;
        request.audit_metadata.data = record->metadata;
        request.audit_metadata.length = record->metadata_length;
        status = ninlil_rt_v1_event_resume_request_digest(
            &record->transaction_id, &request, computed);
    } else if (
        record->operation_kind == NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD) {
        ninlil_event_discard_request_t request;

        (void)memset(&request, 0, sizeof(request));
        request.operation_id = record->operation_id;
        request.actor_id = record->actor_id;
        request.expected_event_id = record->expected_event_id;
        request.expected_content_digest.algorithm =
            record->expected_content_digest_algorithm;
        (void)memcpy(
            request.expected_content_digest.bytes,
            record->expected_content_digest,
            sizeof(request.expected_content_digest.bytes));
        request.expected_spool_revision = record->expected_spool_revision;
        request.discard_reason = record->request_reason;
        request.acknowledge_required_receipt_absent =
            record->acknowledge_flag;
        request.audit_metadata.data = record->metadata;
        request.audit_metadata.length = record->metadata_length;
        status = ninlil_rt_v1_event_discard_request_digest(
            &record->transaction_id, &request, computed);
    } else {
        return 0;
    }
    return status == NINLIL_OK
        && memcmp(
            computed,
            record->canonical_request_digest,
            sizeof(computed)) == 0;
}

ninlil_status_t ninlil_rt_v1_event_ledger_encode(
    const ninlil_rt_v1_event_ledger_record_t *record,
    uint8_t *out_value,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t length;
    uint32_t offset = 0u;
    uint32_t crc;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if (record == NULL || out_value == NULL
        || !record_fields_valid(record)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    length = EVENT_LEDGER_FIXED_BYTES
        + record->metadata_length
        + EVENT_LEDGER_CRC_BYTES;
    if (capacity < length) {
        *out_length = length;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memset(out_value, 0, length);
    (void)memcpy(&out_value[offset], "NEL1", 4u);
    offset += 4u;
    encode_u16_be(&out_value[offset], EVENT_LEDGER_SCHEMA_MAJOR);
    offset += 2u;
    encode_u16_be(&out_value[offset], EVENT_LEDGER_SCHEMA_MINOR);
    offset += 2u;
    encode_u32_be(&out_value[offset], length);
    offset += 4u;
    encode_u16_be(&out_value[offset], (uint16_t)record->operation_kind);
    offset += 2u;
    encode_u16_be(&out_value[offset], 0u);
    offset += 2u;
    encode_u64_be(&out_value[offset], record->record_revision);
    offset += 8u;
    encode_u64_be(&out_value[offset], record->ordered_sequence);
    offset += 8u;
    (void)memcpy(
        &out_value[offset], record->transaction_id.bytes,
        sizeof(record->transaction_id.bytes));
    offset += 16u;
    (void)memcpy(
        &out_value[offset], record->event_id.bytes,
        sizeof(record->event_id.bytes));
    offset += 16u;
    (void)memcpy(
        &out_value[offset], record->operation_id.bytes,
        sizeof(record->operation_id.bytes));
    offset += 16u;
    (void)memcpy(
        &out_value[offset], record->actor_id.bytes,
        sizeof(record->actor_id.bytes));
    offset += 16u;
    (void)memcpy(
        &out_value[offset], record->canonical_request_digest,
        NINLIL_SHA256_BYTES);
    offset += NINLIL_SHA256_BYTES;
    encode_u64_be(&out_value[offset], record->expected_spool_revision);
    offset += 8u;
    (void)memcpy(
        &out_value[offset], record->expected_event_id.bytes,
        sizeof(record->expected_event_id.bytes));
    offset += 16u;
    encode_u16_be(
        &out_value[offset], record->expected_content_digest_algorithm);
    offset += 2u;
    encode_u16_be(&out_value[offset], 0u);
    offset += 2u;
    (void)memcpy(
        &out_value[offset], record->expected_content_digest,
        NINLIL_SHA256_BYTES);
    offset += NINLIL_SHA256_BYTES;
    encode_u32_be(&out_value[offset], record->request_reason);
    offset += 4u;
    encode_u32_be(&out_value[offset], record->acknowledge_flag);
    offset += 4u;
    encode_u32_be(&out_value[offset], record->metadata_length);
    offset += 4u;
    (void)memcpy(
        &out_value[offset], record->audit_clock_epoch_id.bytes,
        sizeof(record->audit_clock_epoch_id.bytes));
    offset += 16u;
    encode_u64_be(&out_value[offset], record->audit_committed_at_ms);
    offset += 8u;
    encode_u32_be(&out_value[offset], record->replay_result_kind);
    offset += 4u;
    encode_u32_be(&out_value[offset], record->replay_result_reason);
    offset += 4u;
    encode_u64_be(&out_value[offset], record->replay_retry_cycle_id);
    offset += 8u;
    encode_u64_be(&out_value[offset], record->replay_spool_revision);
    offset += 8u;
    encode_u32_be(&out_value[offset], record->replay_spool_released);
    offset += 4u;
    encode_u32_be(&out_value[offset], 0u);
    offset += 4u;
    if (offset != EVENT_LEDGER_FIXED_BYTES) {
        return NINLIL_E_INVALID_STATE;
    }
    (void)memcpy(
        &out_value[offset], record->metadata, record->metadata_length);
    offset += record->metadata_length;
    crc = ninlil_model_domain_crc32c(out_value, offset);
    encode_u32_be(&out_value[offset], crc);
    offset += EVENT_LEDGER_CRC_BYTES;
    if (offset != length) {
        return NINLIL_E_INVALID_STATE;
    }
    *out_length = length;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_event_ledger_decode(
    ninlil_bytes_view_t value,
    ninlil_rt_v1_event_ledger_record_t *out_record)
{
    ninlil_rt_v1_event_ledger_record_t decoded;
    uint32_t offset = 0u;
    uint32_t declared_length;
    uint32_t stored_crc;
    uint32_t computed_crc;

    if (out_record == NULL
        || (value.length != 0u && value.data == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (value.length < NINLIL_RT_V1_EVENT_LEDGER_RECORD_MIN_BYTES
        || value.length > NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (memcmp(value.data, "NEL1", 4u) != 0) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (decode_u16_be(&value.data[4]) != EVENT_LEDGER_SCHEMA_MAJOR
        || decode_u16_be(&value.data[6]) != EVENT_LEDGER_SCHEMA_MINOR) {
        return NINLIL_E_UNSUPPORTED;
    }
    declared_length = decode_u32_be(&value.data[8]);
    if (declared_length != value.length) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    stored_crc = decode_u32_be(
        &value.data[value.length - EVENT_LEDGER_CRC_BYTES]);
    computed_crc = ninlil_model_domain_crc32c(
        value.data, value.length - EVENT_LEDGER_CRC_BYTES);
    if (stored_crc != computed_crc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&decoded, 0, sizeof(decoded));
    offset = 12u;
    decoded.operation_kind =
        (ninlil_rt_v1_event_ledger_kind_t)decode_u16_be(
            &value.data[offset]);
    offset += 2u;
    if (decode_u16_be(&value.data[offset]) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    offset += 2u;
    decoded.record_revision = decode_u64_be(&value.data[offset]);
    offset += 8u;
    decoded.ordered_sequence = decode_u64_be(&value.data[offset]);
    offset += 8u;
    (void)memcpy(decoded.transaction_id.bytes, &value.data[offset], 16u);
    offset += 16u;
    (void)memcpy(decoded.event_id.bytes, &value.data[offset], 16u);
    offset += 16u;
    (void)memcpy(decoded.operation_id.bytes, &value.data[offset], 16u);
    offset += 16u;
    (void)memcpy(decoded.actor_id.bytes, &value.data[offset], 16u);
    offset += 16u;
    (void)memcpy(
        decoded.canonical_request_digest,
        &value.data[offset],
        NINLIL_SHA256_BYTES);
    offset += NINLIL_SHA256_BYTES;
    decoded.expected_spool_revision =
        decode_u64_be(&value.data[offset]);
    offset += 8u;
    (void)memcpy(decoded.expected_event_id.bytes, &value.data[offset], 16u);
    offset += 16u;
    decoded.expected_content_digest_algorithm =
        decode_u16_be(&value.data[offset]);
    offset += 2u;
    if (decode_u16_be(&value.data[offset]) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    offset += 2u;
    (void)memcpy(
        decoded.expected_content_digest,
        &value.data[offset],
        NINLIL_SHA256_BYTES);
    offset += NINLIL_SHA256_BYTES;
    decoded.request_reason = decode_u32_be(&value.data[offset]);
    offset += 4u;
    decoded.acknowledge_flag = decode_u32_be(&value.data[offset]);
    offset += 4u;
    decoded.metadata_length = decode_u32_be(&value.data[offset]);
    offset += 4u;
    (void)memcpy(
        decoded.audit_clock_epoch_id.bytes, &value.data[offset], 16u);
    offset += 16u;
    decoded.audit_committed_at_ms = decode_u64_be(&value.data[offset]);
    offset += 8u;
    decoded.replay_result_kind = decode_u32_be(&value.data[offset]);
    offset += 4u;
    decoded.replay_result_reason = decode_u32_be(&value.data[offset]);
    offset += 4u;
    decoded.replay_retry_cycle_id = decode_u64_be(&value.data[offset]);
    offset += 8u;
    decoded.replay_spool_revision = decode_u64_be(&value.data[offset]);
    offset += 8u;
    decoded.replay_spool_released = decode_u32_be(&value.data[offset]);
    offset += 4u;
    if (decode_u32_be(&value.data[offset]) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    offset += 4u;
    if (offset != EVENT_LEDGER_FIXED_BYTES
        || decoded.metadata_length < 1u
        || decoded.metadata_length
            > NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES
        || offset + decoded.metadata_length + EVENT_LEDGER_CRC_BYTES
            != value.length) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(
        decoded.metadata, &value.data[offset], decoded.metadata_length);
    offset += decoded.metadata_length;
    if (offset + EVENT_LEDGER_CRC_BYTES != value.length
        || !record_fields_valid(&decoded)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_record = decoded;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_event_ledger_validate(
    ninlil_rt_v1_event_ledger_kind_t expected_kind,
    ninlil_bytes_view_t value)
{
    ninlil_rt_v1_event_ledger_record_t decoded;
    ninlil_status_t status;

    if (expected_kind != NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME
        && expected_kind != NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_v1_event_ledger_decode(value, &decoded);
    if (status != NINLIL_OK) {
        return status;
    }
    return decoded.operation_kind == expected_kind
        ? NINLIL_OK
        : NINLIL_E_STORAGE_CORRUPT;
}
