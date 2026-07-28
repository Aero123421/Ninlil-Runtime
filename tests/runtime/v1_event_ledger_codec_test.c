#include "domain_store_codec.h"
#include "runtime_v1_event_ledger_codec.h"

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

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static void store_u32_be(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void refresh_crc(uint8_t *value, uint32_t length)
{
    uint32_t crc =
        ninlil_model_domain_crc32c(value, length - 4u);

    store_u32_be(&value[length - 4u], crc);
}

static int all_bytes_equal(const void *value, uint8_t expected, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)value;
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != expected) {
            return 0;
        }
    }
    return 1;
}

static int test_canonical_request_digests(void)
{
    static const uint8_t resume_expected[NINLIL_SHA256_BYTES] = {
        0xceu, 0x46u, 0x78u, 0x9bu, 0x75u, 0x8bu, 0x15u, 0x4bu,
        0xe0u, 0xedu, 0xc8u, 0xf5u, 0x12u, 0xe3u, 0x90u, 0xc2u,
        0x2eu, 0xb6u, 0xb1u, 0xc1u, 0x13u, 0xb9u, 0x38u, 0x2fu,
        0x36u, 0xeeu, 0x4eu, 0x20u, 0x9fu, 0x9fu, 0xb5u, 0xd5u
    };
    static const uint8_t discard_expected[NINLIL_SHA256_BYTES] = {
        0x8eu, 0x88u, 0x88u, 0xdeu, 0x73u, 0x3au, 0x34u, 0x92u,
        0xecu, 0xbau, 0x5fu, 0x3cu, 0x6du, 0xf9u, 0x3eu, 0x38u,
        0x6eu, 0x7eu, 0x33u, 0x95u, 0xbdu, 0x9au, 0x70u, 0x7cu,
        0x56u, 0xe3u, 0x54u, 0xa8u, 0x9bu, 0x6du, 0x4du, 0xadu
    };
    ninlil_id128_t transaction_id;
    ninlil_event_resume_request_t resume;
    ninlil_event_discard_request_t discard;
    uint8_t resume_metadata[] = {0x00u, 0x7fu, 0xffu};
    uint8_t discard_metadata[] = {'a', 'u', 'd', 'i', 't'};
    uint8_t digest[NINLIL_SHA256_BYTES];
    uint32_t index;

    set_id(&transaction_id, 0x10u);
    (void)memset(&resume, 0, sizeof(resume));
    set_header(&resume.abi_version, &resume.struct_size, sizeof(resume));
    set_id(&resume.operation_id, 0x20u);
    set_id(&resume.actor_id, 0x30u);
    resume.expected_spool_revision = UINT64_C(0x0102030405060708);
    resume.resume_reason = NINLIL_RESUME_OPERATOR_OVERRIDE;
    resume.audit_metadata.data = resume_metadata;
    resume.audit_metadata.length = sizeof(resume_metadata);
    REQUIRE(ninlil_rt_v1_event_resume_request_digest(
                &transaction_id, &resume, digest)
        == NINLIL_OK);
    REQUIRE(memcmp(digest, resume_expected, sizeof(digest)) == 0);

    (void)memset(&discard, 0, sizeof(discard));
    set_header(&discard.abi_version, &discard.struct_size, sizeof(discard));
    set_id(&discard.operation_id, 0x20u);
    set_id(&discard.actor_id, 0x30u);
    set_id(&discard.expected_event_id, 0x40u);
    discard.expected_content_digest.algorithm = NINLIL_DIGEST_SHA256;
    for (index = 0u;
         index < sizeof(discard.expected_content_digest.bytes);
         ++index) {
        discard.expected_content_digest.bytes[index] =
            (uint8_t)(index + 1u);
    }
    discard.expected_spool_revision = 9u;
    discard.discard_reason = NINLIL_DISCARD_OPERATOR_OVERRIDE;
    discard.acknowledge_required_receipt_absent = 1u;
    discard.audit_metadata.data = discard_metadata;
    discard.audit_metadata.length = sizeof(discard_metadata);
    REQUIRE(ninlil_rt_v1_event_discard_request_digest(
                &transaction_id, &discard, digest)
        == NINLIL_OK);
    REQUIRE(memcmp(digest, discard_expected, sizeof(digest)) == 0);
    return 0;
}

static void fill_resume_record(
    ninlil_rt_v1_event_ledger_record_t *record,
    uint32_t metadata_length)
{
    ninlil_event_resume_request_t request;
    uint32_t index;

    (void)memset(record, 0, sizeof(*record));
    record->operation_kind = NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME;
    record->record_revision = 1u;
    record->ordered_sequence = 17u;
    set_id(&record->transaction_id, 0x10u);
    set_id(&record->event_id, 0x40u);
    set_id(&record->operation_id, 0x20u);
    set_id(&record->actor_id, 0x30u);
    record->expected_spool_revision = 9u;
    record->request_reason = NINLIL_RESUME_TEST;
    record->metadata_length = metadata_length;
    for (index = 0u; index < metadata_length; ++index) {
        record->metadata[index] = (uint8_t)(index ^ 0x5au);
    }
    record->replay_result_kind =
        NINLIL_EVENT_RESUME_ALREADY_RESUMED;
    record->replay_result_reason = NINLIL_REASON_NONE;
    record->replay_retry_cycle_id = 2u;
    record->replay_spool_revision = 10u;

    (void)memset(&request, 0, sizeof(request));
    request.operation_id = record->operation_id;
    request.actor_id = record->actor_id;
    request.expected_spool_revision = record->expected_spool_revision;
    request.resume_reason = record->request_reason;
    request.audit_metadata.data = record->metadata;
    request.audit_metadata.length = record->metadata_length;
    (void)ninlil_rt_v1_event_resume_request_digest(
        &record->transaction_id,
        &request,
        record->canonical_request_digest);
}

static void fill_discard_record(
    ninlil_rt_v1_event_ledger_record_t *record)
{
    ninlil_event_discard_request_t request;
    uint32_t index;

    (void)memset(record, 0, sizeof(*record));
    record->operation_kind = NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD;
    record->record_revision = 1u;
    record->ordered_sequence = 18u;
    set_id(&record->transaction_id, 0x11u);
    set_id(&record->event_id, 0x41u);
    set_id(&record->operation_id, 0x21u);
    set_id(&record->actor_id, 0x31u);
    record->expected_spool_revision = 20u;
    record->expected_event_id = record->event_id;
    record->expected_content_digest_algorithm = NINLIL_DIGEST_SHA256;
    for (index = 0u; index < NINLIL_SHA256_BYTES; ++index) {
        record->expected_content_digest[index] = (uint8_t)(0x80u + index);
    }
    record->request_reason = NINLIL_DISCARD_TEST_CLEANUP;
    record->acknowledge_flag = 1u;
    record->metadata_length = 5u;
    (void)memcpy(record->metadata, "audit", 5u);
    set_id(&record->audit_clock_epoch_id, 0x60u);
    record->audit_committed_at_ms = 1234u;
    record->replay_result_kind =
        NINLIL_EVENT_DISCARD_ALREADY_DISCARDED;
    record->replay_result_reason =
        NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT;
    record->replay_spool_revision = 21u;
    record->replay_spool_released = 1u;

    (void)memset(&request, 0, sizeof(request));
    request.operation_id = record->operation_id;
    request.actor_id = record->actor_id;
    request.expected_event_id = record->expected_event_id;
    request.expected_content_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(
        request.expected_content_digest.bytes,
        record->expected_content_digest,
        NINLIL_SHA256_BYTES);
    request.expected_spool_revision = record->expected_spool_revision;
    request.discard_reason = record->request_reason;
    request.acknowledge_required_receipt_absent = 1u;
    request.audit_metadata.data = record->metadata;
    request.audit_metadata.length = record->metadata_length;
    (void)ninlil_rt_v1_event_discard_request_digest(
        &record->transaction_id,
        &request,
        record->canonical_request_digest);
}

static int test_key_and_roundtrip(void)
{
    ninlil_rt_v1_event_ledger_record_t source;
    ninlil_rt_v1_event_ledger_record_t decoded;
    uint8_t key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES];
    uint8_t value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES];
    uint32_t value_length = 0u;

    fill_resume_record(
        &source, NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES);
    ninlil_rt_v1_event_ledger_key(
        NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX,
        &source.transaction_id,
        &source.operation_id,
        key);
    REQUIRE(key[0] == 0x45u && key[1] == 0x52u);
    REQUIRE(memcmp(&key[2], source.transaction_id.bytes, 16u) == 0);
    REQUIRE(memcmp(&key[18], source.operation_id.bytes, 16u) == 0);
    REQUIRE(ninlil_rt_v1_event_ledger_encode(
                &source,
                value,
                (uint32_t)sizeof(value),
                &value_length)
        == NINLIL_OK);
    REQUIRE(value_length == NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES);
    REQUIRE(memcmp(value, "NEL1", 4u) == 0);
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_rt_v1_event_ledger_decode(
                (ninlil_bytes_view_t){value, value_length}, &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.operation_kind
        == NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME);
    REQUIRE(decoded.metadata_length
        == NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES);
    REQUIRE(memcmp(
                decoded.metadata,
                source.metadata,
                source.metadata_length)
        == 0);

    fill_discard_record(&source);
    REQUIRE(ninlil_rt_v1_event_ledger_encode(
                &source,
                value,
                (uint32_t)sizeof(value),
                &value_length)
        == NINLIL_OK);
    REQUIRE(ninlil_rt_v1_event_ledger_decode(
                (ninlil_bytes_view_t){value, value_length}, &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.operation_kind
        == NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD);
    REQUIRE(decoded.audit_committed_at_ms == 1234u);
    REQUIRE(decoded.replay_spool_released == 1u);
    return 0;
}

static int expect_decode_failure_unchanged(
    uint8_t *value,
    uint32_t length,
    ninlil_status_t expected_status)
{
    ninlil_rt_v1_event_ledger_record_t output;

    (void)memset(&output, 0xa5, sizeof(output));
    REQUIRE(ninlil_rt_v1_event_ledger_decode(
                (ninlil_bytes_view_t){value, length}, &output)
        == expected_status);
    REQUIRE(all_bytes_equal(&output, 0xa5u, sizeof(output)));
    return 0;
}

static int test_malformed_rejection_and_nonmutation(void)
{
    ninlil_rt_v1_event_ledger_record_t source;
    uint8_t value[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES + 1u];
    uint8_t original[NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES + 1u];
    uint32_t length = 0u;

    fill_resume_record(&source, 3u);
    REQUIRE(ninlil_rt_v1_event_ledger_encode(
                &source, value, (uint32_t)sizeof(value), &length)
        == NINLIL_OK);
    (void)memcpy(original, value, length);
    REQUIRE(expect_decode_failure_unchanged(
                value, length - 1u, NINLIL_E_STORAGE_CORRUPT)
        == 0);
    value[length] = 0u;
    REQUIRE(expect_decode_failure_unchanged(
                value, length + 1u, NINLIL_E_STORAGE_CORRUPT)
        == 0);

    (void)memcpy(value, original, length);
    value[length - 1u] ^= 1u;
    REQUIRE(expect_decode_failure_unchanged(
                value, length, NINLIL_E_STORAGE_CORRUPT)
        == 0);

    (void)memcpy(value, original, length);
    value[14] = 1u;
    refresh_crc(value, length);
    REQUIRE(expect_decode_failure_unchanged(
                value, length, NINLIL_E_STORAGE_CORRUPT)
        == 0);

    (void)memcpy(value, original, length);
    value[5] = 2u;
    refresh_crc(value, length);
    REQUIRE(expect_decode_failure_unchanged(
                value, length, NINLIL_E_UNSUPPORTED)
        == 0);

    (void)memcpy(value, original, length);
    value[0] = 'X';
    refresh_crc(value, length);
    REQUIRE(expect_decode_failure_unchanged(
                value, length, NINLIL_E_UNSUPPORTED)
        == 0);

    (void)memcpy(value, original, length);
    value[96] ^= 1u;
    refresh_crc(value, length);
    REQUIRE(expect_decode_failure_unchanged(
                value, length, NINLIL_E_STORAGE_CORRUPT)
        == 0);

    (void)memset(value, 0, 40u);
    (void)memcpy(value, "NER1", 4u);
    REQUIRE(expect_decode_failure_unchanged(
                value, 40u, NINLIL_E_STORAGE_CORRUPT)
        == 0);
    return 0;
}

int main(void)
{
    REQUIRE(test_canonical_request_digests() == 0);
    REQUIRE(test_key_and_roundtrip() == 0);
    REQUIRE(test_malformed_rejection_and_nonmutation() == 0);
    (void)fprintf(stderr, "v1_event_ledger_codec_test ok\n");
    return 0;
}
