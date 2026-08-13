/* SPDX-License-Identifier: Apache-2.0 */
#include "nra1_codec.h"

#include "ninlil/version.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                   \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "nra1 failure %s:%d: %s\n",              \
                __FILE__, __LINE__,                                         \
                #condition);                                                 \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static void fill_sequence(uint8_t *out, size_t length, uint8_t first)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        out[index] = (uint8_t)(first + (uint8_t)index);
    }
}

static void make_event_application(
    ninlil_nra1_application_t *application,
    size_t payload_length)
{
    (void)memset(application, 0, sizeof(*application));
    application->service_slot = 3u;
    application->required_evidence = NINLIL_EVIDENCE_APPLIED;
    fill_sequence(application->transaction_id, 16u, 0x01u);
    fill_sequence(application->attempt_id, 16u, 0x11u);
    fill_sequence(application->subject, 16u, 0x21u);
    application->absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
    application->payload_len = payload_length;
    fill_sequence(application->payload, payload_length, 0x40u);
}

static void make_receipt(ninlil_nra1_receipt_t *receipt)
{
    (void)memset(receipt, 0, sizeof(*receipt));
    receipt->service_slot = 5u;
    receipt->receipt_stage = NINLIL_EVIDENCE_APPLIED;
    fill_sequence(receipt->transaction_id, 16u, 0x01u);
    fill_sequence(receipt->attempt_id, 16u, 0x11u);
    receipt->evidence_time_now_ms = UINT64_C(0x1122334455667788);
}

static int test_application_one_byte_kat(void)
{
    static const uint8_t expected[NINLIL_NRA1_APPLICATION_BODY_MIN] = {
        0x4e, 0x52, 0x41, 0x31, 0x01, 0x1b,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x40
    };
    ninlil_nra1_application_t application;
    ninlil_nra1_application_t decoded;
    uint8_t body[NINLIL_NRA1_APPLICATION_BODY_MAX];
    size_t length = 0u;

    make_event_application(&application, 1u);
    (void)memset(body, 0xa5, sizeof(body));
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_nra1_encode_application(
                &application, body, sizeof(body), &length)
        == NINLIL_NRA1_OK);
    REQUIRE(length == sizeof(expected));
    REQUIRE(memcmp(body, expected, sizeof(expected)) == 0);
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_OK);
    REQUIRE(decoded.service_slot == application.service_slot);
    REQUIRE(decoded.required_evidence == application.required_evidence);
    REQUIRE(memcmp(decoded.transaction_id, application.transaction_id, 16u) == 0);
    REQUIRE(memcmp(decoded.attempt_id, application.attempt_id, 16u) == 0);
    REQUIRE(memcmp(decoded.subject, application.subject, 16u) == 0);
    REQUIRE(decoded.absolute_effect_deadline_ms == NINLIL_NO_DEADLINE);
    REQUIRE(decoded.payload_len == 1u && decoded.payload[0] == 0x40u);
    REQUIRE(ninlil_nra1_validate_application_family(
                &decoded, NINLIL_FAMILY_EVENT_FACT)
        == NINLIL_NRA1_OK);
    return 0;
}

static int test_application_128_byte_kat(void)
{
    ninlil_nra1_application_t application;
    ninlil_nra1_application_t decoded;
    uint8_t expected[NINLIL_NRA1_APPLICATION_BODY_MAX];
    uint8_t body[NINLIL_NRA1_APPLICATION_BODY_MAX];
    size_t length = 0u;

    (void)memset(&application, 0, sizeof(application));
    application.service_slot = 31u;
    application.required_evidence = NINLIL_EVIDENCE_VERIFIED;
    fill_sequence(application.transaction_id, 16u, 0x01u);
    fill_sequence(application.attempt_id, 16u, 0x11u);
    application.subject[15] = 0x2au;
    application.absolute_effect_deadline_ms = UINT64_C(0x1020304050607080);
    application.payload_len = NINLIL_NRA1_APPLICATION_PAYLOAD_MAX;
    fill_sequence(application.payload, application.payload_len, 0x00u);

    (void)memset(expected, 0, sizeof(expected));
    expected[0] = 0x4eu;
    expected[1] = 0x52u;
    expected[2] = 0x41u;
    expected[3] = 0x31u;
    expected[4] = 0x01u;
    expected[5] = 0xfcu;
    (void)memcpy(expected + 6u, application.transaction_id, 16u);
    (void)memcpy(expected + 22u, application.attempt_id, 16u);
    expected[53] = 0x2au;
    expected[54] = 0x10u;
    expected[55] = 0x20u;
    expected[56] = 0x30u;
    expected[57] = 0x40u;
    expected[58] = 0x50u;
    expected[59] = 0x60u;
    expected[60] = 0x70u;
    expected[61] = 0x80u;
    (void)memcpy(
        expected + NINLIL_NRA1_APPLICATION_HEADER_BYTES,
        application.payload,
        application.payload_len);

    REQUIRE(ninlil_nra1_encode_application(
                &application, body, sizeof(body), &length)
        == NINLIL_NRA1_OK);
    REQUIRE(length == sizeof(expected));
    REQUIRE(memcmp(body, expected, sizeof(expected)) == 0);
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_OK);
    REQUIRE(memcmp(&decoded, &application, sizeof(application)) == 0);
    REQUIRE(ninlil_nra1_validate_application_family(
                &decoded, NINLIL_FAMILY_DESIRED_STATE)
        == NINLIL_NRA1_OK);
    return 0;
}

static int test_receipt_kat(void)
{
    static const uint8_t expected[NINLIL_NRA1_RECEIPT_BODY_BYTES] = {
        0x4e, 0x52, 0x41, 0x31, 0x02, 0x2b,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };
    ninlil_nra1_receipt_t receipt;
    ninlil_nra1_receipt_t decoded;
    uint8_t body[NINLIL_NRA1_RECEIPT_BODY_BYTES];
    size_t length = 0u;

    make_receipt(&receipt);
    REQUIRE(ninlil_nra1_encode_receipt(
                &receipt, body, sizeof(body), &length)
        == NINLIL_NRA1_OK);
    REQUIRE(length == sizeof(expected));
    REQUIRE(memcmp(body, expected, sizeof(expected)) == 0);
    REQUIRE(ninlil_nra1_decode_receipt(body, length, &decoded)
        == NINLIL_NRA1_OK);
    REQUIRE(memcmp(&decoded, &receipt, sizeof(receipt)) == 0);
    return 0;
}

static int test_lengths_and_structural_rejection(void)
{
    ninlil_nra1_application_t application;
    ninlil_nra1_application_t decoded;
    ninlil_nra1_receipt_t receipt;
    ninlil_nra1_receipt_t decoded_receipt;
    uint8_t body[NINLIL_NRA1_APPLICATION_BODY_MAX + 1u];
    size_t length = 0u;

    make_event_application(&application, 1u);
    application.payload_len = 0u;
    REQUIRE(ninlil_nra1_encode_application(
                &application, body, sizeof(body), &length)
        == NINLIL_NRA1_LENGTH);
    application.payload_len = NINLIL_NRA1_APPLICATION_PAYLOAD_MAX + 1u;
    REQUIRE(ninlil_nra1_encode_application(
                &application, body, sizeof(body), &length)
        == NINLIL_NRA1_LENGTH);

    make_event_application(&application, 1u);
    REQUIRE(ninlil_nra1_encode_application(
                &application, body, sizeof(body), &length)
        == NINLIL_NRA1_OK);
    REQUIRE(ninlil_nra1_decode_application(
                body, NINLIL_NRA1_APPLICATION_BODY_MIN - 1u, &decoded)
        == NINLIL_NRA1_LENGTH);
    REQUIRE(ninlil_nra1_decode_application(
                body, NINLIL_NRA1_APPLICATION_BODY_MAX + 1u, &decoded)
        == NINLIL_NRA1_LENGTH);

    body[0] ^= 0x01u;
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    body[0] ^= 0x01u;
    body[4] = NINLIL_NRA1_KIND_RECEIPT;
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    body[4] = NINLIL_NRA1_KIND_APPLICATION;
    body[5] = 0u;
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    body[5] = (uint8_t)((3u << 3u) | 5u);
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    body[5] = (uint8_t)((3u << 3u) | NINLIL_EVIDENCE_APPLIED);
    (void)memset(body + 6u, 0, 16u);
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_STRUCTURAL);

    make_receipt(&receipt);
    REQUIRE(ninlil_nra1_encode_receipt(
                &receipt, body, sizeof(body), &length)
        == NINLIL_NRA1_OK);
    REQUIRE(ninlil_nra1_decode_receipt(body, length - 1u, &decoded_receipt)
        == NINLIL_NRA1_LENGTH);
    REQUIRE(ninlil_nra1_decode_receipt(body, length + 1u, &decoded_receipt)
        == NINLIL_NRA1_LENGTH);
    body[5] = (uint8_t)(5u << 3u);
    REQUIRE(ninlil_nra1_decode_receipt(body, length, &decoded_receipt)
        == NINLIL_NRA1_STRUCTURAL);
    return 0;
}

static int test_family_semantics(void)
{
    ninlil_nra1_application_t application;

    make_event_application(&application, 1u);
    REQUIRE(ninlil_nra1_validate_application_family(
                &application, NINLIL_FAMILY_EVENT_FACT)
        == NINLIL_NRA1_OK);
    (void)memset(application.subject, 0, sizeof(application.subject));
    REQUIRE(ninlil_nra1_validate_application_family(
                &application, NINLIL_FAMILY_EVENT_FACT)
        == NINLIL_NRA1_SEMANTIC);
    application.subject[15] = 1u;
    application.absolute_effect_deadline_ms = 100u;
    REQUIRE(ninlil_nra1_validate_application_family(
                &application, NINLIL_FAMILY_EVENT_FACT)
        == NINLIL_NRA1_SEMANTIC);

    (void)memset(application.subject, 0, sizeof(application.subject));
    application.subject[15] = 1u;
    REQUIRE(ninlil_nra1_validate_application_family(
                &application, NINLIL_FAMILY_DESIRED_STATE)
        == NINLIL_NRA1_OK);
    application.subject[0] = 1u;
    REQUIRE(ninlil_nra1_validate_application_family(
                &application, NINLIL_FAMILY_DESIRED_STATE)
        == NINLIL_NRA1_SEMANTIC);
    application.subject[0] = 0u;
    application.absolute_effect_deadline_ms = NINLIL_NO_DEADLINE;
    REQUIRE(ninlil_nra1_validate_application_family(
                &application, NINLIL_FAMILY_DESIRED_STATE)
        == NINLIL_NRA1_SEMANTIC);
    REQUIRE(ninlil_nra1_validate_application_family(&application, 99u)
        == NINLIL_NRA1_UNSUPPORTED);
    return 0;
}

static int test_atomicity_capacity_and_alias(void)
{
    ninlil_nra1_application_t application;
    ninlil_nra1_application_t decoded;
    ninlil_nra1_application_t before;
    uint8_t body[NINLIL_NRA1_APPLICATION_BODY_MAX];
    uint8_t body_before[NINLIL_NRA1_APPLICATION_BODY_MAX];
    size_t length = 777u;
    union {
        ninlil_nra1_application_t application;
        uint8_t bytes[sizeof(ninlil_nra1_application_t)];
    } alias;

    make_event_application(&application, 1u);
    (void)memset(body, 0xa5, sizeof(body));
    (void)memcpy(body_before, body, sizeof(body));
    REQUIRE(ninlil_nra1_encode_application(
                &application, body, NINLIL_NRA1_APPLICATION_BODY_MIN - 1u,
                &length)
        == NINLIL_NRA1_CAPACITY);
    REQUIRE(length == 777u);
    REQUIRE(memcmp(body, body_before, sizeof(body)) == 0);

    application.service_slot = 0u;
    REQUIRE(ninlil_nra1_encode_application(
                &application, body, sizeof(body), &length)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(length == 777u);
    REQUIRE(memcmp(body, body_before, sizeof(body)) == 0);

    make_event_application(&alias.application, 1u);
    REQUIRE(ninlil_nra1_encode_application(
                &alias.application,
                alias.bytes,
                NINLIL_NRA1_APPLICATION_BODY_MAX,
                &length)
        == NINLIL_NRA1_ALIAS);

    make_event_application(&application, 1u);
    REQUIRE(ninlil_nra1_encode_application(
                &application, body, sizeof(body), &length)
        == NINLIL_NRA1_OK);
    (void)memset(&decoded, 0x5a, sizeof(decoded));
    before = decoded;
    body[0] ^= 1u;
    REQUIRE(ninlil_nra1_decode_application(body, length, &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memset(alias.bytes, 0xa5, sizeof(alias.bytes));
    REQUIRE(ninlil_nra1_decode_application(
                alias.bytes,
                NINLIL_NRA1_APPLICATION_BODY_MIN,
                &alias.application)
        == NINLIL_NRA1_ALIAS);
    return 0;
}

static int test_receipt_negative_atomicity_and_alias(void)
{
    ninlil_nra1_receipt_t receipt;
    ninlil_nra1_receipt_t decoded;
    ninlil_nra1_receipt_t before;
    uint8_t body[NINLIL_NRA1_RECEIPT_BODY_BYTES];
    uint8_t valid_body[NINLIL_NRA1_RECEIPT_BODY_BYTES];
    uint8_t body_before[NINLIL_NRA1_RECEIPT_BODY_BYTES];
    size_t length = 777u;
    union {
        ninlil_nra1_receipt_t receipt;
        uint8_t bytes[sizeof(ninlil_nra1_receipt_t)];
    } alias;

    make_receipt(&receipt);
    (void)memset(body, 0xa5, sizeof(body));
    (void)memcpy(body_before, body, sizeof(body));
    REQUIRE(ninlil_nra1_encode_receipt(
                &receipt, body, NINLIL_NRA1_RECEIPT_BODY_BYTES - 1u,
                &length)
        == NINLIL_NRA1_CAPACITY);
    REQUIRE(length == 777u);
    REQUIRE(memcmp(body, body_before, sizeof(body)) == 0);

    receipt.service_slot = 0u;
    REQUIRE(ninlil_nra1_encode_receipt(
                &receipt, body, sizeof(body), &length)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(length == 777u);
    REQUIRE(memcmp(body, body_before, sizeof(body)) == 0);

    make_receipt(&alias.receipt);
    REQUIRE(ninlil_nra1_encode_receipt(
                &alias.receipt, alias.bytes,
                NINLIL_NRA1_RECEIPT_BODY_BYTES, &length)
        == NINLIL_NRA1_ALIAS);

    make_receipt(&receipt);
    REQUIRE(ninlil_nra1_encode_receipt(
                &receipt, valid_body, sizeof(valid_body), &length)
        == NINLIL_NRA1_OK);
    (void)memset(&decoded, 0x5a, sizeof(decoded));
    before = decoded;

    (void)memcpy(body, valid_body, sizeof(body));
    body[0] ^= 1u;
    REQUIRE(ninlil_nra1_decode_receipt(body, sizeof(body), &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memcpy(body, valid_body, sizeof(body));
    body[4] = NINLIL_NRA1_KIND_APPLICATION;
    REQUIRE(ninlil_nra1_decode_receipt(body, sizeof(body), &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memcpy(body, valid_body, sizeof(body));
    body[5] = (uint8_t)(receipt.service_slot << 3u);
    REQUIRE(ninlil_nra1_decode_receipt(body, sizeof(body), &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memcpy(body, valid_body, sizeof(body));
    body[5] = (uint8_t)((receipt.service_slot << 3u) | 5u);
    REQUIRE(ninlil_nra1_decode_receipt(body, sizeof(body), &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memcpy(body, valid_body, sizeof(body));
    body[5] = receipt.receipt_stage;
    REQUIRE(ninlil_nra1_decode_receipt(body, sizeof(body), &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memcpy(body, valid_body, sizeof(body));
    (void)memset(body + 6u, 0, 16u);
    REQUIRE(ninlil_nra1_decode_receipt(body, sizeof(body), &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memcpy(body, valid_body, sizeof(body));
    (void)memset(body + 22u, 0, 16u);
    REQUIRE(ninlil_nra1_decode_receipt(body, sizeof(body), &decoded)
        == NINLIL_NRA1_STRUCTURAL);
    REQUIRE(memcmp(&decoded, &before, sizeof(decoded)) == 0);

    (void)memset(alias.bytes, 0xa5, sizeof(alias.bytes));
    REQUIRE(ninlil_nra1_decode_receipt(
                alias.bytes, NINLIL_NRA1_RECEIPT_BODY_BYTES,
                &alias.receipt)
        == NINLIL_NRA1_ALIAS);
    return 0;
}

int main(void)
{
    if (test_application_one_byte_kat() != 0
        || test_application_128_byte_kat() != 0
        || test_receipt_kat() != 0
        || test_lengths_and_structural_rejection() != 0
        || test_family_semantics() != 0
        || test_atomicity_capacity_and_alias() != 0
        || test_receipt_negative_atomicity_and_alias() != 0) {
        return 1;
    }
    (void)printf("nra1 codec tests passed\n");
    return 0;
}
