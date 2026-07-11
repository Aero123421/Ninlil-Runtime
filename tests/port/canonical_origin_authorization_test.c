#include "canonical_origin_authorization.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",       \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct fixture {
    ninlil_test_origin_auth_t *provider;
    const ninlil_origin_authorization_ops_t *ops;
} fixture_t;

static ninlil_id128_t marked_id(uint8_t first, uint8_t last)
{
    ninlil_id128_t id = {{0u}};
    id.bytes[0] = first;
    id.bytes[15] = last;
    return id;
}

static int hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    return -1;
}

static int decode_hex(const char *hex, uint8_t *output, size_t length)
{
    size_t index;
    for (index = 0u; index < length; ++index) {
        int high = hex_value(hex[index * 2u]);
        int low = hex_value(hex[index * 2u + 1u]);
        if (high < 0 || low < 0) {
            return 0;
        }
        output[index] = (uint8_t)((high << 4) | low);
    }
    return hex[length * 2u] == '\0';
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static void set_text(ninlil_text_id_t *text, const char *value)
{
    size_t length = strlen(value);
    (void)memset(text, 0, sizeof(*text));
    text->length = (uint8_t)length;
    (void)memcpy(text->bytes, value, length);
}

static ninlil_origin_authorization_request_t canonical_request(uint64_t now_ms)
{
    ninlil_origin_authorization_request_t request;
    (void)memset(&request, 0, sizeof(request));
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    request.environment = NINLIL_ENV_TEST;
    set_header(&request.source.abi_version, &request.source.struct_size,
        sizeof(request.source));
    request.source.runtime_id = marked_id(0x41u, 1u);
    request.source.application_instance_id = marked_id(0x60u, 1u);
    set_header(&request.source.local_identity.abi_version,
        &request.source.local_identity.struct_size,
        sizeof(request.source.local_identity));
    request.source.local_identity.device_id = marked_id(0x40u, 1u);
    request.source.local_identity.installation_id = marked_id(0x50u, 1u);
    request.source.local_identity.site_domain_id = marked_id(0x10u, 1u);
    request.source.local_identity.binding_epoch = 1u;
    request.source.local_identity.membership_epoch = 1u;
    request.source.local_identity.flags = 7u;
    set_header(&request.target.abi_version, &request.target.struct_size,
        sizeof(request.target));
    request.target.target_runtime_id = marked_id(0x21u, 1u);
    request.target.target_application_instance_id = marked_id(0x30u, 1u);
    request.target.device_id = marked_id(0x20u, 1u);
    request.target.installation_id = marked_id(0x50u, 2u);
    request.target.site_domain_id = marked_id(0x10u, 1u);
    request.target.binding_epoch = 1u;
    request.target.membership_epoch = 1u;
    request.target.flags = 7u;
    set_header(&request.service.abi_version, &request.service.struct_size,
        sizeof(request.service));
    set_text(&request.service.namespace_id, "org.ninlil.examples");
    set_text(&request.service.service_id, "durable-event");
    set_text(&request.service.schema_id, "durable-event");
    request.service.descriptor_revision = 1u;
    request.service.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)decode_hex(
        "f64b7c4abf5b9db38b1c9fef0f0e8c341b56caddadb291ebc5456ccbd2aa321b",
        request.service.descriptor_digest.bytes, 32u);
    request.service.schema_major = 1u;
    request.service.schema_minor = 0u;
    request.service.family = NINLIL_FAMILY_EVENT_FACT;
    request.event_id = marked_id(0x90u, 1u);
    request.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    request.content_digest.bytes[0] = 0xc7u;
    request.required_evidence = NINLIL_EVIDENCE_DURABLY_RECORDED;
    request.payload_length = 10u;
    request.current_window_started_at_ms = now_ms - (now_ms % 10000u);
    set_header(&request.now.abi_version, &request.now.struct_size,
        sizeof(request.now));
    request.now.clock_epoch_id = marked_id(0xa0u, 1u);
    request.now.now_ms = now_ms;
    request.now.trust = NINLIL_CLOCK_TRUSTED;
    return request;
}

static fixture_t make_fixture(void)
{
    fixture_t fixture;
    fixture.provider = ninlil_test_origin_auth_create();
    fixture.ops = ninlil_test_origin_auth_ops(fixture.provider);
    return fixture;
}

static void destroy_fixture(fixture_t *fixture)
{
    ninlil_test_origin_auth_destroy(fixture->provider);
    (void)memset(fixture, 0, sizeof(*fixture));
}

static ninlil_origin_auth_status_t evaluate(
    fixture_t *fixture,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)memset(decision, 0xa5, sizeof(*decision));
    return fixture->ops->evaluate(fixture->ops->user, request, decision);
}

static int is_all_zero(const void *value, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)value;
    size_t index;
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int expect_deny(
    fixture_t *fixture,
    const ninlil_origin_authorization_request_t *request,
    ninlil_reason_t reason,
    ninlil_retry_guidance_t guidance,
    uint64_t delay)
{
    ninlil_origin_authorization_decision_t decision;
    if (evaluate(fixture, request, &decision) != NINLIL_ORIGIN_AUTH_OK
        || decision.allowed != 0u || decision.reason != reason
        || decision.retry_guidance != guidance
        || decision.retry_delay_ms != delay
        || decision.abi_version != NINLIL_ABI_VERSION
        || decision.provider_id.bytes[0] != 0x80u
        || decision.provider_id.bytes[15] != 1u
        || decision.provider_revision != 1u
        || decision.decision_digest.algorithm != NINLIL_DIGEST_SHA256
        || is_all_zero(decision.decision_digest.bytes,
            sizeof(decision.decision_digest.bytes))
        || memcmp(&decision.clock_epoch_id, &request->now.clock_epoch_id,
            sizeof(decision.clock_epoch_id)) != 0
        || decision.evaluated_at_ms != request->now.now_ms
        || decision.grant_revision != 0u
        || !is_all_zero(&decision.grant_id, sizeof(decision.grant_id))
        || decision.valid_from_ms != 0u || decision.expires_at_ms != 0u
        || decision.max_payload_bytes != 0u
        || decision.max_active_spool_count != 0u
        || decision.max_active_spool_bytes != 0u
        || decision.rate_window_ms != 0u
        || decision.max_admissions_per_window != 0u
        || decision.max_attempts_per_retry_cycle != 0u) {
        return 0;
    }
    return 1;
}

static int expect_permanent_zero(
    fixture_t *fixture,
    const ninlil_origin_authorization_request_t *request)
{
    ninlil_origin_authorization_decision_t decision;
    return evaluate(fixture, request, &decision)
            == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE
        && is_all_zero(&decision, sizeof(decision));
}

static int test_oa1_allow_exact(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request = canonical_request(0u);
    ninlil_origin_authorization_decision_t decision;
    ninlil_origin_authorization_decision_t retained;
    uint8_t expected_digest[32];
    REQUIRE(fixture.provider != NULL && fixture.ops != NULL);
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(decision.abi_version == NINLIL_ABI_VERSION);
    REQUIRE(decision.struct_size == sizeof(decision));
    REQUIRE(decision.allowed == 1u);
    REQUIRE(decision.reason == NINLIL_REASON_NONE);
    REQUIRE(decision.retry_guidance == NINLIL_RETRY_NEVER);
    REQUIRE(decision.retry_delay_ms == 0u);
    REQUIRE(decision.provider_id.bytes[0] == 0x80u
        && decision.provider_id.bytes[15] == 1u);
    REQUIRE(decision.provider_revision == 1u);
    REQUIRE(decision.grant_id.bytes[0] == 0x70u
        && decision.grant_id.bytes[15] == 1u);
    REQUIRE(decision.grant_revision == 1u);
    REQUIRE(decode_hex(
        "3b3e9cae32f01600e4a0553339f978744f87b0af03506c1db1d484c2a2b63c93",
        expected_digest, sizeof(expected_digest)));
    REQUIRE(memcmp(decision.decision_digest.bytes,
        expected_digest, sizeof(expected_digest)) == 0);
    REQUIRE(decision.clock_epoch_id.bytes[0] == 0xa0u);
    REQUIRE(decision.evaluated_at_ms == 0u);
    REQUIRE(decision.valid_from_ms == 0u);
    REQUIRE(decision.expires_at_ms == 86400000u);
    REQUIRE(decision.max_payload_bytes == 1024u);
    REQUIRE(decision.max_active_spool_count == 32u);
    REQUIRE(decision.max_active_spool_bytes == 32768u);
    REQUIRE(decision.rate_window_ms == 10000u);
    REQUIRE(decision.max_admissions_per_window == 8u);
    REQUIRE(decision.max_attempts_per_retry_cycle == 8u);
    retained = decision;
    (void)memset(&request, 0x5a, sizeof(request));
    REQUIRE(memcmp(&decision, &retained, sizeof(decision)) == 0);
    REQUIRE(ninlil_test_origin_auth_allow_count(fixture.provider) == 1u);
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa2_clock_expiry(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    request = canonical_request(86399999u);
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(decision.allowed == 1u);
    request = canonical_request(86400000u);
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    request = canonical_request(0u);
    request.now.trust = NINLIL_CLOCK_UNCERTAIN;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_CLOCK_UNCERTAIN,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    request = canonical_request(0u);
    request.now.clock_epoch_id.bytes[15] = 2u;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_CLOCK_UNCERTAIN,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    request = canonical_request(0u);
    (void)memset(&request.now.clock_epoch_id, 0,
        sizeof(request.now.clock_epoch_id));
    REQUIRE(expect_permanent_zero(&fixture, &request));
    request = canonical_request(0u);
    request.now.trust = 0u;
    REQUIRE(expect_permanent_zero(&fixture, &request));
    request = canonical_request(0u);
    request.now.trust = 99u;
    REQUIRE(expect_permanent_zero(&fixture, &request));
    request = canonical_request(9999u);
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    request = canonical_request(10000u);
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    request.current_window_started_at_ms = 0u;
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE);
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa3_binding(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request;
    uint32_t mutation;
    for (mutation = 0u; mutation < 17u; ++mutation) {
        request = canonical_request(0u);
        switch (mutation) {
        case 0u: request.source.runtime_id.bytes[1] ^= 1u; break;
        case 1u: request.source.application_instance_id.bytes[1] ^= 1u; break;
        case 2u: request.source.local_identity.device_id.bytes[1] ^= 1u; break;
        case 3u: request.source.local_identity.installation_id.bytes[1] ^= 1u; break;
        case 4u: request.source.local_identity.site_domain_id.bytes[1] ^= 1u; break;
        case 5u:
            request.source.local_identity.flags = 5u;
            (void)memset(&request.source.local_identity.installation_id,
                0, sizeof(request.source.local_identity.installation_id));
            break;
        case 6u: request.source.local_identity.binding_epoch = 2u; break;
        case 7u: request.source.local_identity.membership_epoch = 2u; break;
        case 8u: request.service.namespace_id.bytes[1] ^= 1u; break;
        case 9u: request.service.service_id.bytes[1] ^= 1u; break;
        case 10u: request.service.schema_id.bytes[1] ^= 1u; break;
        case 11u: request.service.descriptor_revision = 2u; break;
        case 12u: request.service.descriptor_digest.bytes[1] ^= 1u; break;
        case 13u: request.service.schema_major = 2u; break;
        case 14u: request.service.schema_minor = 1u; break;
        case 15u: request.service.family = NINLIL_FAMILY_DESIRED_STATE; break;
        default: request.required_evidence = NINLIL_EVIDENCE_APPLIED; break;
        }
        REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_GRANT_INVALID,
            NINLIL_RETRY_OPERATOR_ACTION, 0u));
    }
    /* Each alternate, structurally valid source presence snapshot is a bind
     * mismatch rather than a malformed request. */
    request = canonical_request(0u);
    request.source.local_identity.flags &=
        ~NINLIL_LOCAL_IDENTITY_HAS_DEVICE;
    (void)memset(&request.source.local_identity.device_id, 0,
        sizeof(request.source.local_identity.device_id));
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_GRANT_INVALID,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    request = canonical_request(0u);
    request.source.local_identity.flags &=
        ~NINLIL_LOCAL_IDENTITY_HAS_SITE;
    (void)memset(&request.source.local_identity.site_domain_id, 0,
        sizeof(request.source.local_identity.site_domain_id));
    request.source.local_identity.membership_epoch = 0u;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_GRANT_INVALID,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    for (mutation = 0u; mutation < 8u; ++mutation) {
        request = canonical_request(0u);
        switch (mutation) {
        case 0u: request.target.target_runtime_id.bytes[1] ^= 1u; break;
        case 1u: request.target.target_application_instance_id.bytes[1] ^= 1u; break;
        case 2u: request.target.device_id.bytes[1] ^= 1u; break;
        case 3u: request.target.installation_id.bytes[1] ^= 1u; break;
        case 4u: request.target.site_domain_id.bytes[1] ^= 1u; break;
        case 5u:
            request.target.flags = 5u;
            (void)memset(&request.target.installation_id, 0,
                sizeof(request.target.installation_id));
            break;
        case 6u: request.target.binding_epoch = 2u; break;
        default: request.target.membership_epoch = 2u; break;
        }
        REQUIRE(expect_deny(&fixture, &request,
            NINLIL_REASON_TARGET_UNAUTHORIZED,
            NINLIL_RETRY_MODIFIED, 0u));
    }
    request = canonical_request(0u);
    request.target.flags &= ~NINLIL_TARGET_HAS_DEVICE;
    (void)memset(&request.target.device_id, 0,
        sizeof(request.target.device_id));
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_TARGET_UNAUTHORIZED, NINLIL_RETRY_MODIFIED, 0u));
    request = canonical_request(0u);
    request.target.flags &= ~NINLIL_TARGET_HAS_SITE;
    (void)memset(&request.target.site_domain_id, 0,
        sizeof(request.target.site_domain_id));
    request.target.membership_epoch = 0u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_TARGET_UNAUTHORIZED, NINLIL_RETRY_MODIFIED, 0u));
    request = canonical_request(0u);
    request.event_id.bytes[15] = 9u;
    request.content_digest.bytes[0] = 0x55u;
    {
        ninlil_origin_authorization_decision_t decision;
        REQUIRE(evaluate(&fixture, &request, &decision)
            == NINLIL_ORIGIN_AUTH_OK);
        REQUIRE(decision.allowed == 1u);
    }
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa4_limit_precedence(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    request = canonical_request(0u);
    request.payload_length = 1024u;
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(decision.allowed == 1u);
    request.payload_length = 1025u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    request = canonical_request(0u);
    request.active_spool_count = 31u;
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    request.active_spool_count = 32u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    request = canonical_request(0u);
    request.active_spool_bytes = 30198u;
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    request.active_spool_bytes = 30199u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    request.active_spool_bytes = UINT64_MAX;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    REQUIRE(ninlil_test_origin_auth_arithmetic_overflow_count(
        fixture.provider) == 1u);
    request = canonical_request(0u);
    request.admissions_in_current_window = 7u;
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    request.admissions_in_current_window = 8u;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_RATE_EXHAUSTED,
        NINLIL_RETRY_SAME_AFTER, 10000u));
    request = canonical_request(5000u);
    request.admissions_in_current_window = 8u;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_RATE_EXHAUSTED,
        NINLIL_RETRY_SAME_AFTER, 5000u));
    request.payload_length = 1025u;
    request.active_spool_count = 32u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));

    /* Pairwise compound cases prove count -> bytes -> rate precedence. */
    request = canonical_request(0u);
    request.active_spool_count = 32u;
    request.active_spool_bytes = UINT64_MAX;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    REQUIRE(ninlil_test_origin_auth_arithmetic_overflow_count(
        fixture.provider) == 1u);
    request = canonical_request(0u);
    request.active_spool_count = 32u;
    request.admissions_in_current_window = 8u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    request = canonical_request(0u);
    request.active_spool_bytes = UINT64_MAX;
    request.admissions_in_current_window = 8u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    REQUIRE(ninlil_test_origin_auth_arithmetic_overflow_count(
        fixture.provider) == 2u);
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa5_stateless_and_diagnostics(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request = canonical_request(0u);
    ninlil_origin_authorization_decision_t decision;
    uint32_t index;
    for (index = 0u; index < 100000u; ++index) {
        REQUIRE(evaluate(&fixture, &request, &decision)
            == NINLIL_ORIGIN_AUTH_OK);
        REQUIRE(decision.allowed == 1u);
    }
    REQUIRE(ninlil_test_origin_auth_call_count(fixture.provider) == 100000u);
    REQUIRE(ninlil_test_origin_auth_allow_count(fixture.provider) == 100000u);
    REQUIRE(ninlil_test_origin_auth_trace_count(fixture.provider)
        == NINLIL_TEST_ORIGIN_AUTH_TRACE_CAPACITY);
    REQUIRE(ninlil_test_origin_auth_trace_overflowed(fixture.provider));
    REQUIRE(ninlil_test_origin_auth_trace_at(fixture.provider, 0u)->sequence
        == 1u);
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa6_closed_output(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request = canonical_request(0u);
    ninlil_origin_authorization_decision_t decision;
    ninlil_origin_authorization_decision_t poison;
    ninlil_origin_authorization_decision_t partial_allow;
    ninlil_origin_authorization_decision_t partial_deny;
    (void)memset(&poison, 0x5a, sizeof(poison));

    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE, NULL, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE);
    REQUIRE(is_all_zero(&decision, sizeof(decision)));
    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE, NULL, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE);
    REQUIRE(is_all_zero(&decision, sizeof(decision)));

    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        (ninlil_origin_auth_status_t)99u, &poison, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision) == 99u);
    REQUIRE(memcmp(&decision, &poison, sizeof(decision)) == 0);
    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE, &poison, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE);
    REQUIRE(memcmp(&decision, &poison, sizeof(decision)) == 0);

    request = canonical_request(0u);
    REQUIRE(evaluate(&fixture, &request, &partial_allow)
        == NINLIL_ORIGIN_AUTH_OK);
    partial_allow.decision_digest.algorithm = 0u;
    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_OK, &partial_allow, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(memcmp(&decision, &partial_allow, sizeof(decision)) == 0);

    request = canonical_request(0u);
    request.now.trust = NINLIL_CLOCK_UNCERTAIN;
    REQUIRE(evaluate(&fixture, &request, &partial_deny)
        == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(partial_deny.allowed == 0u);
    (void)memset(&partial_deny.provider_id, 0,
        sizeof(partial_deny.provider_id));
    request = canonical_request(0u);
    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_OK, &partial_deny, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(memcmp(&decision, &partial_deny, sizeof(decision)) == 0);
    REQUIRE(decision.allowed == 0u);

    REQUIRE(ninlil_test_origin_auth_raw_count(fixture.provider) == 6u);
    REQUIRE(ninlil_test_origin_auth_temporary_count(fixture.provider) == 2u);
    REQUIRE(ninlil_test_origin_auth_permanent_count(fixture.provider) == 1u);
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa7_fault_fifo_and_validation(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    uint32_t mutation;

    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE, NULL, 2u));
    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE, NULL, 1u));

    /* Structural mutation table: all malformed source/service/target shapes
     * retain both FIFO entries and the head remaining count. */
    for (mutation = 0u; mutation < 30u; ++mutation) {
        request = canonical_request(0u);
        switch (mutation) {
        case 0u: request.abi_version = 0u; break;
        case 1u: request.struct_size = 0u; break;
        case 2u: request.source.abi_version = 0u; break;
        case 3u: request.source.struct_size = 0u; break;
        case 4u:
            (void)memset(&request.source.runtime_id, 0,
                sizeof(request.source.runtime_id));
            break;
        case 5u:
            (void)memset(&request.source.application_instance_id, 0,
                sizeof(request.source.application_instance_id));
            break;
        case 6u: request.source.local_identity.abi_version = 0u; break;
        case 7u: request.source.local_identity.struct_size = 0u; break;
        case 8u: request.source.local_identity.reserved_zero = 1u; break;
        case 9u: request.source.local_identity.binding_epoch = 0u; break;
        case 10u: request.source.local_identity.membership_epoch = 0u; break;
        case 11u:
            request.source.local_identity.flags &=
                ~(NINLIL_LOCAL_IDENTITY_HAS_DEVICE
                    | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION);
            (void)memset(&request.source.local_identity.device_id, 0,
                sizeof(request.source.local_identity.device_id));
            (void)memset(&request.source.local_identity.installation_id, 0,
                sizeof(request.source.local_identity.installation_id));
            break;
        case 12u:
            request.source.local_identity.flags &=
                ~NINLIL_LOCAL_IDENTITY_HAS_SITE;
            (void)memset(&request.source.local_identity.site_domain_id, 0,
                sizeof(request.source.local_identity.site_domain_id));
            break;
        case 13u: request.target.abi_version = 0u; break;
        case 14u: request.target.struct_size = 0u; break;
        case 15u: request.target.reserved_zero = 1u; break;
        case 16u:
            (void)memset(&request.target.target_runtime_id, 0,
                sizeof(request.target.target_runtime_id));
            break;
        case 17u:
            (void)memset(&request.target.target_application_instance_id, 0,
                sizeof(request.target.target_application_instance_id));
            break;
        case 18u: request.target.binding_epoch = 0u; break;
        case 19u: request.target.membership_epoch = 0u; break;
        case 20u:
            request.target.flags &= ~(NINLIL_TARGET_HAS_DEVICE
                | NINLIL_TARGET_HAS_INSTALLATION);
            (void)memset(&request.target.device_id, 0,
                sizeof(request.target.device_id));
            (void)memset(&request.target.installation_id, 0,
                sizeof(request.target.installation_id));
            break;
        case 21u:
            request.target.flags &= ~NINLIL_TARGET_HAS_SITE;
            (void)memset(&request.target.site_domain_id, 0,
                sizeof(request.target.site_domain_id));
            break;
        case 22u: request.service.abi_version = 0u; break;
        case 23u: request.service.struct_size = 0u; break;
        case 24u:
            request.service.namespace_id.bytes[
                request.service.namespace_id.length] = 1u;
            break;
        case 25u:
            request.service.service_id.bytes[
                request.service.service_id.length] = 1u;
            break;
        case 26u:
            request.service.schema_id.bytes[
                request.service.schema_id.length] = 1u;
            break;
        case 27u: request.service.descriptor_digest.algorithm = 0u; break;
        case 28u: request.service.descriptor_digest.reserved_zero = 1u; break;
        default: request.service.family = 7u; break;
        }
        REQUIRE(expect_permanent_zero(&fixture, &request));
        REQUIRE(ninlil_test_origin_auth_fault_consumed_count(
            fixture.provider) == 0u);
    }

    request = canonical_request(0u);
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE);
    REQUIRE(ninlil_test_origin_auth_fault_consumed_count(
        fixture.provider) == 1u);
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE);
    REQUIRE(ninlil_test_origin_auth_fault_consumed_count(
        fixture.provider) == 2u);
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE);
    REQUIRE(ninlil_test_origin_auth_fault_consumed_count(
        fixture.provider) == 3u);
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(decision.allowed == 1u);
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa8_guard_and_oa9_core_boundary(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request = canonical_request(0u);
    ninlil_origin_authorization_request_t retained_request;
    ninlil_origin_authorization_decision_t natural_allow;
    ninlil_origin_authorization_decision_t decision;

    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE, NULL, 1u));
    request.environment = NINLIL_ENV_PRODUCTION_RESERVED;
    REQUIRE(expect_permanent_zero(&fixture, &request));
    REQUIRE(ninlil_test_origin_auth_fault_consumed_count(
        fixture.provider) == 0u);
    REQUIRE(ninlil_test_origin_auth_raw_count(fixture.provider) == 0u);
    request = canonical_request(0u);
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE);
    REQUIRE(ninlil_test_origin_auth_fault_consumed_count(
        fixture.provider) == 1u);

    request = canonical_request(0u);
    REQUIRE(evaluate(&fixture, &request, &natural_allow)
        == NINLIL_ORIGIN_AUTH_OK);

    /*
     * OA9 proves both natural DENY and the forced valid ALLOW seam leave the
     * provider stateless: the caller-owned quota snapshot is unchanged and a
     * later natural evaluation sees exactly the same count. Core prospective
     * deny/delay/durable charge/double-charge remain the AQ integration gate.
     */
    request = canonical_request(0u);
    request.active_spool_count = 32u;
    retained_request = request;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    REQUIRE(memcmp(&request, &retained_request, sizeof(request)) == 0);
    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_OK, &natural_allow, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(decision.allowed == 1u);
    REQUIRE(memcmp(&request, &retained_request, sizeof(request)) == 0);
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    REQUIRE(ninlil_test_origin_auth_raw_count(fixture.provider) == 2u);
    destroy_fixture(&fixture);
    return 0;
}

static int test_oa10_diagnostics(void)
{
    fixture_t fixture = make_fixture();
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    const ninlil_test_origin_auth_trace_record_t *trace;
    uint32_t calls;

    request = canonical_request(0u);
    REQUIRE(evaluate(&fixture, &request, &decision) == NINLIL_ORIGIN_AUTH_OK);
    request.now.trust = NINLIL_CLOCK_UNCERTAIN;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_CLOCK_UNCERTAIN,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    request = canonical_request(0u);
    request.source.runtime_id.bytes[1] = 1u;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_GRANT_INVALID,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    request = canonical_request(0u);
    request.target.target_runtime_id.bytes[1] = 1u;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_TARGET_UNAUTHORIZED, NINLIL_RETRY_MODIFIED, 0u));
    request = canonical_request(86400000u);
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_GRANT_EXPIRED,
        NINLIL_RETRY_OPERATOR_ACTION, 0u));
    request = canonical_request(0u);
    request.active_spool_bytes = UINT64_MAX;
    REQUIRE(expect_deny(&fixture, &request,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
        NINLIL_RETRY_SAME_AFTER, 1000u));
    request = canonical_request(0u);
    request.admissions_in_current_window = 8u;
    REQUIRE(expect_deny(&fixture, &request, NINLIL_REASON_RATE_EXHAUSTED,
        NINLIL_RETRY_SAME_AFTER, 10000u));
    request = canonical_request(0u);
    request.service.namespace_id.bytes[request.service.namespace_id.length]
        = 1u;
    REQUIRE(expect_permanent_zero(&fixture, &request));
    request = canonical_request(0u);
    REQUIRE(ninlil_test_origin_auth_raw_enqueue(fixture.provider,
        NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE, NULL, 1u));
    REQUIRE(evaluate(&fixture, &request, &decision)
        == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE);
    request.environment = NINLIL_ENV_PRODUCTION_RESERVED;
    REQUIRE(expect_permanent_zero(&fixture, &request));

    REQUIRE(ninlil_test_origin_auth_allow_count(fixture.provider) == 1u);
    REQUIRE(ninlil_test_origin_auth_deny_count(fixture.provider,
        NINLIL_REASON_CLOCK_UNCERTAIN) == 1u);
    REQUIRE(ninlil_test_origin_auth_deny_count(fixture.provider,
        NINLIL_REASON_GRANT_INVALID) == 1u);
    REQUIRE(ninlil_test_origin_auth_deny_count(fixture.provider,
        NINLIL_REASON_TARGET_UNAUTHORIZED) == 1u);
    REQUIRE(ninlil_test_origin_auth_deny_count(fixture.provider,
        NINLIL_REASON_GRANT_EXPIRED) == 1u);
    REQUIRE(ninlil_test_origin_auth_deny_count(fixture.provider,
        NINLIL_REASON_GRANT_LIMIT_EXCEEDED) == 1u);
    REQUIRE(ninlil_test_origin_auth_deny_count(fixture.provider,
        NINLIL_REASON_RATE_EXHAUSTED) == 1u);
    REQUIRE(ninlil_test_origin_auth_temporary_count(fixture.provider) == 1u);
    REQUIRE(ninlil_test_origin_auth_permanent_count(fixture.provider) == 2u);
    REQUIRE(ninlil_test_origin_auth_raw_count(fixture.provider) == 1u);
    REQUIRE(ninlil_test_origin_auth_validation_failure_count(
        fixture.provider) == 1u);
    REQUIRE(ninlil_test_origin_auth_fault_consumed_count(
        fixture.provider) == 1u);
    REQUIRE(ninlil_test_origin_auth_arithmetic_overflow_count(
        fixture.provider) == 1u);

    trace = ninlil_test_origin_auth_trace_at(fixture.provider, 1u);
    REQUIRE(trace != NULL && trace->sequence == 2u
        && trace->status == NINLIL_ORIGIN_AUTH_OK
        && trace->allowed == 0u
        && trace->reason == NINLIL_REASON_CLOCK_UNCERTAIN
        && trace->fault_consumed == 0u
        && trace->validation_failure == 0u);
    trace = ninlil_test_origin_auth_trace_at(fixture.provider, 7u);
    REQUIRE(trace != NULL && trace->sequence == 8u
        && trace->status == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE
        && trace->fault_consumed == 0u
        && trace->validation_failure == 1u);
    trace = ninlil_test_origin_auth_trace_at(fixture.provider, 8u);
    REQUIRE(trace != NULL && trace->sequence == 9u
        && trace->status == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE
        && trace->fault_consumed == 1u
        && trace->validation_failure == 0u);
    trace = ninlil_test_origin_auth_trace_at(fixture.provider, 9u);
    REQUIRE(trace != NULL && trace->sequence == 10u
        && trace->environment == NINLIL_ENV_PRODUCTION_RESERVED
        && trace->status == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE
        && trace->fault_consumed == 0u
        && trace->validation_failure == 0u);

    request = canonical_request(0u);
    for (calls = 10u;
         calls <= (uint32_t)NINLIL_TEST_ORIGIN_AUTH_TRACE_CAPACITY;
         ++calls) {
        REQUIRE(evaluate(&fixture, &request, &decision)
            == NINLIL_ORIGIN_AUTH_OK);
    }
    REQUIRE(ninlil_test_origin_auth_call_count(fixture.provider)
        == NINLIL_TEST_ORIGIN_AUTH_TRACE_CAPACITY + 1u);
    REQUIRE(ninlil_test_origin_auth_trace_count(fixture.provider)
        == NINLIL_TEST_ORIGIN_AUTH_TRACE_CAPACITY);
    REQUIRE(ninlil_test_origin_auth_trace_overflowed(fixture.provider));
    destroy_fixture(&fixture);
    return 0;
}

int main(void)
{
    if (test_oa1_allow_exact() != 0
        || test_oa2_clock_expiry() != 0
        || test_oa3_binding() != 0
        || test_oa4_limit_precedence() != 0
        || test_oa5_stateless_and_diagnostics() != 0
        || test_oa6_closed_output() != 0
        || test_oa7_fault_fifo_and_validation() != 0
        || test_oa8_guard_and_oa9_core_boundary() != 0
        || test_oa10_diagnostics() != 0) {
        return 1;
    }
    return 0;
}
