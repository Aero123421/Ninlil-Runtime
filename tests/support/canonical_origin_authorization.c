#include "canonical_origin_authorization.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define ORIGIN_AUTH_VALID_FROM_MS ((uint64_t)0u)
#define ORIGIN_AUTH_EXPIRES_AT_MS ((uint64_t)86400000u)
#define ORIGIN_AUTH_MAX_PAYLOAD ((uint32_t)1024u)
#define ORIGIN_AUTH_MAX_ACTIVE_COUNT ((uint32_t)32u)
#define ORIGIN_AUTH_MAX_ACTIVE_BYTES ((uint64_t)32768u)
#define ORIGIN_AUTH_WINDOW_MS ((uint32_t)10000u)
#define ORIGIN_AUTH_MAX_WINDOW_COUNT ((uint32_t)8u)
#define ORIGIN_AUTH_LIMIT_RETRY_MS ((uint64_t)1000u)
#define ORIGIN_AUTH_EVENT_OVERHEAD ((uint64_t)2560u)

typedef struct raw_outcome {
    ninlil_origin_auth_status_t status;
    ninlil_origin_authorization_decision_t decision;
    uint32_t remaining;
} raw_outcome_t;

struct ninlil_test_origin_auth {
    ninlil_origin_authorization_ops_t ops;
    raw_outcome_t faults[NINLIL_TEST_ORIGIN_AUTH_FAULT_CAPACITY];
    size_t fault_head;
    size_t fault_count;
    ninlil_test_origin_auth_trace_record_t
        trace[NINLIL_TEST_ORIGIN_AUTH_TRACE_CAPACITY];
    size_t trace_count;
    int trace_overflowed;
    uint64_t next_trace_sequence;
    uint64_t call_count;
    uint64_t allow_count;
    uint64_t deny_grant_invalid;
    uint64_t deny_target_unauthorized;
    uint64_t deny_grant_expired;
    uint64_t deny_grant_limit;
    uint64_t deny_rate;
    uint64_t deny_clock;
    uint64_t temporary_count;
    uint64_t permanent_count;
    uint64_t raw_count;
    uint64_t validation_failure_count;
    uint64_t fault_consumed_count;
    uint64_t arithmetic_overflow_count;
};

static ninlil_origin_auth_status_t fixture_evaluate(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision);

static const uint8_t id_site[16] = {
    0x10u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_controller_device[16] = {
    0x20u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_controller_runtime[16] = {
    0x21u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_controller_application[16] = {
    0x30u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_endpoint_device[16] = {
    0x40u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_endpoint_runtime[16] = {
    0x41u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_endpoint_installation[16] = {
    0x50u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_controller_installation[16] = {
    0x50u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u
};
static const uint8_t id_endpoint_application[16] = {
    0x60u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_grant[16] = {
    0x70u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_provider[16] = {
    0x80u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t id_clock_epoch[16] = {
    0xa0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const uint8_t descriptor_digest_bytes[32] = {
    0xf6u, 0x4bu, 0x7cu, 0x4au, 0xbfu, 0x5bu, 0x9du, 0xb3u,
    0x8bu, 0x1cu, 0x9fu, 0xefu, 0x0fu, 0x0eu, 0x8cu, 0x34u,
    0x1bu, 0x56u, 0xcau, 0xddu, 0xadu, 0xb2u, 0x91u, 0xebu,
    0xc5u, 0x45u, 0x6cu, 0xcbu, 0xd2u, 0xaau, 0x32u, 0x1bu
};
static const uint8_t decision_digest_bytes[32] = {
    0x3bu, 0x3eu, 0x9cu, 0xaeu, 0x32u, 0xf0u, 0x16u, 0x00u,
    0xe4u, 0xa0u, 0x55u, 0x33u, 0x39u, 0xf9u, 0x78u, 0x74u,
    0x4fu, 0x87u, 0xb0u, 0xafu, 0x03u, 0x50u, 0x6cu, 0x1du,
    0xb1u, 0xd4u, 0x84u, 0xc2u, 0xa2u, 0xb6u, 0x3cu, 0x93u
};

static int abi_header_valid(uint16_t version, uint16_t size, size_t required)
{
    return version == NINLIL_ABI_VERSION && (size_t)size >= required;
}

static int bytes_any_nonzero(const uint8_t *bytes, size_t length)
{
    size_t index;
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int id_valid(const ninlil_id128_t *id)
{
    return id != NULL && bytes_any_nonzero(id->bytes, sizeof(id->bytes));
}

static int id_is_zero(const ninlil_id128_t *id)
{
    return id != NULL && !bytes_any_nonzero(id->bytes, sizeof(id->bytes));
}

static int id_matches(const ninlil_id128_t *id, const uint8_t expected[16])
{
    return id != NULL && memcmp(id->bytes, expected, 16u) == 0;
}

static int digest_valid(const ninlil_digest256_t *digest)
{
    return digest != NULL
        && digest->algorithm == NINLIL_DIGEST_SHA256
        && digest->reserved_zero == 0u
        && bytes_any_nonzero(digest->bytes, sizeof(digest->bytes));
}

static int text_shape_valid(const ninlil_text_id_t *text, int is_namespace)
{
    size_t index;
    if (text == NULL || text->length == 0u
        || text->length > NINLIL_MAX_TEXT_ID_BYTES) {
        return 0;
    }
    if (!((text->bytes[0] >= (uint8_t)'a'
                && text->bytes[0] <= (uint8_t)'z')
            || (text->bytes[0] >= (uint8_t)'0'
                && text->bytes[0] <= (uint8_t)'9'))) {
        return 0;
    }
    for (index = 0u; index < text->length; ++index) {
        uint8_t c = text->bytes[index];
        int alpha = c >= (uint8_t)'a' && c <= (uint8_t)'z';
        int digit = c >= (uint8_t)'0' && c <= (uint8_t)'9';
        int common = alpha || digit || c == (uint8_t)'.'
            || c == (uint8_t)'-';
        int service_extra = c == (uint8_t)'_';
        if (!(common || (!is_namespace && service_extra))) {
            return 0;
        }
    }
    if (bytes_any_nonzero(&text->bytes[text->length],
            NINLIL_MAX_TEXT_ID_BYTES - text->length)) {
        return 0;
    }
    return 1;
}

static int text_matches(const ninlil_text_id_t *text, const char *expected)
{
    size_t length = strlen(expected);
    return text != NULL && text->length == length
        && memcmp(text->bytes, expected, length) == 0;
}

static int local_identity_shape_valid(const ninlil_local_identity_t *identity)
{
    uint32_t known = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    if (identity == NULL
        || !abi_header_valid(identity->abi_version,
            identity->struct_size, sizeof(*identity))
        || identity->reserved_zero != 0u
        || (identity->flags & ~known) != 0u) {
        return 0;
    }
    if (((identity->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u)
            != id_valid(&identity->device_id)
        || ((identity->flags & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u)
            != id_valid(&identity->installation_id)
        || ((identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u)
            != id_valid(&identity->site_domain_id)
        || (((identity->flags & (NINLIL_LOCAL_IDENTITY_HAS_DEVICE
                | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION)) != 0u)
            != (identity->binding_epoch != 0u))
        || (((identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u)
            != (identity->membership_epoch != 0u))) {
        return 0;
    }
    return 1;
}

static int target_shape_valid(const ninlil_concrete_target_t *target)
{
    uint32_t known = NINLIL_TARGET_HAS_DEVICE
        | NINLIL_TARGET_HAS_INSTALLATION | NINLIL_TARGET_HAS_SITE;
    if (target == NULL
        || !abi_header_valid(target->abi_version,
            target->struct_size, sizeof(*target))
        || target->reserved_zero != 0u
        || !id_valid(&target->target_runtime_id)
        || !id_valid(&target->target_application_instance_id)
        || (target->flags & ~known) != 0u) {
        return 0;
    }
    if (((target->flags & NINLIL_TARGET_HAS_DEVICE) != 0u)
            != id_valid(&target->device_id)
        || ((target->flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u)
            != id_valid(&target->installation_id)
        || ((target->flags & NINLIL_TARGET_HAS_SITE) != 0u)
            != id_valid(&target->site_domain_id)
        || (((target->flags & (NINLIL_TARGET_HAS_DEVICE
                | NINLIL_TARGET_HAS_INSTALLATION)) != 0u)
            != (target->binding_epoch != 0u))
        || (((target->flags & NINLIL_TARGET_HAS_SITE) != 0u)
            != (target->membership_epoch != 0u))) {
        return 0;
    }
    return 1;
}

static int family_is_known(ninlil_family_t family)
{
    return family == NINLIL_FAMILY_EVENT_FACT
        || family == NINLIL_FAMILY_DESIRED_STATE
        || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED
        || family == NINLIL_FAMILY_TRANSFER_RESERVED
        || family == NINLIL_FAMILY_CONFIG_RESERVED
        || family == NINLIL_FAMILY_NETWORK_CONTROL_RESERVED;
}

static int event_identity_valid(
    const ninlil_origin_authorization_request_t *request)
{
    if (request->service.family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || request->service.family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return id_is_zero(&request->event_id);
    }
    return id_valid(&request->event_id);
}

static int request_structurally_valid(
    const ninlil_origin_authorization_request_t *request)
{
    uint64_t expected_window;
    if (request == NULL) {
        return 0;
    }
    if (!abi_header_valid(request->abi_version,
            request->struct_size, sizeof(*request))
        || request->reserved_zero != 0u
        || request->environment < NINLIL_ENV_TEST
        || request->environment > NINLIL_ENV_PRODUCTION_RESERVED
        || !abi_header_valid(request->source.abi_version,
            request->source.struct_size, sizeof(request->source))
        || !id_valid(&request->source.runtime_id)
        || !id_valid(&request->source.application_instance_id)
        || !local_identity_shape_valid(&request->source.local_identity)
        || !target_shape_valid(&request->target)
        || !abi_header_valid(request->service.abi_version,
            request->service.struct_size, sizeof(request->service))
        || !text_shape_valid(&request->service.namespace_id, 1)
        || !text_shape_valid(&request->service.service_id, 0)
        || !text_shape_valid(&request->service.schema_id, 0)
        || !digest_valid(&request->service.descriptor_digest)
        || !family_is_known(request->service.family)
        || (!event_identity_valid(request))
        || !digest_valid(&request->content_digest)
        || request->required_evidence < NINLIL_EVIDENCE_RECEIVED
        || request->required_evidence > NINLIL_EVIDENCE_VERIFIED
        || !abi_header_valid(request->now.abi_version,
            request->now.struct_size, sizeof(request->now))
        || request->now.reserved_zero != 0u
        || !id_valid(&request->now.clock_epoch_id)
        || (request->now.trust != NINLIL_CLOCK_TRUSTED
            && request->now.trust != NINLIL_CLOCK_UNCERTAIN)) {
        return 0;
    }
    expected_window = request->now.now_ms
        - (request->now.now_ms % ORIGIN_AUTH_WINDOW_MS);
    return request->current_window_started_at_ms == expected_window;
}

static int latest_state_lab_allow(
    const ninlil_origin_authorization_request_t *request)
{
    return request->service.family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        && text_matches(&request->service.service_id, "latest-state")
        && text_matches(&request->service.schema_id, "latest-state")
        && request->required_evidence == NINLIL_EVIDENCE_APPLIED
        && id_is_zero(&request->event_id)
        && id_valid(&request->target.target_runtime_id)
        && id_valid(&request->target.target_application_instance_id);
}

static int source_and_service_match(
    const ninlil_origin_authorization_request_t *request)
{
    const ninlil_local_identity_t *identity = &request->source.local_identity;
    return id_matches(&request->source.runtime_id, id_endpoint_runtime)
        && id_matches(&request->source.application_instance_id,
            id_endpoint_application)
        && identity->flags == 7u
        && id_matches(&identity->device_id, id_endpoint_device)
        && id_matches(&identity->installation_id, id_endpoint_installation)
        && id_matches(&identity->site_domain_id, id_site)
        && identity->binding_epoch == 1u
        && identity->membership_epoch == 1u
        && text_matches(&request->service.namespace_id,
            "org.ninlil.examples")
        && text_matches(&request->service.service_id, "durable-event")
        && text_matches(&request->service.schema_id, "durable-event")
        && request->service.descriptor_revision == 1u
        && request->service.descriptor_digest.algorithm == NINLIL_DIGEST_SHA256
        && request->service.descriptor_digest.reserved_zero == 0u
        && memcmp(request->service.descriptor_digest.bytes,
            descriptor_digest_bytes, 32u) == 0
        && request->service.schema_major == 1u
        && request->service.schema_minor == 0u
        && request->service.family == NINLIL_FAMILY_EVENT_FACT
        && request->required_evidence == NINLIL_EVIDENCE_DURABLY_RECORDED;
}

static int target_matches(const ninlil_concrete_target_t *target)
{
    return id_matches(&target->target_runtime_id, id_controller_runtime)
        && id_matches(&target->target_application_instance_id,
            id_controller_application)
        && target->flags == 7u
        && id_matches(&target->device_id, id_controller_device)
        && id_matches(&target->installation_id, id_controller_installation)
        && id_matches(&target->site_domain_id, id_site)
        && target->binding_epoch == 1u
        && target->membership_epoch == 1u;
}

static void set_common_decision(
    ninlil_origin_authorization_decision_t *decision,
    const ninlil_origin_authorization_request_t *request)
{
    decision->abi_version = NINLIL_ABI_VERSION;
    decision->struct_size = (uint16_t)sizeof(*decision);
    (void)memcpy(decision->provider_id.bytes, id_provider, 16u);
    decision->provider_revision = 1u;
    decision->decision_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(decision->decision_digest.bytes,
        decision_digest_bytes, 32u);
    decision->clock_epoch_id = request->now.clock_epoch_id;
    decision->evaluated_at_ms = request->now.now_ms;
}

static void set_allow_decision(
    ninlil_origin_authorization_decision_t *decision,
    const ninlil_origin_authorization_request_t *request)
{
    set_common_decision(decision, request);
    decision->allowed = 1u;
    decision->reason = NINLIL_REASON_NONE;
    decision->retry_guidance = NINLIL_RETRY_NEVER;
    (void)memcpy(decision->grant_id.bytes, id_grant, 16u);
    decision->grant_revision = 1u;
    decision->valid_from_ms = ORIGIN_AUTH_VALID_FROM_MS;
    decision->expires_at_ms = ORIGIN_AUTH_EXPIRES_AT_MS;
    decision->max_payload_bytes = ORIGIN_AUTH_MAX_PAYLOAD;
    decision->max_active_spool_count = ORIGIN_AUTH_MAX_ACTIVE_COUNT;
    decision->max_active_spool_bytes = ORIGIN_AUTH_MAX_ACTIVE_BYTES;
    decision->rate_window_ms = ORIGIN_AUTH_WINDOW_MS;
    decision->max_admissions_per_window = ORIGIN_AUTH_MAX_WINDOW_COUNT;
    decision->max_attempts_per_retry_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
}

static void set_deny_decision(
    ninlil_origin_authorization_decision_t *decision,
    const ninlil_origin_authorization_request_t *request,
    ninlil_reason_t reason,
    ninlil_retry_guidance_t guidance,
    uint64_t delay)
{
    set_common_decision(decision, request);
    decision->allowed = 0u;
    decision->reason = reason;
    decision->retry_guidance = guidance;
    decision->retry_delay_ms = delay;
}

static void increment_saturating(uint64_t *value)
{
    if (*value != UINT64_MAX) {
        *value += 1u;
    }
}

static void record_trace(
    ninlil_test_origin_auth_t *provider,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_auth_status_t status,
    const ninlil_origin_authorization_decision_t *decision,
    uint32_t fault_consumed,
    uint32_t validation_failure)
{
    ninlil_test_origin_auth_trace_record_t *record;
    if (provider->trace_count >= NINLIL_TEST_ORIGIN_AUTH_TRACE_CAPACITY) {
        provider->trace_overflowed = 1;
        return;
    }
    record = &provider->trace[provider->trace_count++];
    (void)memset(record, 0, sizeof(*record));
    record->sequence = provider->next_trace_sequence;
    if (provider->next_trace_sequence != UINT64_MAX) {
        provider->next_trace_sequence += 1u;
    }
    record->status = status;
    record->fault_consumed = fault_consumed;
    record->validation_failure = validation_failure;
    if (request != NULL) {
        record->environment = request->environment;
        record->event_id = request->event_id;
        record->now_ms = request->now.now_ms;
        record->active_spool_bytes = request->active_spool_bytes;
        record->payload_length = request->payload_length;
        record->active_spool_count = request->active_spool_count;
        record->admissions_in_current_window =
            request->admissions_in_current_window;
    }
    if (decision != NULL) {
        record->allowed = decision->allowed;
        record->reason = decision->reason;
    }
}

static void count_result(
    ninlil_test_origin_auth_t *provider,
    ninlil_origin_auth_status_t status,
    const ninlil_origin_authorization_decision_t *decision,
    int raw)
{
    if (raw) {
        increment_saturating(&provider->raw_count);
    }
    if (status == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE) {
        increment_saturating(&provider->temporary_count);
    } else if (status == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE) {
        increment_saturating(&provider->permanent_count);
    } else if (status == NINLIL_ORIGIN_AUTH_OK && decision != NULL) {
        if (decision->allowed == 1u) {
            increment_saturating(&provider->allow_count);
        } else if (decision->allowed == 0u) {
            uint64_t *counter = NULL;
            switch (decision->reason) {
            case NINLIL_REASON_GRANT_INVALID:
                counter = &provider->deny_grant_invalid;
                break;
            case NINLIL_REASON_TARGET_UNAUTHORIZED:
                counter = &provider->deny_target_unauthorized;
                break;
            case NINLIL_REASON_GRANT_EXPIRED:
                counter = &provider->deny_grant_expired;
                break;
            case NINLIL_REASON_GRANT_LIMIT_EXCEEDED:
                counter = &provider->deny_grant_limit;
                break;
            case NINLIL_REASON_RATE_EXHAUSTED:
                counter = &provider->deny_rate;
                break;
            case NINLIL_REASON_CLOCK_UNCERTAIN:
                counter = &provider->deny_clock;
                break;
            default:
                break;
            }
            if (counter != NULL) {
                increment_saturating(counter);
            }
        }
    }
}

static int pop_raw(
    ninlil_test_origin_auth_t *provider, raw_outcome_t *out)
{
    raw_outcome_t *entry;
    if (provider->fault_count == 0u) {
        return 0;
    }
    entry = &provider->faults[provider->fault_head];
    *out = *entry;
    entry->remaining -= 1u;
    if (entry->remaining == 0u) {
        provider->fault_head = (provider->fault_head + 1u)
            % NINLIL_TEST_ORIGIN_AUTH_FAULT_CAPACITY;
        provider->fault_count -= 1u;
    }
    increment_saturating(&provider->fault_consumed_count);
    return 1;
}

static ninlil_origin_auth_status_t finish_natural(
    ninlil_test_origin_auth_t *provider,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    count_result(provider, NINLIL_ORIGIN_AUTH_OK, decision, 0);
    record_trace(provider, request, NINLIL_ORIGIN_AUTH_OK,
        decision, 0u, 0u);
    return NINLIL_ORIGIN_AUTH_OK;
}

static ninlil_origin_auth_status_t fixture_evaluate(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    ninlil_test_origin_auth_t *provider = (ninlil_test_origin_auth_t *)user;
    raw_outcome_t raw;
    uint64_t prospective_bytes;
    uint64_t window_end;
    uint64_t rate_delay;
    increment_saturating(&provider->call_count);
    if (out_decision == NULL) {
        increment_saturating(&provider->validation_failure_count);
        increment_saturating(&provider->permanent_count);
        record_trace(provider, NULL, NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE,
            NULL, 0u, 1u);
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    (void)memset(out_decision, 0, sizeof(*out_decision));
    if (!request_structurally_valid(request)) {
        increment_saturating(&provider->validation_failure_count);
        increment_saturating(&provider->permanent_count);
        record_trace(provider, NULL, NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE,
            out_decision, 0u, 1u);
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    if (request->environment != NINLIL_ENV_TEST) {
        increment_saturating(&provider->permanent_count);
        record_trace(provider, request, NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE,
            out_decision, 0u, 0u);
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    if (pop_raw(provider, &raw)) {
        *out_decision = raw.decision;
        count_result(provider, raw.status, out_decision, 1);
        record_trace(provider, request, raw.status, out_decision, 1u, 0u);
        return raw.status;
    }
    if (request->now.trust == NINLIL_CLOCK_UNCERTAIN
        || !id_matches(&request->now.clock_epoch_id, id_clock_epoch)) {
        set_deny_decision(out_decision, request,
            NINLIL_REASON_CLOCK_UNCERTAIN,
            NINLIL_RETRY_OPERATOR_ACTION, 0u);
        return finish_natural(provider, request, out_decision);
    }
    if (latest_state_lab_allow(request)) {
        set_allow_decision(out_decision, request);
        return finish_natural(provider, request, out_decision);
    }
    if (!source_and_service_match(request)) {
        set_deny_decision(out_decision, request,
            NINLIL_REASON_GRANT_INVALID,
            NINLIL_RETRY_OPERATOR_ACTION, 0u);
        return finish_natural(provider, request, out_decision);
    }
    if (!target_matches(&request->target)) {
        set_deny_decision(out_decision, request,
            NINLIL_REASON_TARGET_UNAUTHORIZED,
            NINLIL_RETRY_MODIFIED, 0u);
        return finish_natural(provider, request, out_decision);
    }
    if (request->now.now_ms >= ORIGIN_AUTH_EXPIRES_AT_MS) {
        set_deny_decision(out_decision, request,
            NINLIL_REASON_GRANT_EXPIRED,
            NINLIL_RETRY_OPERATOR_ACTION, 0u);
        return finish_natural(provider, request, out_decision);
    }
    if (request->payload_length > ORIGIN_AUTH_MAX_PAYLOAD) {
        set_deny_decision(out_decision, request,
            NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
            NINLIL_RETRY_SAME_AFTER, ORIGIN_AUTH_LIMIT_RETRY_MS);
        return finish_natural(provider, request, out_decision);
    }
    if (request->active_spool_count >= ORIGIN_AUTH_MAX_ACTIVE_COUNT) {
        set_deny_decision(out_decision, request,
            NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
            NINLIL_RETRY_SAME_AFTER, ORIGIN_AUTH_LIMIT_RETRY_MS);
        return finish_natural(provider, request, out_decision);
    }
    if (UINT64_MAX - request->active_spool_bytes
            < (uint64_t)request->payload_length + ORIGIN_AUTH_EVENT_OVERHEAD) {
        increment_saturating(&provider->arithmetic_overflow_count);
        set_deny_decision(out_decision, request,
            NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
            NINLIL_RETRY_SAME_AFTER, ORIGIN_AUTH_LIMIT_RETRY_MS);
        return finish_natural(provider, request, out_decision);
    }
    prospective_bytes = request->active_spool_bytes
        + request->payload_length + ORIGIN_AUTH_EVENT_OVERHEAD;
    if (prospective_bytes > ORIGIN_AUTH_MAX_ACTIVE_BYTES) {
        set_deny_decision(out_decision, request,
            NINLIL_REASON_GRANT_LIMIT_EXCEEDED,
            NINLIL_RETRY_SAME_AFTER, ORIGIN_AUTH_LIMIT_RETRY_MS);
        return finish_natural(provider, request, out_decision);
    }
    if (request->admissions_in_current_window
        >= ORIGIN_AUTH_MAX_WINDOW_COUNT) {
        window_end = request->current_window_started_at_ms
            + ORIGIN_AUTH_WINDOW_MS;
        rate_delay = window_end - request->now.now_ms;
        set_deny_decision(out_decision, request,
            NINLIL_REASON_RATE_EXHAUSTED,
            NINLIL_RETRY_SAME_AFTER, rate_delay);
        return finish_natural(provider, request, out_decision);
    }
    set_allow_decision(out_decision, request);
    return finish_natural(provider, request, out_decision);
}

ninlil_test_origin_auth_t *ninlil_test_origin_auth_create(void)
{
    ninlil_test_origin_auth_t *provider =
        (ninlil_test_origin_auth_t *)calloc(1u, sizeof(*provider));
    if (provider == NULL) {
        return NULL;
    }
    provider->next_trace_sequence = 1u;
    provider->ops.abi_version = NINLIL_ABI_VERSION;
    provider->ops.struct_size = (uint16_t)sizeof(provider->ops);
    provider->ops.user = provider;
    provider->ops.evaluate = fixture_evaluate;
    return provider;
}

void ninlil_test_origin_auth_destroy(ninlil_test_origin_auth_t *provider)
{
    free(provider);
}

const ninlil_origin_authorization_ops_t *ninlil_test_origin_auth_ops(
    ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? NULL : &provider->ops;
}

int ninlil_test_origin_auth_raw_enqueue(
    ninlil_test_origin_auth_t *provider,
    ninlil_origin_auth_status_t status,
    const ninlil_origin_authorization_decision_t *decision,
    uint32_t count)
{
    size_t index;
    raw_outcome_t *entry;
    if (provider == NULL || count == 0u
        || provider->fault_count >= NINLIL_TEST_ORIGIN_AUTH_FAULT_CAPACITY) {
        return 0;
    }
    index = (provider->fault_head + provider->fault_count)
        % NINLIL_TEST_ORIGIN_AUTH_FAULT_CAPACITY;
    entry = &provider->faults[index];
    (void)memset(entry, 0, sizeof(*entry));
    entry->status = status;
    entry->remaining = count;
    if (decision != NULL) {
        entry->decision = *decision;
    }
    provider->fault_count += 1u;
    return 1;
}

uint64_t ninlil_test_origin_auth_call_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->call_count;
}

uint64_t ninlil_test_origin_auth_allow_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->allow_count;
}

uint64_t ninlil_test_origin_auth_deny_count(
    const ninlil_test_origin_auth_t *provider, ninlil_reason_t reason)
{
    if (provider == NULL) {
        return 0u;
    }
    switch (reason) {
    case NINLIL_REASON_GRANT_INVALID:
        return provider->deny_grant_invalid;
    case NINLIL_REASON_TARGET_UNAUTHORIZED:
        return provider->deny_target_unauthorized;
    case NINLIL_REASON_GRANT_EXPIRED:
        return provider->deny_grant_expired;
    case NINLIL_REASON_GRANT_LIMIT_EXCEEDED:
        return provider->deny_grant_limit;
    case NINLIL_REASON_RATE_EXHAUSTED:
        return provider->deny_rate;
    case NINLIL_REASON_CLOCK_UNCERTAIN:
        return provider->deny_clock;
    default:
        return 0u;
    }
}

uint64_t ninlil_test_origin_auth_temporary_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->temporary_count;
}

uint64_t ninlil_test_origin_auth_permanent_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->permanent_count;
}

uint64_t ninlil_test_origin_auth_raw_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->raw_count;
}

uint64_t ninlil_test_origin_auth_validation_failure_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->validation_failure_count;
}

uint64_t ninlil_test_origin_auth_fault_consumed_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->fault_consumed_count;
}

uint64_t ninlil_test_origin_auth_arithmetic_overflow_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->arithmetic_overflow_count;
}

size_t ninlil_test_origin_auth_trace_count(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0u : provider->trace_count;
}

int ninlil_test_origin_auth_trace_overflowed(
    const ninlil_test_origin_auth_t *provider)
{
    return provider == NULL ? 0 : provider->trace_overflowed;
}

const ninlil_test_origin_auth_trace_record_t *ninlil_test_origin_auth_trace_at(
    const ninlil_test_origin_auth_t *provider, size_t index)
{
    if (provider == NULL || index >= provider->trace_count) {
        return NULL;
    }
    return &provider->trace[index];
}
