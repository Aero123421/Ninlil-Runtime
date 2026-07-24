#include "submission_preflight.h"
#include "family_capability_model.h"

#include <stddef.h>
#include <string.h>

static int bytes_are_zero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int id_is_zero(const ninlil_id128_t *id)
{
    return bytes_are_zero(id->bytes, sizeof(id->bytes));
}

static int id_equal(const ninlil_id128_t *left, const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int digest_is_valid(const ninlil_digest256_t *digest)
{
    return digest->algorithm == NINLIL_DIGEST_SHA256
        && digest->reserved_zero == 0u;
}

static int digest_equal(
    const ninlil_digest256_t *left,
    const ninlil_digest256_t *right)
{
    return left->algorithm == right->algorithm
        && left->reserved_zero == right->reserved_zero
        && memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

typedef enum text_id_grammar {
    TEXT_ID_NAMESPACE = 1,
    TEXT_ID_SERVICE_OR_SCHEMA = 2
} text_id_grammar_t;

static int ascii_is_lower_or_digit(uint8_t value)
{
    return (value >= (uint8_t)'a' && value <= (uint8_t)'z')
        || (value >= (uint8_t)'0' && value <= (uint8_t)'9');
}

static int text_id_is_valid(
    const ninlil_text_id_t *text_id,
    text_id_grammar_t grammar)
{
    size_t index;

    if (text_id->length == 0u
        || text_id->length > sizeof(text_id->bytes)
        || !ascii_is_lower_or_digit(text_id->bytes[0])) {
        return 0;
    }
    for (index = 1u; index < text_id->length; ++index) {
        uint8_t value = text_id->bytes[index];
        if (!ascii_is_lower_or_digit(value)
            && value != (uint8_t)'.'
            && value != (uint8_t)'-'
            && (grammar != TEXT_ID_SERVICE_OR_SCHEMA
                || value != (uint8_t)'_')) {
            return 0;
        }
    }
    for (index = text_id->length; index < sizeof(text_id->bytes); ++index) {
        if (text_id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int header_is_current(uint16_t abi_version, uint16_t struct_size, size_t size)
{
    return abi_version == NINLIL_ABI_VERSION
        && (size_t)struct_size >= size;
}

static int presence_shape_is_valid(
    uint32_t flags,
    const ninlil_id128_t *device_id,
    const ninlil_id128_t *installation_id,
    const ninlil_id128_t *site_id,
    uint64_t binding_epoch,
    uint64_t membership_epoch)
{
    uint32_t allowed_flags = NINLIL_TARGET_HAS_DEVICE
        | NINLIL_TARGET_HAS_INSTALLATION
        | NINLIL_TARGET_HAS_SITE;
    int has_device;
    int has_installation;
    int has_site;

    if ((flags & ~allowed_flags) != 0u) {
        return 0;
    }
    has_device = (flags & NINLIL_TARGET_HAS_DEVICE) != 0u;
    has_installation = (flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u;
    has_site = (flags & NINLIL_TARGET_HAS_SITE) != 0u;
    return id_is_zero(device_id) == !has_device
        && id_is_zero(installation_id) == !has_installation
        && id_is_zero(site_id) == !has_site
        && (binding_epoch != 0u) == (has_device || has_installation)
        && (membership_epoch != 0u) == has_site;
}

static int local_identity_is_valid(const ninlil_local_identity_t *identity)
{
    return header_is_current(
               identity->abi_version,
               identity->struct_size,
               sizeof(*identity))
        && identity->reserved_zero == 0u
        && presence_shape_is_valid(
            identity->flags,
            &identity->device_id,
            &identity->installation_id,
            &identity->site_domain_id,
            identity->binding_epoch,
            identity->membership_epoch);
}

static int concrete_target_is_valid(const ninlil_concrete_target_t *target)
{
    return header_is_current(
               target->abi_version,
               target->struct_size,
               sizeof(*target))
        && !id_is_zero(&target->target_runtime_id)
        && !id_is_zero(&target->target_application_instance_id)
        && target->reserved_zero == 0u
        && presence_shape_is_valid(
            target->flags,
            &target->device_id,
            &target->installation_id,
            &target->site_domain_id,
            target->binding_epoch,
            target->membership_epoch);
}

static int family_uses_outbox(ninlil_family_t family)
{
    return family == NINLIL_FAMILY_DESIRED_STATE
        || family == NINLIL_FAMILY_TRANSFER_RESERVED
        || family == NINLIL_FAMILY_CONFIG_RESERVED;
}

static int family_uses_event_spool(ninlil_family_t family)
{
    return family == NINLIL_FAMILY_EVENT_FACT
        || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED;
}

static int assurance_is_valid(
    const ninlil_admission_assurance_t *assurance,
    ninlil_family_t family)
{
    return header_is_current(
               assurance->abi_version,
               assurance->struct_size,
               sizeof(*assurance))
        && assurance->assurance_profile
            == NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL
        && assurance->submission_validated == 1u
        && assurance->target_roster_fixed == 1u
        && assurance->descriptor_snapshot_fixed == 1u
        && assurance->local_journal_committed == 1u
        && assurance->local_capacity_reserved == 1u
        && assurance->idempotency_mapping_committed == 1u
        && assurance->origin_grant_snapshot_committed
            == (family_uses_event_spool(family) ? 1u : 0u)
        && assurance->remote_capacity_reserved == 0u
        && assurance->route_feasibility_verified == 0u
        && assurance->receive_window_reserved == 0u
        && assurance->bearer_capacity_reserved == 0u
        && assurance->airtime_reserved == 0u
        && assurance->compliance_permit_issued == 0u
        && assurance->reserved_zero == 0u;
}

static int existing_pair_is_valid(
    const ninlil_model_existing_admission_t *existing)
{
    return !id_is_zero(&existing->transaction_id)
        && digest_is_valid(&existing->canonical_submission_digest);
}

static void initialize_public_result(
    ninlil_submission_result_t *result,
    int semantic_result)
{
    (void)memset(result, 0, sizeof(*result));
    result->abi_version = NINLIL_ABI_VERSION;
    result->struct_size = (uint16_t)sizeof(*result);
    if (semantic_result != 0) {
        result->assurance.abi_version = NINLIL_ABI_VERSION;
        result->assurance.struct_size =
            (uint16_t)sizeof(result->assurance);
    }
}

static void set_api_error(
    ninlil_model_submission_preflight_result_t *result,
    ninlil_status_t status)
{
    result->action = NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL;
    result->api_status = status;
    initialize_public_result(&result->public_result, 0);
    result->public_result.kind = NINLIL_SUBMISSION_INVALID;
    result->public_result.reason = NINLIL_REASON_NONE;
    result->public_result.retry_guidance = NINLIL_RETRY_NEVER;
}

static ninlil_retry_guidance_t default_guidance(ninlil_reason_t reason)
{
    switch (reason) {
    case NINLIL_REASON_TARGET_COUNT_UNSUPPORTED:
    case NINLIL_REASON_INVALID_SCHEMA:
    case NINLIL_REASON_INVALID_PAYLOAD_LENGTH:
    case NINLIL_REASON_DEADLINE_INVALID:
    case NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED:
    case NINLIL_REASON_EVIDENCE_UNSUPPORTED:
    case NINLIL_REASON_IDEMPOTENCY_CONFLICT:
    case NINLIL_REASON_TARGET_UNAUTHORIZED:
    case NINLIL_REASON_UNSUPPORTED_DIRECTION:
        return NINLIL_RETRY_MODIFIED;
    case NINLIL_REASON_GRANT_INVALID:
    case NINLIL_REASON_GRANT_EXPIRED:
    case NINLIL_REASON_CLOCK_UNCERTAIN:
    case NINLIL_REASON_COUNTER_EXHAUSTED:
        return NINLIL_RETRY_OPERATOR_ACTION;
    case NINLIL_REASON_CAPACITY_EXHAUSTED:
    case NINLIL_REASON_GRANT_LIMIT_EXCEEDED:
    case NINLIL_REASON_RATE_EXHAUSTED:
        return NINLIL_RETRY_SAME_AFTER;
    default:
        return NINLIL_RETRY_NEVER;
    }
}

static void set_rejected_with_guidance(
    ninlil_model_submission_preflight_result_t *result,
    ninlil_reason_t reason,
    ninlil_retry_guidance_t guidance,
    uint64_t delay)
{
    result->action = NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL;
    result->api_status = NINLIL_OK;
    initialize_public_result(&result->public_result, 1);
    result->public_result.kind = NINLIL_SUBMISSION_REJECTED;
    result->public_result.reason = reason;
    result->public_result.retry_guidance = guidance;
    result->public_result.retry_delay_ms = delay;
}

static void set_rejected(
    ninlil_model_submission_preflight_result_t *result,
    ninlil_reason_t reason)
{
    set_rejected_with_guidance(
        result, reason, default_guidance(reason), 0u);
}

static int service_shape_is_valid(
    const ninlil_model_submission_service_t *service)
{
    uint32_t allowed_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);

    if (!header_is_current(
            service->source.abi_version,
            service->source.struct_size,
            sizeof(service->source))
        || !header_is_current(
            service->identity.abi_version,
            service->identity.struct_size,
            sizeof(service->identity))
        || id_is_zero(&service->source.runtime_id)
        || id_is_zero(&service->source.application_instance_id)
        || !local_identity_is_valid(&service->source.local_identity)
        || !text_id_is_valid(
            &service->identity.namespace_id, TEXT_ID_NAMESPACE)
        || !text_id_is_valid(
            &service->identity.service_id, TEXT_ID_SERVICE_OR_SCHEMA)
        || !text_id_is_valid(
            &service->identity.schema_id, TEXT_ID_SERVICE_OR_SCHEMA)
        || service->identity.descriptor_revision == 0u
        || !digest_is_valid(&service->identity.descriptor_digest)
        || service->identity.family != service->family
        || service->identity.schema_major != service->schema_major
        || service->identity.schema_minor < service->schema_minor_min
        || service->identity.schema_minor > service->schema_minor_max
        || service->schema_minor_min > service->schema_minor_max
        || service->reserved_zero_u16 != 0u
        || service->supported_evidence_mask == 0u
        || (service->supported_evidence_mask & ~allowed_evidence_mask) != 0u
        || service->logical_payload_limit == 0u
        || service->inflight_limit == 0u
        || service->admission_window_ms == 0u
        || service->admission_window_ms > NINLIL_M1A_MAX_RETRY_DELAY_MS
        || service->max_admissions_per_window == 0u
        || service->max_payload_bytes_per_window
            < service->logical_payload_limit
        || service->max_evidence_per_target == 0u
        || service->max_evidence_per_target > 8u) {
        return 0;
    }

    if (service->family == NINLIL_FAMILY_DESIRED_STATE
        || service->family == NINLIL_FAMILY_TRANSFER_RESERVED
        || service->family == NINLIL_FAMILY_CONFIG_RESERVED) {
        return service->minimum_deadline_ms > 0u
            && service->minimum_deadline_ms <= service->maximum_deadline_ms
            && service->maximum_deadline_ms < NINLIL_NO_DEADLINE;
    }
    return service->minimum_deadline_ms == NINLIL_NO_DEADLINE
        && service->maximum_deadline_ms == NINLIL_NO_DEADLINE
        && service->maximum_evidence_grace_ms == 0u;
}

static int submission_identity_shape_is_valid(
    const ninlil_model_submission_preflight_input_t *input)
{
    const ninlil_model_semantic_submission_t *submission =
        &input->submission;

    if (!digest_is_valid(&submission->content_digest)
        || !digest_is_valid(&submission->canonical_submission_digest)) {
        return 0;
    }
    if (input->service.family == NINLIL_FAMILY_DESIRED_STATE
        || input->service.family == NINLIL_FAMILY_TRANSFER_RESERVED
        || input->service.family == NINLIL_FAMILY_CONFIG_RESERVED
        || input->service.family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || input->service.family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return id_is_zero(&submission->event_id)
            && submission->generation != 0u;
    }
    return !id_is_zero(&submission->event_id)
        && submission->generation == 0u;
}

static int idempotency_key_is_valid(
    const ninlil_model_idempotency_key_t *key)
{
    size_t index;

    if (key->length == 0u || key->length > sizeof(key->bytes)) {
        return 0;
    }
    for (index = key->length; index < sizeof(key->bytes); ++index) {
        if (key->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int mapping_state_is_known(ninlil_model_mapping_state_t state)
{
    return state >= NINLIL_MODEL_MAPPING_ABSENT
        && state <= NINLIL_MODEL_MAPPING_STORAGE_FAILURE;
}

static int mapping_failure_status_is_valid(ninlil_status_t status)
{
    return status == NINLIL_E_WOULD_BLOCK
        || status == NINLIL_E_STORAGE
        || status == NINLIL_E_STORAGE_CORRUPT
        || status == NINLIL_E_STORAGE_COMMIT_UNKNOWN;
}

static int mapping_fact_shape_is_valid(
    const ninlil_model_mapping_fact_t *mapping)
{
    if (!mapping_state_is_known(mapping->state)) {
        return 0;
    }
    if (mapping->state == NINLIL_MODEL_MAPPING_STORAGE_FAILURE) {
        return mapping->record_verified == 0u
            && mapping_failure_status_is_valid(mapping->failure_status);
    }
    if (mapping->failure_status != NINLIL_OK) {
        return 0;
    }
    if (mapping->state == NINLIL_MODEL_MAPPING_ABSENT) {
        return mapping->record_verified == 0u;
    }
    return mapping->record_verified == 1u
        && existing_pair_is_valid(&mapping->existing);
}

static void set_already(
    ninlil_model_submission_preflight_result_t *result,
    const ninlil_model_existing_admission_t *existing)
{
    result->action = NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL;
    result->api_status = NINLIL_OK;
    initialize_public_result(&result->public_result, 1);
    result->public_result.kind = NINLIL_SUBMISSION_ALREADY_ADMITTED;
    result->public_result.reason = NINLIL_REASON_NONE;
    result->public_result.retry_guidance = NINLIL_RETRY_NEVER;
    result->public_result.transaction_id = existing->transaction_id;
    result->public_result.canonical_submission_digest =
        existing->canonical_submission_digest;
    result->public_result.assurance = existing->assurance;
}

static void set_conflict(
    ninlil_model_submission_preflight_result_t *result,
    const ninlil_model_existing_admission_t *existing)
{
    result->action = NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL;
    result->api_status = NINLIL_OK;
    initialize_public_result(&result->public_result, 1);
    result->public_result.kind = NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT;
    result->public_result.reason = NINLIL_REASON_IDEMPOTENCY_CONFLICT;
    result->public_result.retry_guidance = NINLIL_RETRY_MODIFIED;
    result->public_result.transaction_id = existing->transaction_id;
    result->public_result.canonical_submission_digest =
        existing->canonical_submission_digest;
}

static ninlil_status_t reduce_idempotency(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_submission_preflight_result_t *result,
    int *out_is_new)
{
    const ninlil_model_mapping_fact_t *key = &input->caller_key_mapping;
    const ninlil_model_mapping_fact_t *event = &input->event_id_mapping;

    *out_is_new = 0;
    if (!mapping_fact_shape_is_valid(key)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (key->state == NINLIL_MODEL_MAPPING_MATCH
        && !digest_equal(
            &key->existing.canonical_submission_digest,
            &input->submission.canonical_submission_digest)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (key->state == NINLIL_MODEL_MAPPING_STORAGE_FAILURE) {
        set_api_error(result, key->failure_status);
        return NINLIL_OK;
    }

    if (input->service.family == NINLIL_FAMILY_DESIRED_STATE
        || input->service.family == NINLIL_FAMILY_TRANSFER_RESERVED
        || input->service.family == NINLIL_FAMILY_CONFIG_RESERVED) {
        if (event->state != NINLIL_MODEL_MAPPING_ABSENT) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (key->state == NINLIL_MODEL_MAPPING_ABSENT) {
            *out_is_new = 1;
        } else if (key->state == NINLIL_MODEL_MAPPING_MATCH) {
            if (!assurance_is_valid(&key->existing.assurance, input->service.family)) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
            set_already(result, &key->existing);
        } else {
            set_conflict(result, &key->existing);
        }
        return NINLIL_OK;
    }

    if (!mapping_fact_shape_is_valid(event)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (event->state == NINLIL_MODEL_MAPPING_MATCH
        && !digest_equal(
            &event->existing.canonical_submission_digest,
            &input->submission.canonical_submission_digest)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (event->state == NINLIL_MODEL_MAPPING_STORAGE_FAILURE) {
        set_api_error(result, event->failure_status);
        return NINLIL_OK;
    }
    if (key->state == NINLIL_MODEL_MAPPING_ABSENT
        && event->state == NINLIL_MODEL_MAPPING_ABSENT) {
        *out_is_new = 1;
        return NINLIL_OK;
    }
    if (key->state == NINLIL_MODEL_MAPPING_MATCH
        && event->state == NINLIL_MODEL_MAPPING_MATCH
        && id_equal(
            &key->existing.transaction_id,
            &event->existing.transaction_id)
        && digest_equal(
            &key->existing.canonical_submission_digest,
            &event->existing.canonical_submission_digest)) {
        if (!assurance_is_valid(&key->existing.assurance, input->service.family)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        set_already(result, &key->existing);
        return NINLIL_OK;
    }

    /* ADR-0002: caller-key projection wins whenever that mapping exists. */
    if (key->state != NINLIL_MODEL_MAPPING_ABSENT) {
        set_conflict(result, &key->existing);
    } else {
        set_conflict(result, &event->existing);
    }
    return NINLIL_OK;
}

static int deny_tuple_is_valid(
    const ninlil_model_origin_authority_result_t *authority)
{
    switch (authority->deny_reason) {
    case NINLIL_REASON_GRANT_LIMIT_EXCEEDED:
    case NINLIL_REASON_RATE_EXHAUSTED:
        return authority->deny_guidance == NINLIL_RETRY_SAME_AFTER
            && authority->deny_retry_delay_ms
                <= NINLIL_M1A_MAX_RETRY_DELAY_MS;
    case NINLIL_REASON_TARGET_UNAUTHORIZED:
        return authority->deny_guidance == NINLIL_RETRY_MODIFIED
            && authority->deny_retry_delay_ms == 0u;
    case NINLIL_REASON_GRANT_INVALID:
    case NINLIL_REASON_GRANT_EXPIRED:
    case NINLIL_REASON_CLOCK_UNCERTAIN:
        return authority->deny_guidance == NINLIL_RETRY_OPERATOR_ACTION
            && authority->deny_retry_delay_ms == 0u;
    default:
        return 0;
    }
}

static int grant_is_valid(
    const ninlil_model_submission_preflight_input_t *input)
{
    const ninlil_model_origin_grant_snapshot_t *grant =
        &input->authority.grant;

    return !id_is_zero(&grant->provider_id)
        && grant->provider_revision != 0u
        && digest_is_valid(&grant->decision_digest)
        && !id_is_zero(&grant->grant_id)
        && grant->grant_revision != 0u
        && id_equal(&grant->clock_epoch_id, &input->clock.clock_epoch_id)
        && grant->evaluated_at_ms == input->clock.now_ms
        && grant->valid_from_ms <= grant->evaluated_at_ms
        && grant->evaluated_at_ms < grant->expires_at_ms
        && grant->retry_delay_ms == 0u
        && grant->max_payload_bytes > 0u
        && grant->max_active_spool_count > 0u
        && grant->max_active_spool_bytes > 0u
        && grant->rate_window_ms == input->service.admission_window_ms
        && grant->max_admissions_per_window > 0u
        && grant->max_admissions_per_window
            <= input->service.max_admissions_per_window
        && grant->max_attempts_per_retry_cycle
            == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
}

static int grant_is_zero(const ninlil_model_origin_grant_snapshot_t *grant)
{
    return id_is_zero(&grant->provider_id)
        && grant->provider_revision == 0u
        && grant->decision_digest.algorithm == 0u
        && grant->decision_digest.reserved_zero == 0u
        && bytes_are_zero(
            grant->decision_digest.bytes,
            sizeof(grant->decision_digest.bytes))
        && id_is_zero(&grant->grant_id)
        && grant->grant_revision == 0u
        && id_is_zero(&grant->clock_epoch_id)
        && grant->evaluated_at_ms == 0u
        && grant->valid_from_ms == 0u
        && grant->expires_at_ms == 0u
        && grant->retry_delay_ms == 0u
        && grant->max_payload_bytes == 0u
        && grant->max_active_spool_count == 0u
        && grant->max_active_spool_bytes == 0u
        && grant->rate_window_ms == 0u
        && grant->max_admissions_per_window == 0u
        && grant->max_attempts_per_retry_cycle == 0u;
}

static int deny_provenance_is_valid(
    const ninlil_model_submission_preflight_input_t *input)
{
    const ninlil_model_origin_grant_snapshot_t *decision =
        &input->authority.grant;

    return !id_is_zero(&decision->provider_id)
        && decision->provider_revision != 0u
        && digest_is_valid(&decision->decision_digest)
        && id_equal(&decision->clock_epoch_id, &input->clock.clock_epoch_id)
        && decision->evaluated_at_ms == input->clock.now_ms
        && id_is_zero(&decision->grant_id)
        && decision->grant_revision == 0u
        && decision->valid_from_ms == 0u
        && decision->expires_at_ms == 0u
        && decision->retry_delay_ms == 0u
        && decision->max_payload_bytes == 0u
        && decision->max_active_spool_count == 0u
        && decision->max_active_spool_bytes == 0u
        && decision->rate_window_ms == 0u
        && decision->max_admissions_per_window == 0u
        && decision->max_attempts_per_retry_cycle == 0u;
}

static ninlil_status_t reduce_authority(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_submission_preflight_result_t *result,
    int *out_allowed)
{
    *out_allowed = 0;
    if (input->service.family == NINLIL_FAMILY_DESIRED_STATE
        || input->service.family == NINLIL_FAMILY_TRANSFER_RESERVED
        || input->service.family == NINLIL_FAMILY_CONFIG_RESERVED) {
        if (input->authority.fact
            != NINLIL_MODEL_ORIGIN_AUTH_NOT_APPLICABLE) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        *out_allowed = 1;
        return NINLIL_OK;
    }

    if (input->service.family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || input->service.family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        /* Uplink B5 families follow EventFact origin authority path. */
    } else if (input->service.family != NINLIL_FAMILY_EVENT_FACT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    switch (input->authority.fact) {
    case NINLIL_MODEL_ORIGIN_AUTH_ALLOW:
        if (input->authority.deny_reason != NINLIL_REASON_NONE
            || input->authority.deny_guidance != NINLIL_RETRY_NEVER
            || input->authority.deny_retry_delay_ms != 0u
            || !grant_is_valid(input)) {
            set_api_error(result, NINLIL_E_DEGRADED);
            return NINLIL_OK;
        }
        *out_allowed = 1;
        return NINLIL_OK;
    case NINLIL_MODEL_ORIGIN_AUTH_DENY:
        if (!deny_tuple_is_valid(&input->authority)
            || !deny_provenance_is_valid(input)) {
            set_api_error(result, NINLIL_E_DEGRADED);
            return NINLIL_OK;
        }
        set_rejected_with_guidance(
            result,
            input->authority.deny_reason,
            input->authority.deny_guidance,
            input->authority.deny_retry_delay_ms);
        return NINLIL_OK;
    case NINLIL_MODEL_ORIGIN_AUTH_TEMPORARY_FAILURE:
        if (input->authority.deny_reason != NINLIL_REASON_NONE
            || input->authority.deny_guidance != NINLIL_RETRY_NEVER
            || input->authority.deny_retry_delay_ms != 0u
            || !grant_is_zero(&input->authority.grant)) {
            set_api_error(result, NINLIL_E_DEGRADED);
            return NINLIL_OK;
        }
        set_api_error(result, NINLIL_E_WOULD_BLOCK);
        return NINLIL_OK;
    case NINLIL_MODEL_ORIGIN_AUTH_PERMANENT_OR_INVALID:
        set_api_error(result, NINLIL_E_DEGRADED);
        return NINLIL_OK;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

static int checked_increment(uint64_t value, uint64_t *out_value)
{
    if (value == UINT64_MAX) {
        return 0;
    }
    *out_value = value + 1u;
    return 1;
}

static int checked_add(uint64_t left, uint64_t right, uint64_t *out_value)
{
    if (left > UINT64_MAX - right) {
        return 0;
    }
    *out_value = left + right;
    return 1;
}

static int add_request(
    ninlil_model_capacity_batch_request_t *requests,
    uint32_t *count,
    ninlil_resource_kind_t kind,
    uint64_t amount)
{
    if (amount == 0u) {
        return 1;
    }
    if (*count >= NINLIL_MODEL_RESOURCE_KIND_COUNT
        || (*count > 0u && requests[*count - 1u].kind >= kind)) {
        return 0;
    }
    requests[*count].kind = kind;
    requests[*count].amount = amount;
    *count += 1u;
    return 1;
}

static int build_resource_requests(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_resource_reservation_plan_t *plan)
{
    uint64_t evidence_amount =
        (uint64_t)input->service.max_evidence_per_target + 1u;

    if (!add_request(
            plan->reserve_requests,
            &plan->reserve_request_count,
            NINLIL_RESOURCE_TRANSACTION,
            1u)
        || !add_request(
            plan->reserve_requests,
            &plan->reserve_request_count,
            NINLIL_RESOURCE_TARGET,
            1u)) {
        return 0;
    }
    if (family_uses_outbox(input->service.family)) {
        if (!add_request(
                plan->reserve_requests,
                &plan->reserve_request_count,
                NINLIL_RESOURCE_OUTBOX_BYTES,
                input->submission.payload_length)) {
            return 0;
        }
    } else if (family_uses_event_spool(input->service.family)) {
        if (!add_request(
                plan->reserve_requests,
                &plan->reserve_request_count,
                NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
                1u)
            || !add_request(
                plan->reserve_requests,
                &plan->reserve_request_count,
                NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
                (uint64_t)input->submission.payload_length
                    + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES)) {
            return 0;
        }
    }
    if (!add_request(
            plan->reserve_requests,
            &plan->reserve_request_count,
            NINLIL_RESOURCE_EVIDENCE,
            evidence_amount)) {
        return 0;
    }

    if (!add_request(
            plan->commit_requests,
            &plan->commit_request_count,
            NINLIL_RESOURCE_TRANSACTION,
            1u)
        || !add_request(
            plan->commit_requests,
            &plan->commit_request_count,
            NINLIL_RESOURCE_TARGET,
            1u)) {
        return 0;
    }
    if (family_uses_outbox(input->service.family)) {
        if (!add_request(
                plan->commit_requests,
                &plan->commit_request_count,
                NINLIL_RESOURCE_OUTBOX_BYTES,
                input->submission.payload_length)) {
            return 0;
        }
    } else if (family_uses_event_spool(input->service.family)) {
        if (!add_request(
                plan->commit_requests,
                &plan->commit_request_count,
                NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
                1u)
            || !add_request(
                plan->commit_requests,
                &plan->commit_request_count,
                NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
                input->submission.payload_length)) {
            return 0;
        }
    }
    return add_request(
        plan->commit_requests,
        &plan->commit_request_count,
        NINLIL_RESOURCE_EVIDENCE,
        1u);
}

static ninlil_status_t evaluate_resources(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_submission_preflight_result_t *result,
    ninlil_model_resource_reservation_plan_t *plan,
    int *out_ready)
{
    ninlil_model_capacity_batch_input_t batch;
    ninlil_model_capacity_batch_result_t batch_result;
    uint32_t index;
    ninlil_status_t status;

    *out_ready = 0;
    if (!build_resource_requests(input, plan)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&batch, 0, sizeof(batch));
    batch.current = input->resource_ledger;
    batch.operation = NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK;
    batch.request_count = plan->reserve_request_count;
    for (index = 0u; index < batch.request_count; ++index) {
        batch.requests[index] = plan->reserve_requests[index];
    }
    status = ninlil_model_capacity_batch_transition(&batch, &batch_result);
    if (status != NINLIL_OK) {
        return status;
    }
    if (batch_result.action
        == NINLIL_MODEL_CAPACITY_BATCH_BLOCK_SET_REQUIRED) {
        result->action =
            NINLIL_MODEL_SUBMISSION_PREFLIGHT_CAPACITY_BLOCK_COMMIT_REQUIRED;
        result->api_status = NINLIL_OK;
        result->capacity_block.next_ledger = batch_result.next;
        result->capacity_block.failing_kind = batch_result.failing_kind;
        result->capacity_block.failing_request_ordinal =
            batch_result.failing_request_ordinal;
        return NINLIL_OK;
    }
    if (batch_result.action == NINLIL_MODEL_CAPACITY_BATCH_ALREADY_BLOCKED) {
        set_rejected(result, NINLIL_REASON_CAPACITY_EXHAUSTED);
        return NINLIL_OK;
    }
    if (batch_result.action
        == NINLIL_MODEL_CAPACITY_BATCH_COUNTER_EXHAUSTED) {
        set_rejected(result, NINLIL_REASON_COUNTER_EXHAUSTED);
        return NINLIL_OK;
    }
    if (batch_result.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED) {
        return NINLIL_E_INVALID_STATE;
    }
    plan->reserved_ledger = batch_result.next;

    (void)memset(&batch, 0, sizeof(batch));
    batch.current = plan->reserved_ledger;
    batch.operation = NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED;
    batch.request_count = plan->commit_request_count;
    for (index = 0u; index < batch.request_count; ++index) {
        batch.requests[index] = plan->commit_requests[index];
    }
    status = ninlil_model_capacity_batch_transition(&batch, &batch_result);
    if (status != NINLIL_OK
        || batch_result.action
            != NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED) {
        return status == NINLIL_OK ? NINLIL_E_INVALID_STATE : status;
    }
    plan->committed_ledger = batch_result.next;
    *out_ready = 1;
    return NINLIL_OK;
}

static ninlil_status_t evaluate_quota_and_grant(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_submission_preflight_result_t *result,
    ninlil_model_quota_commit_plan_t *plan,
    int *out_passed)
{
    uint64_t admissions = 0u;
    uint64_t bytes = 0u;
    uint64_t prospective;
    uint64_t window_remaining;

    *out_passed = 0;
    if (input->quota.window_is_current > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input->quota.window_is_current != 0u) {
        admissions = input->quota.admissions_in_window;
        bytes = input->quota.payload_bytes_in_window;
    }

    if (!checked_increment(input->quota.inflight_count, &prospective)
        || prospective > input->service.inflight_limit) {
        set_rejected(result, NINLIL_REASON_CAPACITY_EXHAUSTED);
        return NINLIL_OK;
    }
    plan->next_inflight_count = prospective;
    window_remaining = input->service.admission_window_ms
        - (input->clock.now_ms % input->service.admission_window_ms);
    if (!checked_increment(admissions, &prospective)
        || prospective > input->service.max_admissions_per_window) {
        set_rejected_with_guidance(
            result,
            NINLIL_REASON_RATE_EXHAUSTED,
            NINLIL_RETRY_SAME_AFTER,
            window_remaining);
        return NINLIL_OK;
    }
    plan->next_admissions_in_window = prospective;
    if (!checked_add(bytes, input->submission.payload_length, &prospective)
        || prospective > input->service.max_payload_bytes_per_window) {
        set_rejected_with_guidance(
            result,
            NINLIL_REASON_RATE_EXHAUSTED,
            NINLIL_RETRY_SAME_AFTER,
            window_remaining);
        return NINLIL_OK;
    }
    plan->next_payload_bytes_in_window = prospective;

    if (family_uses_event_spool(input->service.family)) {
        uint64_t spool_bytes;
        const ninlil_model_origin_grant_snapshot_t *grant =
            &input->authority.grant;

        if (input->submission.payload_length > grant->max_payload_bytes) {
            set_rejected(result, NINLIL_REASON_GRANT_LIMIT_EXCEEDED);
            return NINLIL_OK;
        }
        if (!checked_increment(
                input->event_grant_usage.active_spool_count,
                &prospective)
            || prospective > grant->max_active_spool_count) {
            set_rejected(result, NINLIL_REASON_GRANT_LIMIT_EXCEEDED);
            return NINLIL_OK;
        }
        plan->next_event_active_spool_count = prospective;
        if (!checked_add(
                input->submission.payload_length,
                NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES,
                &spool_bytes)
            || !checked_add(
                input->event_grant_usage.active_spool_bytes,
                spool_bytes,
                &prospective)
            || prospective > grant->max_active_spool_bytes) {
            set_rejected(result, NINLIL_REASON_GRANT_LIMIT_EXCEEDED);
            return NINLIL_OK;
        }
        plan->next_event_active_spool_bytes = prospective;
        prospective = plan->next_admissions_in_window;
        if (prospective > grant->max_admissions_per_window) {
            set_rejected_with_guidance(
                result,
                NINLIL_REASON_RATE_EXHAUSTED,
                NINLIL_RETRY_SAME_AFTER,
                window_remaining);
            return NINLIL_OK;
        }
    }

    plan->clock_epoch_id = input->clock.clock_epoch_id;
    plan->window_started_at_ms = input->clock.now_ms
        - (input->clock.now_ms % input->service.admission_window_ms);
    *out_passed = 1;
    return NINLIL_OK;
}

static void fill_admission_plan(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_submission_preflight_result_t *result,
    uint64_t transaction_sequence,
    uint64_t owner_sequence,
    uint64_t absolute_effect_deadline,
    uint64_t absolute_evidence_close,
    const ninlil_model_quota_commit_plan_t *quota,
    const ninlil_model_resource_reservation_plan_t *resources)
{
    ninlil_model_admission_plan_t *plan = &result->admission;

    plan->family = input->service.family;
    plan->registered_service = input->service;
    plan->source = input->service.source;
    plan->target = input->submission.target;
    plan->service = input->service.identity;
    plan->idempotency_key = input->submission.idempotency_key;
    plan->content_digest = input->submission.content_digest;
    plan->canonical_submission_digest =
        input->submission.canonical_submission_digest;
    plan->event_id = input->submission.event_id;
    plan->generation = input->submission.generation;
    plan->required_evidence = input->submission.required_evidence;
    plan->payload_length = input->submission.payload_length;
    plan->transaction_sequence = transaction_sequence;
    plan->scheduler_owner_sequence = owner_sequence;
    plan->admission_clock_epoch_id = input->clock.clock_epoch_id;
    plan->admitted_at_ms = input->clock.now_ms;
    if (family_uses_outbox(input->service.family)) {
        plan->deadline_clock_epoch_id = input->clock.clock_epoch_id;
    }
    plan->absolute_effect_deadline_ms = absolute_effect_deadline;
    plan->absolute_evidence_close_ms = absolute_evidence_close;
    plan->quota = *quota;
    plan->resources = *resources;
    if (family_uses_event_spool(input->service.family)) {
        plan->grant = input->authority.grant;
    }
}

ninlil_status_t ninlil_model_submission_preflight(
    const ninlil_model_submission_preflight_input_t *input,
    ninlil_model_submission_preflight_result_t *out_result)
{
    ninlil_status_t status;
    int is_new;
    int allowed;
    int quota_passed;
    int resources_ready;
    uint64_t transaction_sequence;
    uint64_t owner_sequence;
    uint64_t absolute_effect_deadline = NINLIL_NO_DEADLINE;
    uint64_t absolute_evidence_close = NINLIL_NO_DEADLINE;
    ninlil_model_quota_commit_plan_t quota_plan;
    ninlil_model_resource_reservation_plan_t resource_plan;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (input == NULL
        || !ninlil_model_family_is_admit_supported(input->service.family)
        || (input->service.local_side
                != NINLIL_MODEL_LOCAL_SUBMISSION_SENDER
            && input->service.local_side
                != NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    /* RF4: a structurally valid receiver submission stops before all facts. */
    if (input->service.local_side == NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER) {
        set_rejected(out_result, NINLIL_REASON_UNSUPPORTED_DIRECTION);
        return NINLIL_OK;
    }
    if (!service_shape_is_valid(&input->service)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    /* 13 Submission reducer: semantic guards are intentionally ordered. */
    if (input->submission.target_count != 1u) {
        set_rejected(out_result, NINLIL_REASON_TARGET_COUNT_UNSUPPORTED);
        return NINLIL_OK;
    }
    if (input->submission.schema_major != input->service.schema_major
        || input->submission.schema_minor < input->service.schema_minor_min
        || input->submission.schema_minor > input->service.schema_minor_max
        || input->service.identity.schema_minor
            != input->submission.schema_minor) {
        set_rejected(out_result, NINLIL_REASON_INVALID_SCHEMA);
        return NINLIL_OK;
    }
    if (input->submission.payload_length
        > input->service.logical_payload_limit) {
        set_rejected(out_result, NINLIL_REASON_INVALID_PAYLOAD_LENGTH);
        return NINLIL_OK;
    }
    if (input->submission.content_digest_matches > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input->submission.content_digest_matches == 0u) {
        set_api_error(out_result, NINLIL_E_INVALID_ARGUMENT);
        return NINLIL_OK;
    }
    if (!concrete_target_is_valid(&input->submission.target)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!submission_identity_shape_is_valid(input)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (input->service.family == NINLIL_FAMILY_DESIRED_STATE
        || input->service.family == NINLIL_FAMILY_TRANSFER_RESERVED
        || input->service.family == NINLIL_FAMILY_CONFIG_RESERVED) {
        if (input->submission.effect_deadline_ms == NINLIL_NO_DEADLINE
            || input->submission.effect_deadline_ms
                < input->service.minimum_deadline_ms
            || input->submission.effect_deadline_ms
                > input->service.maximum_deadline_ms
            || input->submission.evidence_grace_ms
                > input->service.maximum_evidence_grace_ms) {
            set_rejected(out_result, NINLIL_REASON_DEADLINE_INVALID);
            return NINLIL_OK;
        }
    } else if (input->submission.effect_deadline_ms != NINLIL_NO_DEADLINE
        || input->submission.evidence_grace_ms != 0u) {
        set_rejected(
            out_result,
            NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED);
        return NINLIL_OK;
    }
    if (input->submission.required_evidence < NINLIL_EVIDENCE_RECEIVED
        || input->submission.required_evidence > NINLIL_EVIDENCE_VERIFIED
        || (input->service.supported_evidence_mask
                & NINLIL_EVIDENCE_MASK(input->submission.required_evidence))
            == 0u) {
        set_rejected(out_result, NINLIL_REASON_EVIDENCE_UNSUPPORTED);
        return NINLIL_OK;
    }
    if (!idempotency_key_is_valid(&input->submission.idempotency_key)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = reduce_idempotency(input, out_result, &is_new);
    if (status != NINLIL_OK) {
        (void)memset(out_result, 0, sizeof(*out_result));
        return status;
    }
    if (is_new == 0) {
        return NINLIL_OK;
    }

    switch (input->clock.state) {
    case NINLIL_MODEL_ADMISSION_CLOCK_TRUSTED:
        if (id_is_zero(&input->clock.clock_epoch_id)) {
            set_api_error(out_result, NINLIL_E_DEGRADED);
            return NINLIL_OK;
        }
        break;
    case NINLIL_MODEL_ADMISSION_CLOCK_TEMPORARY_OR_UNCERTAIN:
        set_api_error(out_result, NINLIL_E_CLOCK_UNCERTAIN);
        return NINLIL_OK;
    case NINLIL_MODEL_ADMISSION_CLOCK_PERMANENT_OR_INVALID:
        set_api_error(out_result, NINLIL_E_DEGRADED);
        return NINLIL_OK;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (family_uses_outbox(input->service.family)
        && (!checked_add(
                input->clock.now_ms,
                input->submission.effect_deadline_ms,
                &absolute_effect_deadline)
            || !checked_add(
                absolute_effect_deadline,
                input->submission.evidence_grace_ms,
                &absolute_evidence_close))) {
        set_rejected(out_result, NINLIL_REASON_DEADLINE_INVALID);
        return NINLIL_OK;
    }

    if (!checked_increment(
            input->last_transaction_sequence,
            &transaction_sequence)) {
        set_rejected(out_result, NINLIL_REASON_COUNTER_EXHAUSTED);
        return NINLIL_OK;
    }
    if (!checked_increment(
            input->last_scheduler_owner_sequence,
            &owner_sequence)) {
        set_rejected(out_result, NINLIL_REASON_COUNTER_EXHAUSTED);
        return NINLIL_OK;
    }

    status = reduce_authority(input, out_result, &allowed);
    if (status != NINLIL_OK) {
        (void)memset(out_result, 0, sizeof(*out_result));
        return status;
    }
    if (allowed == 0) {
        return NINLIL_OK;
    }

    (void)memset(&quota_plan, 0, sizeof(quota_plan));
    status = evaluate_quota_and_grant(
        input, out_result, &quota_plan, &quota_passed);
    if (status != NINLIL_OK) {
        (void)memset(out_result, 0, sizeof(*out_result));
        return status;
    }
    if (quota_passed == 0) {
        return NINLIL_OK;
    }

    (void)memset(&resource_plan, 0, sizeof(resource_plan));
    status = evaluate_resources(
        input, out_result, &resource_plan, &resources_ready);
    if (status != NINLIL_OK) {
        (void)memset(out_result, 0, sizeof(*out_result));
        return status;
    }
    if (resources_ready == 0) {
        return NINLIL_OK;
    }

    out_result->action =
        NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION;
    out_result->api_status = NINLIL_OK;
    fill_admission_plan(
        input,
        out_result,
        transaction_sequence,
        owner_sequence,
        absolute_effect_deadline,
        absolute_evidence_close,
        &quota_plan,
        &resource_plan);
    return NINLIL_OK;
}
