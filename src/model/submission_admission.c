#include "submission_admission.h"
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

static int text_id_equal(const ninlil_text_id_t *left, const ninlil_text_id_t *right)
{
    return left->length == right->length
        && memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int key_equal(
    const ninlil_model_idempotency_key_t *left,
    const ninlil_model_idempotency_key_t *right)
{
    return left->length == right->length
        && memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static int local_identity_equal(
    const ninlil_local_identity_t *left,
    const ninlil_local_identity_t *right)
{
    return left->abi_version == right->abi_version
        && left->struct_size == right->struct_size
        && id_equal(&left->device_id, &right->device_id)
        && id_equal(&left->installation_id, &right->installation_id)
        && id_equal(&left->site_domain_id, &right->site_domain_id)
        && left->binding_epoch == right->binding_epoch
        && left->membership_epoch == right->membership_epoch
        && left->flags == right->flags
        && left->reserved_zero == right->reserved_zero;
}

static int party_equal(const ninlil_party_t *left, const ninlil_party_t *right)
{
    return left->abi_version == right->abi_version
        && left->struct_size == right->struct_size
        && id_equal(&left->runtime_id, &right->runtime_id)
        && id_equal(
            &left->application_instance_id, &right->application_instance_id)
        && local_identity_equal(&left->local_identity, &right->local_identity);
}

static int target_equal(
    const ninlil_concrete_target_t *left,
    const ninlil_concrete_target_t *right)
{
    return left->abi_version == right->abi_version
        && left->struct_size == right->struct_size
        && id_equal(&left->target_runtime_id, &right->target_runtime_id)
        && id_equal(
            &left->target_application_instance_id,
            &right->target_application_instance_id)
        && id_equal(&left->device_id, &right->device_id)
        && id_equal(&left->installation_id, &right->installation_id)
        && id_equal(&left->site_domain_id, &right->site_domain_id)
        && left->binding_epoch == right->binding_epoch
        && left->membership_epoch == right->membership_epoch
        && left->flags == right->flags
        && left->reserved_zero == right->reserved_zero;
}

static int service_identity_equal(
    const ninlil_service_identity_t *left,
    const ninlil_service_identity_t *right)
{
    return left->abi_version == right->abi_version
        && left->struct_size == right->struct_size
        && text_id_equal(&left->namespace_id, &right->namespace_id)
        && text_id_equal(&left->service_id, &right->service_id)
        && text_id_equal(&left->schema_id, &right->schema_id)
        && left->descriptor_revision == right->descriptor_revision
        && digest_equal(&left->descriptor_digest, &right->descriptor_digest)
        && left->schema_major == right->schema_major
        && left->schema_minor == right->schema_minor
        && left->family == right->family;
}

static int submission_service_equal(
    const ninlil_model_submission_service_t *left,
    const ninlil_model_submission_service_t *right)
{
    return left->family == right->family
        && left->local_side == right->local_side
        && party_equal(&left->source, &right->source)
        && service_identity_equal(&left->identity, &right->identity)
        && left->schema_major == right->schema_major
        && left->schema_minor_min == right->schema_minor_min
        && left->schema_minor_max == right->schema_minor_max
        && left->reserved_zero_u16 == right->reserved_zero_u16
        && left->supported_evidence_mask == right->supported_evidence_mask
        && left->logical_payload_limit == right->logical_payload_limit
        && left->inflight_limit == right->inflight_limit
        && left->admission_window_ms == right->admission_window_ms
        && left->max_admissions_per_window
            == right->max_admissions_per_window
        && left->max_payload_bytes_per_window
            == right->max_payload_bytes_per_window
        && left->max_evidence_per_target == right->max_evidence_per_target
        && left->minimum_deadline_ms == right->minimum_deadline_ms
        && left->maximum_deadline_ms == right->maximum_deadline_ms
        && left->maximum_evidence_grace_ms
            == right->maximum_evidence_grace_ms;
}

static int grant_equal(
    const ninlil_model_origin_grant_snapshot_t *left,
    const ninlil_model_origin_grant_snapshot_t *right)
{
    return id_equal(&left->provider_id, &right->provider_id)
        && left->provider_revision == right->provider_revision
        && digest_equal(&left->decision_digest, &right->decision_digest)
        && id_equal(&left->grant_id, &right->grant_id)
        && left->grant_revision == right->grant_revision
        && id_equal(&left->clock_epoch_id, &right->clock_epoch_id)
        && left->evaluated_at_ms == right->evaluated_at_ms
        && left->valid_from_ms == right->valid_from_ms
        && left->expires_at_ms == right->expires_at_ms
        && left->retry_delay_ms == right->retry_delay_ms
        && left->max_payload_bytes == right->max_payload_bytes
        && left->max_active_spool_count == right->max_active_spool_count
        && left->max_active_spool_bytes == right->max_active_spool_bytes
        && left->rate_window_ms == right->rate_window_ms
        && left->max_admissions_per_window
            == right->max_admissions_per_window
        && left->max_attempts_per_retry_cycle
            == right->max_attempts_per_retry_cycle;
}

static int quota_equal(
    const ninlil_model_quota_commit_plan_t *left,
    const ninlil_model_quota_commit_plan_t *right)
{
    return id_equal(&left->clock_epoch_id, &right->clock_epoch_id)
        && left->window_started_at_ms == right->window_started_at_ms
        && left->next_inflight_count == right->next_inflight_count
        && left->next_admissions_in_window
            == right->next_admissions_in_window
        && left->next_payload_bytes_in_window
            == right->next_payload_bytes_in_window
        && left->next_event_active_spool_count
            == right->next_event_active_spool_count
        && left->next_event_active_spool_bytes
            == right->next_event_active_spool_bytes;
}

static int capacity_entry_equal(
    const ninlil_model_capacity_entry_t *left,
    const ninlil_model_capacity_entry_t *right)
{
    return left->kind == right->kind
        && left->limit == right->limit
        && left->used == right->used
        && left->reserved == right->reserved
        && left->high_water == right->high_water
        && left->capacity_epoch == right->capacity_epoch
        && left->blocked == right->blocked
        && left->counter_exhausted_marker
            == right->counter_exhausted_marker;
}

static int ledger_equal(
    const ninlil_model_resource_ledger_t *left,
    const ninlil_model_resource_ledger_t *right)
{
    size_t index;

    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        if (!capacity_entry_equal(&left->entries[index], &right->entries[index])) {
            return 0;
        }
    }
    return 1;
}

static int header_is_current(uint16_t version, uint16_t size, size_t required)
{
    return version == NINLIL_ABI_VERSION && (size_t)size >= required;
}

static int ascii_lower_or_digit(uint8_t value)
{
    return (value >= (uint8_t)'a' && value <= (uint8_t)'z')
        || (value >= (uint8_t)'0' && value <= (uint8_t)'9');
}

static int text_id_is_valid(const ninlil_text_id_t *text, int namespace_grammar)
{
    size_t index;

    if (text->length == 0u || text->length > sizeof(text->bytes)
        || !ascii_lower_or_digit(text->bytes[0])) {
        return 0;
    }
    for (index = 1u; index < text->length; ++index) {
        uint8_t value = text->bytes[index];
        if (!ascii_lower_or_digit(value) && value != (uint8_t)'.'
            && value != (uint8_t)'-'
            && (namespace_grammar != 0 || value != (uint8_t)'_')) {
            return 0;
        }
    }
    for (index = text->length; index < sizeof(text->bytes); ++index) {
        if (text->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int presence_is_valid(
    uint32_t flags,
    const ninlil_id128_t *device,
    const ninlil_id128_t *installation,
    const ninlil_id128_t *site,
    uint64_t binding_epoch,
    uint64_t membership_epoch)
{
    uint32_t allowed = NINLIL_TARGET_HAS_DEVICE
        | NINLIL_TARGET_HAS_INSTALLATION | NINLIL_TARGET_HAS_SITE;
    int has_device = (flags & NINLIL_TARGET_HAS_DEVICE) != 0u;
    int has_installation =
        (flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u;
    int has_site = (flags & NINLIL_TARGET_HAS_SITE) != 0u;

    return (flags & ~allowed) == 0u
        && id_is_zero(device) == !has_device
        && id_is_zero(installation) == !has_installation
        && id_is_zero(site) == !has_site
        && (binding_epoch != 0u) == (has_device || has_installation)
        && (membership_epoch != 0u) == has_site;
}

static int party_is_valid(const ninlil_party_t *party)
{
    return header_is_current(
               party->abi_version, party->struct_size, sizeof(*party))
        && !id_is_zero(&party->runtime_id)
        && !id_is_zero(&party->application_instance_id)
        && header_is_current(
            party->local_identity.abi_version,
            party->local_identity.struct_size,
            sizeof(party->local_identity))
        && party->local_identity.reserved_zero == 0u
        && presence_is_valid(
            party->local_identity.flags,
            &party->local_identity.device_id,
            &party->local_identity.installation_id,
            &party->local_identity.site_domain_id,
            party->local_identity.binding_epoch,
            party->local_identity.membership_epoch);
}

static int target_is_valid(const ninlil_concrete_target_t *target)
{
    return header_is_current(
               target->abi_version, target->struct_size, sizeof(*target))
        && !id_is_zero(&target->target_runtime_id)
        && !id_is_zero(&target->target_application_instance_id)
        && target->reserved_zero == 0u
        && presence_is_valid(
            target->flags,
            &target->device_id,
            &target->installation_id,
            &target->site_domain_id,
            target->binding_epoch,
            target->membership_epoch);
}

static int service_identity_is_valid(const ninlil_service_identity_t *service)
{
    return header_is_current(
               service->abi_version, service->struct_size, sizeof(*service))
        && text_id_is_valid(&service->namespace_id, 1)
        && text_id_is_valid(&service->service_id, 0)
        && text_id_is_valid(&service->schema_id, 0)
        && service->descriptor_revision != 0u
        && digest_is_valid(&service->descriptor_digest)
        && ninlil_model_family_is_admit_supported(service->family);
}

static int registered_service_is_valid(
    const ninlil_model_submission_service_t *service)
{
    uint32_t allowed_evidence =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);

    int common = service->local_side
            == NINLIL_MODEL_LOCAL_SUBMISSION_SENDER
        && party_is_valid(&service->source)
        && service_identity_is_valid(&service->identity)
        && service->identity.family == service->family
        && service->identity.schema_major == service->schema_major
        && service->schema_minor_min <= service->schema_minor_max
        && service->identity.schema_minor >= service->schema_minor_min
        && service->identity.schema_minor <= service->schema_minor_max
        && service->reserved_zero_u16 == 0u
        && service->supported_evidence_mask != 0u
        && (service->supported_evidence_mask & ~allowed_evidence) == 0u
        && service->logical_payload_limit > 0u
        && service->inflight_limit > 0u
        && service->admission_window_ms > 0u
        && service->admission_window_ms <= NINLIL_M1A_MAX_RETRY_DELAY_MS
        && service->max_admissions_per_window > 0u
        && service->max_payload_bytes_per_window
            >= service->logical_payload_limit
        && service->max_evidence_per_target > 0u
        && service->max_evidence_per_target <= 8u;

    if (!common) {
        return 0;
    }
    if (service->family == NINLIL_FAMILY_DESIRED_STATE
        || service->family == NINLIL_FAMILY_TRANSFER_RESERVED
        || service->family == NINLIL_FAMILY_CONFIG_RESERVED) {
        return service->minimum_deadline_ms >= 1u
            && service->minimum_deadline_ms <= service->maximum_deadline_ms
            && service->maximum_deadline_ms < NINLIL_NO_DEADLINE;
    }
    return service->minimum_deadline_ms == NINLIL_NO_DEADLINE
        && service->maximum_deadline_ms == NINLIL_NO_DEADLINE
        && service->maximum_evidence_grace_ms == 0u;
}

static int grant_decision_is_zero(
    const ninlil_model_origin_grant_snapshot_t *grant);

static int plan_grant_shape_is_valid(const ninlil_model_admission_plan_t *plan)
{
    const ninlil_model_origin_grant_snapshot_t *grant = &plan->grant;

    if (plan->family == NINLIL_FAMILY_DESIRED_STATE
        || plan->family == NINLIL_FAMILY_TRANSFER_RESERVED
        || plan->family == NINLIL_FAMILY_CONFIG_RESERVED) {
        return grant_decision_is_zero(grant);
    }
    return !id_is_zero(&grant->provider_id)
        && grant->provider_revision != 0u
        && digest_is_valid(&grant->decision_digest)
        && !id_is_zero(&grant->grant_id)
        && grant->grant_revision != 0u
        && id_equal(&grant->clock_epoch_id, &plan->admission_clock_epoch_id)
        && grant->evaluated_at_ms == plan->admitted_at_ms
        && grant->valid_from_ms <= grant->evaluated_at_ms
        && grant->evaluated_at_ms < grant->expires_at_ms
        && grant->retry_delay_ms == 0u
        && grant->max_payload_bytes > 0u
        && plan->payload_length <= grant->max_payload_bytes
        && grant->max_active_spool_count > 0u
        && grant->max_active_spool_bytes > 0u
        && grant->rate_window_ms
            == plan->registered_service.admission_window_ms
        && grant->max_admissions_per_window > 0u
        && grant->max_admissions_per_window
            <= plan->registered_service.max_admissions_per_window
        && grant->max_attempts_per_retry_cycle
            == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
}

static int desired_deadlines_are_valid(
    const ninlil_model_admission_plan_t *plan)
{
    uint64_t relative_effect;
    uint64_t relative_grace;

    if (plan->absolute_effect_deadline_ms < plan->admitted_at_ms
        || plan->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
        || plan->absolute_evidence_close_ms
            < plan->absolute_effect_deadline_ms) {
        return 0;
    }
    relative_effect =
        plan->absolute_effect_deadline_ms - plan->admitted_at_ms;
    relative_grace = plan->absolute_evidence_close_ms
        - plan->absolute_effect_deadline_ms;
    return relative_effect >= plan->registered_service.minimum_deadline_ms
        && relative_effect <= plan->registered_service.maximum_deadline_ms
        && relative_grace
            <= plan->registered_service.maximum_evidence_grace_ms;
}

static int key_is_valid(const ninlil_model_idempotency_key_t *key)
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

static int digest_is_zero(const ninlil_digest256_t *digest)
{
    return digest->algorithm == 0u
        && digest->reserved_zero == 0u
        && bytes_are_zero(digest->bytes, sizeof(digest->bytes));
}

static int text_id_is_zero(const ninlil_text_id_t *text_id)
{
    return text_id->length == 0u
        && bytes_are_zero(text_id->bytes, sizeof(text_id->bytes));
}

static int key_is_zero(const ninlil_model_idempotency_key_t *key)
{
    return key->length == 0u
        && bytes_are_zero(key->bytes, sizeof(key->bytes));
}

static int local_identity_is_zero(const ninlil_local_identity_t *identity)
{
    return identity->abi_version == 0u
        && identity->struct_size == 0u
        && id_is_zero(&identity->device_id)
        && id_is_zero(&identity->installation_id)
        && id_is_zero(&identity->site_domain_id)
        && identity->binding_epoch == 0u
        && identity->membership_epoch == 0u
        && identity->flags == 0u
        && identity->reserved_zero == 0u;
}

static int party_is_zero(const ninlil_party_t *party)
{
    return party->abi_version == 0u
        && party->struct_size == 0u
        && id_is_zero(&party->runtime_id)
        && id_is_zero(&party->application_instance_id)
        && local_identity_is_zero(&party->local_identity);
}

static int target_is_zero(const ninlil_concrete_target_t *target)
{
    return target->abi_version == 0u
        && target->struct_size == 0u
        && id_is_zero(&target->target_runtime_id)
        && id_is_zero(&target->target_application_instance_id)
        && id_is_zero(&target->device_id)
        && id_is_zero(&target->installation_id)
        && id_is_zero(&target->site_domain_id)
        && target->binding_epoch == 0u
        && target->membership_epoch == 0u
        && target->flags == 0u
        && target->reserved_zero == 0u;
}

static int service_identity_is_zero(const ninlil_service_identity_t *service)
{
    return service->abi_version == 0u
        && service->struct_size == 0u
        && text_id_is_zero(&service->namespace_id)
        && text_id_is_zero(&service->service_id)
        && text_id_is_zero(&service->schema_id)
        && service->descriptor_revision == 0u
        && digest_is_zero(&service->descriptor_digest)
        && service->schema_major == 0u
        && service->schema_minor == 0u
        && service->family == 0u;
}

static int mapping_scope_is_zero(const ninlil_model_mapping_scope_t *scope)
{
    return id_is_zero(&scope->source_application_instance_id)
        && text_id_is_zero(&scope->namespace_id)
        && text_id_is_zero(&scope->service_id);
}

static int grant_decision_is_zero(
    const ninlil_model_origin_grant_snapshot_t *grant)
{
    return id_is_zero(&grant->provider_id)
        && grant->provider_revision == 0u
        && digest_is_zero(&grant->decision_digest)
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

static int event_mapping_is_zero(
    const ninlil_model_event_mapping_record_t *mapping)
{
    return mapping_scope_is_zero(&mapping->scope)
        && id_is_zero(&mapping->event_id)
        && key_is_zero(&mapping->caller_key)
        && id_is_zero(&mapping->transaction_id)
        && digest_is_zero(&mapping->canonical_submission_digest);
}

static int bound_grant_is_zero(const ninlil_model_bound_grant_record_t *grant)
{
    return grant_decision_is_zero(&grant->decision)
        && party_is_zero(&grant->source)
        && service_identity_is_zero(&grant->service)
        && target_is_zero(&grant->target)
        && id_is_zero(&grant->event_id)
        && digest_is_zero(&grant->content_digest)
        && grant->required_evidence == 0u
        && grant->payload_length == 0u;
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

static void set_api_error_result(
    ninlil_submission_result_t *result,
    ninlil_status_t status,
    ninlil_status_t *out_status)
{
    initialize_public_result(result, 0);
    result->kind = NINLIL_SUBMISSION_INVALID;
    result->reason = NINLIL_REASON_NONE;
    result->retry_guidance = NINLIL_RETRY_NEVER;
    *out_status = status;
}

static void set_rejected_no_space(
    ninlil_submission_result_t *result,
    ninlil_status_t *out_status)
{
    initialize_public_result(result, 1);
    result->kind = NINLIL_SUBMISSION_REJECTED;
    result->reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
    result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
    *out_status = NINLIL_OK;
}

static int resource_plan_matches_admission(
    const ninlil_model_admission_plan_t *plan);

static int quota_shape_is_valid(const ninlil_model_admission_plan_t *plan)
{
    const ninlil_model_quota_commit_plan_t *quota = &plan->quota;
    uint64_t expected_window_start;

    if (plan->registered_service.admission_window_ms == 0u) {
        return 0;
    }
    expected_window_start = plan->admitted_at_ms
        - (plan->admitted_at_ms
            % plan->registered_service.admission_window_ms);
    if (!id_equal(&quota->clock_epoch_id, &plan->admission_clock_epoch_id)
        || quota->window_started_at_ms != expected_window_start
        || quota->next_inflight_count == 0u
        || quota->next_inflight_count > plan->registered_service.inflight_limit
        || quota->next_admissions_in_window == 0u
        || quota->next_admissions_in_window
            > plan->registered_service.max_admissions_per_window
        || quota->next_payload_bytes_in_window < plan->payload_length
        || quota->next_payload_bytes_in_window
            > plan->registered_service.max_payload_bytes_per_window) {
        return 0;
    }
    if (plan->family == NINLIL_FAMILY_DESIRED_STATE) {
        return quota->next_event_active_spool_count == 0u
            && quota->next_event_active_spool_bytes == 0u;
    }
    return plan->grant.rate_window_ms
            == plan->registered_service.admission_window_ms
        && quota->next_admissions_in_window
            <= plan->grant.max_admissions_per_window
        && quota->next_event_active_spool_count >= 1u
        && quota->next_event_active_spool_count
            <= plan->grant.max_active_spool_count
        && quota->next_event_active_spool_bytes
            >= (uint64_t)plan->payload_length
                + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES
        && quota->next_event_active_spool_bytes
            <= plan->grant.max_active_spool_bytes;
}

static int plan_uplink_identity_is_valid(const ninlil_model_admission_plan_t *plan);

static int plan_is_valid(const ninlil_model_admission_plan_t *plan)
{
    ninlil_model_capacity_snapshot_view_t snapshot;

    if ((plan->family != NINLIL_FAMILY_DESIRED_STATE
            && plan->family != NINLIL_FAMILY_EVENT_FACT
            && !ninlil_model_family_is_b5_lab(plan->family))
        || plan->registered_service.family != plan->family
        || plan->registered_service.local_side
            != NINLIL_MODEL_LOCAL_SUBMISSION_SENDER
        || plan->service.family != plan->family
        || !registered_service_is_valid(&plan->registered_service)
        || !party_is_valid(&plan->source)
        || !target_is_valid(&plan->target)
        || !service_identity_is_valid(&plan->service)
        || !party_equal(&plan->source, &plan->registered_service.source)
        || !service_identity_equal(
            &plan->service, &plan->registered_service.identity)
        || plan->transaction_sequence == 0u
        || plan->scheduler_owner_sequence == 0u
        || id_is_zero(&plan->admission_clock_epoch_id)
        || !key_is_valid(&plan->idempotency_key)
        || !digest_is_valid(&plan->content_digest)
        || !digest_is_valid(&plan->canonical_submission_digest)
        || plan->payload_length > NINLIL_MODEL_ADMISSION_MAX_PAYLOAD_BYTES
        || plan->payload_length > plan->registered_service.logical_payload_limit
        || plan->required_evidence < NINLIL_EVIDENCE_RECEIVED
        || plan->required_evidence > NINLIL_EVIDENCE_VERIFIED
        || (plan->registered_service.supported_evidence_mask
                & NINLIL_EVIDENCE_MASK(plan->required_evidence)) == 0u
        || !plan_grant_shape_is_valid(plan)
        || !quota_shape_is_valid(plan)
        || !resource_plan_matches_admission(plan)
        || ninlil_model_resource_ledger_project(
               &plan->resources.committed_ledger, &snapshot)
            != NINLIL_OK) {
        return 0;
    }
    if (plan->family == NINLIL_FAMILY_DESIRED_STATE
        || plan->family == NINLIL_FAMILY_TRANSFER_RESERVED
        || plan->family == NINLIL_FAMILY_CONFIG_RESERVED) {
        return id_is_zero(&plan->event_id)
            && plan->generation != 0u
            && id_equal(
                &plan->deadline_clock_epoch_id,
                &plan->admission_clock_epoch_id)
            && desired_deadlines_are_valid(plan);
    }
    return plan_uplink_identity_is_valid(plan);
}

static int plan_uplink_identity_is_valid(const ninlil_model_admission_plan_t *plan)
{
    if (plan->family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || plan->family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return id_is_zero(&plan->event_id)
            && plan->generation != 0u
            && id_is_zero(&plan->deadline_clock_epoch_id)
            && plan->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
            && plan->absolute_evidence_close_ms == NINLIL_NO_DEADLINE;
    }
    return !id_is_zero(&plan->event_id)
        && plan->generation == 0u
        && id_is_zero(&plan->deadline_clock_epoch_id)
        && plan->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
        && plan->absolute_evidence_close_ms == NINLIL_NO_DEADLINE;
}

static int payload_is_valid(
    const ninlil_model_owned_payload_t *payload,
    const ninlil_model_admission_plan_t *plan)
{
    size_t index;

    if (payload->length != plan->payload_length
        || payload->length > sizeof(payload->bytes)
        || payload->content_verified != 1u
        || !digest_is_valid(&payload->verified_content_digest)
        || !digest_equal(
            &payload->verified_content_digest, &plan->content_digest)) {
        return 0;
    }
    for (index = payload->length; index < sizeof(payload->bytes); ++index) {
        if (payload->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int descriptor_contract_is_valid(
    const ninlil_model_descriptor_contract_extension_t *contract,
    ninlil_family_t family)
{
    if (contract->target_limit != 1u
        || contract->max_attempts_per_target_per_cycle == 0u
        || contract->max_attempts_per_target_per_cycle
            > NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || contract->reserved_zero != 0u
        || contract->custody_policy
            != NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE
        || contract->attempt_receipt_timeout_ms == 0u
        || contract->attempt_receipt_timeout_ms
            > NINLIL_M1A_MAX_ATTEMPT_RECEIPT_TIMEOUT_MS
        || contract->retry_backoff_ms == 0u
        || contract->retry_backoff_ms > NINLIL_M1A_MAX_RETRY_BACKOFF_MS
        || contract->application_completion_timeout_ms == 0u
        || contract->application_completion_timeout_ms
            > NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS
        || contract->required_dedup_window_ms == 0u) {
        return 0;
    }
    if (family == NINLIL_FAMILY_EVENT_FACT
        || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return contract->max_attempts_per_target_per_cycle
                == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
            && contract->direction == NINLIL_DIRECTION_UPLINK
            && contract->admission_authority
                == NINLIL_AUTHORITY_ORIGIN_WITH_GRANT
            && contract->apply_contract
                == NINLIL_APPLY_APPLICATION_DEDUP;
    }
    return contract->direction == NINLIL_DIRECTION_DOWNLINK
        && contract->admission_authority
            == NINLIL_AUTHORITY_CONTROLLER_ONLY
        && (contract->apply_contract == NINLIL_APPLY_IDEMPOTENT
            || contract->apply_contract
                == NINLIL_APPLY_APPLICATION_DEDUP);
}

static void make_assurance(
    ninlil_family_t family,
    ninlil_admission_assurance_t *assurance)
{
    (void)memset(assurance, 0, sizeof(*assurance));
    assurance->abi_version = NINLIL_ABI_VERSION;
    assurance->struct_size = (uint16_t)sizeof(*assurance);
    assurance->assurance_profile = NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL;
    assurance->submission_validated = 1u;
    assurance->target_roster_fixed = 1u;
    assurance->descriptor_snapshot_fixed = 1u;
    assurance->local_journal_committed = 1u;
    assurance->local_capacity_reserved = 1u;
    assurance->idempotency_mapping_committed = 1u;
    assurance->origin_grant_snapshot_committed =
        (family == NINLIL_FAMILY_EVENT_FACT
            || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
            || family == NINLIL_FAMILY_MEASUREMENT_RESERVED)
            ? 1u
            : 0u;
}

static ninlil_model_mapping_scope_t make_mapping_scope(
    const ninlil_model_admission_plan_t *plan)
{
    ninlil_model_mapping_scope_t scope;

    (void)memset(&scope, 0, sizeof(scope));
    scope.source_application_instance_id = plan->source.application_instance_id;
    scope.namespace_id = plan->service.namespace_id;
    scope.service_id = plan->service.service_id;
    return scope;
}

static uint32_t common_record_mask(void)
{
    return NINLIL_MODEL_ADMISSION_WRITE_TRANSACTION_ID_INDEX
        | NINLIL_MODEL_ADMISSION_WRITE_TRANSACTION_COUNTER
        | NINLIL_MODEL_ADMISSION_WRITE_OWNER_COUNTER
        | NINLIL_MODEL_ADMISSION_WRITE_OWNER_BINDING
        | NINLIL_MODEL_ADMISSION_WRITE_TRANSACTION
        | NINLIL_MODEL_ADMISSION_WRITE_TARGET
        | NINLIL_MODEL_ADMISSION_WRITE_DESCRIPTOR
        | NINLIL_MODEL_ADMISSION_WRITE_PAYLOAD
        | NINLIL_MODEL_ADMISSION_WRITE_CALLER_MAPPING
        | NINLIL_MODEL_ADMISSION_WRITE_QUOTA
        | NINLIL_MODEL_ADMISSION_WRITE_RESOURCES
        | NINLIL_MODEL_ADMISSION_WRITE_INITIAL_QUEUE
        | NINLIL_MODEL_ADMISSION_WRITE_EVIDENCE;
}

static void build_write_set(
    const ninlil_model_id_allocation_input_t *input,
    const ninlil_id128_t *transaction_id,
    ninlil_model_admission_write_set_t *write_set)
{
    ninlil_model_mapping_scope_t scope =
        make_mapping_scope(&input->preflight_plan);

    (void)memset(write_set, 0, sizeof(*write_set));
    write_set->durability = NINLIL_DURABILITY_FULL;
    write_set->record_mask = common_record_mask();
    write_set->transaction_id = *transaction_id;
    write_set->plan = input->preflight_plan;
    write_set->payload = input->payload;
    write_set->descriptor.registered_service =
        input->preflight_plan.registered_service;
    write_set->descriptor.contract = input->descriptor_contract;
    write_set->caller_mapping.scope = scope;
    write_set->caller_mapping.caller_key =
        input->preflight_plan.idempotency_key;
    write_set->caller_mapping.transaction_id = *transaction_id;
    write_set->caller_mapping.canonical_submission_digest =
        input->preflight_plan.canonical_submission_digest;
    write_set->initial_transaction_state = NINLIL_TXN_READY;
    write_set->initial_outcome = NINLIL_OUTCOME_NONE;
    write_set->initial_reason = NINLIL_REASON_NONE;
    write_set->transaction_record_revision = 1u;
    write_set->reservation_manifest.evidence_summary_used = 1u;
    write_set->reservation_manifest.evidence_raw_reserved =
        input->preflight_plan.registered_service.max_evidence_per_target;
    write_set->committed_quota = input->preflight_plan.quota;
    write_set->committed_resource_ledger =
        input->preflight_plan.resources.committed_ledger;
    make_assurance(input->preflight_plan.family, &write_set->assurance);

    if (input->preflight_plan.family == NINLIL_FAMILY_EVENT_FACT
        || input->preflight_plan.family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || input->preflight_plan.family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        write_set->record_mask |=
            NINLIL_MODEL_ADMISSION_WRITE_EVENT_MAPPING
            | NINLIL_MODEL_ADMISSION_WRITE_GRANT
            | NINLIL_MODEL_ADMISSION_WRITE_EVENT_MANAGEMENT;
        write_set->event_mapping_present = 1u;
        write_set->event_mapping.scope = scope;
        write_set->event_mapping.event_id = input->preflight_plan.event_id;
        write_set->event_mapping.caller_key =
            input->preflight_plan.idempotency_key;
        write_set->event_mapping.transaction_id = *transaction_id;
        write_set->event_mapping.canonical_submission_digest =
            input->preflight_plan.canonical_submission_digest;
        write_set->grant_snapshot_present = 1u;
        write_set->grant_snapshot.decision = input->preflight_plan.grant;
        write_set->grant_snapshot.source = input->preflight_plan.source;
        write_set->grant_snapshot.service = input->preflight_plan.service;
        write_set->grant_snapshot.target = input->preflight_plan.target;
        write_set->grant_snapshot.event_id = input->preflight_plan.event_id;
        write_set->grant_snapshot.content_digest =
            input->preflight_plan.content_digest;
        write_set->grant_snapshot.required_evidence =
            input->preflight_plan.required_evidence;
        write_set->grant_snapshot.payload_length =
            input->preflight_plan.payload_length;
        write_set->initial_queue_kind = NINLIL_MODEL_INITIAL_EVENT_SPOOL;
        write_set->event_spool_revision = 1u;
        write_set->initial_family_snapshot.family_state =
            NINLIL_MODEL_INITIAL_EVENT_HELD_READY;
        write_set->initial_family_snapshot.retry_cycle_id = 1u;
        write_set->initial_family_snapshot.deadline_verdict =
            NINLIL_DEADLINE_NOT_APPLICABLE;
        write_set->initial_family_snapshot.spool_revision = 1u;
        write_set->event_management_reservation_present = 1u;
        write_set->reservation_manifest.event_resume_slots =
            NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS;
        write_set->reservation_manifest.event_resume_slot_bytes = 256u;
        write_set->reservation_manifest.event_discard_slots = 1u;
        write_set->reservation_manifest.event_discard_slot_bytes = 512u;
        write_set->reservation_manifest.event_management_total_bytes =
            NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES;
    } else if (input->preflight_plan.family == NINLIL_FAMILY_DESIRED_STATE
        || input->preflight_plan.family == NINLIL_FAMILY_TRANSFER_RESERVED
        || input->preflight_plan.family == NINLIL_FAMILY_CONFIG_RESERVED) {
        write_set->record_mask |=
            NINLIL_MODEL_ADMISSION_WRITE_COMMAND_CANCEL;
        write_set->initial_queue_kind = NINLIL_MODEL_INITIAL_COMMAND_OUTBOX;
        write_set->initial_family_snapshot.family_state =
            NINLIL_MODEL_INITIAL_DESIRED_TARGET_READY;
        write_set->initial_family_snapshot.deadline_verdict =
            NINLIL_DEADLINE_PENDING;
        write_set->command_cancel_reservation_present = 1u;
        write_set->reservation_manifest.command_cancel_slots = 1u;
        write_set->reservation_manifest
            .command_cancel_outbox_metadata_slots = 1u;
    }
}

static int entropy_state_is_known(ninlil_model_entropy_draw_state_t state)
{
    return state >= NINLIL_MODEL_ENTROPY_DRAW_FULL
        && state <= NINLIL_MODEL_ENTROPY_DRAW_PARTIAL;
}

static int collision_state_is_lookup_failure(
    ninlil_model_transaction_collision_state_t state)
{
    return state == NINLIL_MODEL_TRANSACTION_LOOKUP_BUSY
        || state == NINLIL_MODEL_TRANSACTION_LOOKUP_IO_ERROR
        || state == NINLIL_MODEL_TRANSACTION_LOOKUP_CORRUPT;
}

static ninlil_status_t lookup_failure_status(
    ninlil_model_transaction_collision_state_t state)
{
    switch (state) {
    case NINLIL_MODEL_TRANSACTION_LOOKUP_BUSY:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_MODEL_TRANSACTION_LOOKUP_IO_ERROR:
        return NINLIL_E_STORAGE;
    case NINLIL_MODEL_TRANSACTION_LOOKUP_CORRUPT:
        return NINLIL_E_STORAGE_CORRUPT;
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

static int draw_shape_is_valid(
    const ninlil_model_transaction_id_draw_t *draw,
    uint32_t ordinal)
{
    if (draw->ordinal != ordinal || !entropy_state_is_known(draw->entropy_state)) {
        return 0;
    }
    if (draw->entropy_state != NINLIL_MODEL_ENTROPY_DRAW_FULL) {
        return draw->collision_state
            == NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
    }
    if (id_is_zero(&draw->candidate)) {
        return draw->collision_state
            == NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
    }
    return draw->collision_state >= NINLIL_MODEL_TRANSACTION_ID_UNIQUE
        && draw->collision_state <= NINLIL_MODEL_TRANSACTION_LOOKUP_CORRUPT;
}

ninlil_status_t ninlil_model_reduce_transaction_id_allocation(
    const ninlil_model_id_allocation_input_t *input,
    ninlil_model_id_allocation_result_t *out_result)
{
    uint32_t index;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (input == NULL || !plan_is_valid(&input->preflight_plan)
        || !payload_is_valid(&input->payload, &input->preflight_plan)
        || !descriptor_contract_is_valid(
            &input->descriptor_contract, input->preflight_plan.family)
        || input->draw_count > NINLIL_MODEL_TRANSACTION_ID_MAX_DRAWS) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    for (index = 0u; index < input->draw_count; ++index) {
        const ninlil_model_transaction_id_draw_t *draw = &input->draws[index];

        if (!draw_shape_is_valid(draw, index + 1u)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        out_result->draws_consumed = index + 1u;
        if (draw->entropy_state != NINLIL_MODEL_ENTROPY_DRAW_FULL
            || id_is_zero(&draw->candidate)
            || draw->collision_state
                == NINLIL_MODEL_TRANSACTION_ID_COLLISION) {
            continue;
        }
        if (collision_state_is_lookup_failure(draw->collision_state)) {
            ninlil_status_t status =
                lookup_failure_status(draw->collision_state);

            if (index + 1u != input->draw_count) {
                (void)memset(out_result, 0, sizeof(*out_result));
                return NINLIL_E_INVALID_ARGUMENT;
            }
            out_result->action = NINLIL_MODEL_ID_ALLOCATION_TERMINAL;
            set_api_error_result(
                &out_result->public_result,
                status,
                &out_result->api_status);
            if (status == NINLIL_E_STORAGE
                || status == NINLIL_E_STORAGE_CORRUPT) {
                out_result->health_degraded = 1u;
                out_result->health_add_cause = NINLIL_REASON_STORAGE_IO;
            }
            return NINLIL_OK;
        }
        if (draw->collision_state != NINLIL_MODEL_TRANSACTION_ID_UNIQUE
            || index + 1u != input->draw_count) {
            (void)memset(out_result, 0, sizeof(*out_result));
            return NINLIL_E_INVALID_ARGUMENT;
        }
        out_result->action =
            NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT;
        out_result->api_status = NINLIL_OK;
        out_result->health_clear_entropy_transaction_id = 1u;
        build_write_set(input, &draw->candidate, &out_result->write_set);
        return NINLIL_OK;
    }

    if (input->draw_count < NINLIL_MODEL_TRANSACTION_ID_MAX_DRAWS) {
        out_result->action = NINLIL_MODEL_ID_ALLOCATION_NEEDS_DRAW;
        out_result->api_status = NINLIL_OK;
        out_result->next_draw_ordinal = input->draw_count + 1u;
        return NINLIL_OK;
    }

    out_result->action = NINLIL_MODEL_ID_ALLOCATION_TERMINAL;
    set_api_error_result(
        &out_result->public_result,
        NINLIL_E_ENTROPY,
        &out_result->api_status);
    out_result->health_degraded = 1u;
    out_result->health_add_cause = NINLIL_REASON_OUTCOME_UNKNOWN;
    return NINLIL_OK;
}

static uint32_t expected_record_mask(ninlil_family_t family)
{
    uint32_t mask = common_record_mask();

    if (family == NINLIL_FAMILY_EVENT_FACT
        || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return mask | NINLIL_MODEL_ADMISSION_WRITE_EVENT_MAPPING
            | NINLIL_MODEL_ADMISSION_WRITE_GRANT
            | NINLIL_MODEL_ADMISSION_WRITE_EVENT_MANAGEMENT;
    }
    return mask | NINLIL_MODEL_ADMISSION_WRITE_COMMAND_CANCEL;
}

static int mapping_scope_matches_plan(
    const ninlil_model_mapping_scope_t *scope,
    const ninlil_model_admission_plan_t *plan)
{
    return id_equal(
               &scope->source_application_instance_id,
               &plan->source.application_instance_id)
        && text_id_equal(&scope->namespace_id, &plan->service.namespace_id)
        && text_id_equal(&scope->service_id, &plan->service.service_id);
}

static int assurance_is_valid(
    const ninlil_admission_assurance_t *assurance,
    ninlil_family_t family)
{
    return assurance->abi_version == NINLIL_ABI_VERSION
        && assurance->struct_size >= sizeof(*assurance)
        && assurance->assurance_profile
            == NINLIL_ASSURANCE_FOUNDATION_M1A_LOCAL
        && assurance->submission_validated == 1u
        && assurance->target_roster_fixed == 1u
        && assurance->descriptor_snapshot_fixed == 1u
        && assurance->local_journal_committed == 1u
        && assurance->local_capacity_reserved == 1u
        && assurance->idempotency_mapping_committed == 1u
        && assurance->origin_grant_snapshot_committed
            == ((family == NINLIL_FAMILY_EVENT_FACT
                    || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
                    || family == NINLIL_FAMILY_MEASUREMENT_RESERVED)
                ? 1u
                : 0u)
        && assurance->remote_capacity_reserved == 0u
        && assurance->route_feasibility_verified == 0u
        && assurance->receive_window_reserved == 0u
        && assurance->bearer_capacity_reserved == 0u
        && assurance->airtime_reserved == 0u
        && assurance->compliance_permit_issued == 0u
        && assurance->reserved_zero == 0u;
}

static int request_amount(
    const ninlil_model_capacity_batch_request_t *requests,
    uint32_t request_count,
    ninlil_resource_kind_t kind,
    uint64_t *out_amount)
{
    uint32_t index;
    uint32_t found = 0u;

    *out_amount = 0u;
    for (index = 0u; index < request_count; ++index) {
        if (requests[index].kind == kind) {
            *out_amount = requests[index].amount;
            found += 1u;
        }
    }
    return found <= 1u;
}

static int resource_plan_matches_admission(
    const ninlil_model_admission_plan_t *plan)
{
    const ninlil_model_resource_reservation_plan_t *resources =
        &plan->resources;
    uint64_t reserve_transaction;
    uint64_t reserve_target;
    uint64_t reserve_outbox;
    uint64_t reserve_event_count;
    uint64_t reserve_event_bytes;
    uint64_t reserve_evidence;
    uint64_t commit_transaction;
    uint64_t commit_target;
    uint64_t commit_outbox;
    uint64_t commit_event_count;
    uint64_t commit_event_bytes;
    uint64_t commit_evidence;
    uint64_t evidence_total =
        (uint64_t)plan->registered_service.max_evidence_per_target + 1u;
    uint32_t index;
    ninlil_model_capacity_batch_input_t transition;
    ninlil_model_capacity_batch_result_t transition_result;

    if (resources->reserve_request_count > NINLIL_MODEL_RESOURCE_KIND_COUNT
        || resources->commit_request_count > NINLIL_MODEL_RESOURCE_KIND_COUNT) {
        return 0;
    }
    for (index = 0u; index < resources->reserve_request_count; ++index) {
        if (resources->reserve_requests[index].amount == 0u
            || resources->reserve_requests[index].used_release != 0u
            || resources->reserve_requests[index].reserved_release != 0u
            || resources->reserve_requests[index].reopens_blocked_class != 0u
            || (index > 0u
                && resources->reserve_requests[index - 1u].kind
                    >= resources->reserve_requests[index].kind)) {
            return 0;
        }
    }
    for (index = 0u; index < resources->commit_request_count; ++index) {
        if (resources->commit_requests[index].amount == 0u
            || resources->commit_requests[index].used_release != 0u
            || resources->commit_requests[index].reserved_release != 0u
            || resources->commit_requests[index].reopens_blocked_class != 0u
            || (index > 0u
                && resources->commit_requests[index - 1u].kind
                    >= resources->commit_requests[index].kind)) {
            return 0;
        }
    }

    if (!request_amount(
            resources->reserve_requests,
            resources->reserve_request_count,
            NINLIL_RESOURCE_TRANSACTION,
            &reserve_transaction)
        || !request_amount(
            resources->reserve_requests,
            resources->reserve_request_count,
            NINLIL_RESOURCE_TARGET,
            &reserve_target)
        || !request_amount(
            resources->reserve_requests,
            resources->reserve_request_count,
            NINLIL_RESOURCE_OUTBOX_BYTES,
            &reserve_outbox)
        || !request_amount(
            resources->reserve_requests,
            resources->reserve_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
            &reserve_event_count)
        || !request_amount(
            resources->reserve_requests,
            resources->reserve_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
            &reserve_event_bytes)
        || !request_amount(
            resources->reserve_requests,
            resources->reserve_request_count,
            NINLIL_RESOURCE_EVIDENCE,
            &reserve_evidence)
        || !request_amount(
            resources->commit_requests,
            resources->commit_request_count,
            NINLIL_RESOURCE_TRANSACTION,
            &commit_transaction)
        || !request_amount(
            resources->commit_requests,
            resources->commit_request_count,
            NINLIL_RESOURCE_TARGET,
            &commit_target)
        || !request_amount(
            resources->commit_requests,
            resources->commit_request_count,
            NINLIL_RESOURCE_OUTBOX_BYTES,
            &commit_outbox)
        || !request_amount(
            resources->commit_requests,
            resources->commit_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_COUNT,
            &commit_event_count)
        || !request_amount(
            resources->commit_requests,
            resources->commit_request_count,
            NINLIL_RESOURCE_EVENT_SPOOL_BYTES,
            &commit_event_bytes)
        || !request_amount(
            resources->commit_requests,
            resources->commit_request_count,
            NINLIL_RESOURCE_EVIDENCE,
            &commit_evidence)
        || reserve_transaction != 1u
        || reserve_target != 1u
        || reserve_evidence != evidence_total
        || commit_transaction != 1u
        || commit_target != 1u
        || commit_evidence != 1u) {
        return 0;
    }

    (void)memset(&transition, 0, sizeof(transition));
    transition.current = resources->reserved_ledger;
    transition.operation = NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED;
    transition.request_count = resources->commit_request_count;
    for (index = 0u; index < transition.request_count; ++index) {
        transition.requests[index] = resources->commit_requests[index];
    }
    if (ninlil_model_capacity_batch_transition(
            &transition, &transition_result) != NINLIL_OK
        || transition_result.action
            != NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED
        || !ledger_equal(
            &transition_result.next, &resources->committed_ledger)) {
        return 0;
    }

    if (plan->family == NINLIL_FAMILY_EVENT_FACT
        || plan->family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || plan->family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return resources->reserve_request_count == 5u
            && resources->commit_request_count
                == (plan->payload_length == 0u ? 4u : 5u)
            && reserve_outbox == 0u
            && commit_outbox == 0u
            && reserve_event_count == 1u
            && commit_event_count == 1u
            && reserve_event_bytes
                == (uint64_t)plan->payload_length
                    + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES
            && commit_event_bytes == plan->payload_length;
    }
    return resources->reserve_request_count
            == (plan->payload_length == 0u ? 3u : 4u)
        && resources->commit_request_count
            == (plan->payload_length == 0u ? 3u : 4u)
        && reserve_outbox == plan->payload_length
        && commit_outbox == plan->payload_length
        && reserve_event_count == 0u
        && commit_event_count == 0u
        && reserve_event_bytes == 0u
        && commit_event_bytes == 0u;
}

static int initial_snapshot_and_manifest_are_valid(
    const ninlil_model_admission_write_set_t *write_set)
{
    const ninlil_model_initial_target_spool_snapshot_t *snapshot =
        &write_set->initial_family_snapshot;
    const ninlil_model_admission_reservation_manifest_t *manifest =
        &write_set->reservation_manifest;

    if (snapshot->attempts_in_cycle != 0u
        || snapshot->cumulative_attempts != 0u
        || snapshot->reason != NINLIL_REASON_NONE
        || snapshot->highest_evidence != NINLIL_EVIDENCE_NONE
        || snapshot->latest_evidence != NINLIL_EVIDENCE_NONE
        || snapshot->effect_certainty != NINLIL_EFFECT_CERTAINTY_NONE
        || snapshot->dispatch_fenced != 0u
        || !id_is_zero(&snapshot->current_attempt_id)
        || snapshot->timer_present != 0u
        || snapshot->cancel_state != 0u
        || snapshot->delivery_possible != 0u
        || snapshot->event_park_cause != NINLIL_EVENT_PARK_CAUSE_NONE
        || snapshot->evidence_summary_latest != NINLIL_EVIDENCE_NONE
        || snapshot->evidence_summary_late != 0u
        || snapshot->evidence_raw_used != 0u
        || manifest->evidence_summary_used != 1u
        || manifest->evidence_raw_reserved
            != write_set->plan.registered_service.max_evidence_per_target) {
        return 0;
    }
    if (write_set->plan.family == NINLIL_FAMILY_EVENT_FACT
        || write_set->plan.family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || write_set->plan.family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        return snapshot->family_state == NINLIL_MODEL_INITIAL_EVENT_HELD_READY
            && snapshot->deadline_verdict
                == NINLIL_DEADLINE_NOT_APPLICABLE
            && snapshot->retry_cycle_id == 1u
            && snapshot->spool_revision == 1u
            && manifest->command_cancel_slots == 0u
            && manifest->command_cancel_outbox_metadata_slots == 0u
            && manifest->event_resume_slots
                == NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS
            && manifest->event_resume_slot_bytes == 256u
            && manifest->event_discard_slots == 1u
            && manifest->event_discard_slot_bytes == 512u
            && manifest->event_management_total_bytes
                == NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES;
    }
    return snapshot->family_state
            == NINLIL_MODEL_INITIAL_DESIRED_TARGET_READY
        && snapshot->deadline_verdict == NINLIL_DEADLINE_PENDING
        && snapshot->retry_cycle_id == 0u
        && snapshot->spool_revision == 0u
        && manifest->command_cancel_slots == 1u
        && manifest->command_cancel_outbox_metadata_slots == 1u
        && manifest->event_resume_slots == 0u
        && manifest->event_resume_slot_bytes == 0u
        && manifest->event_discard_slots == 0u
        && manifest->event_discard_slot_bytes == 0u
        && manifest->event_management_total_bytes == 0u;
}

static int write_set_is_valid(
    const ninlil_model_admission_write_set_t *write_set)
{
    const ninlil_model_admission_plan_t *plan = &write_set->plan;

    if (write_set->durability != NINLIL_DURABILITY_FULL
        || !plan_is_valid(plan)
        || id_is_zero(&write_set->transaction_id)
        || write_set->record_mask != expected_record_mask(plan->family)
        || !payload_is_valid(&write_set->payload, plan)
        || !descriptor_contract_is_valid(
            &write_set->descriptor.contract, plan->family)
        || !submission_service_equal(
            &write_set->descriptor.registered_service,
            &plan->registered_service)
        || !mapping_scope_matches_plan(&write_set->caller_mapping.scope, plan)
        || !id_equal(
            &write_set->caller_mapping.transaction_id,
            &write_set->transaction_id)
        || !digest_equal(
            &write_set->caller_mapping.canonical_submission_digest,
            &plan->canonical_submission_digest)
        || !key_equal(
            &write_set->caller_mapping.caller_key, &plan->idempotency_key)
        || write_set->initial_transaction_state != NINLIL_TXN_READY
        || write_set->initial_outcome != NINLIL_OUTCOME_NONE
        || write_set->initial_reason != NINLIL_REASON_NONE
        || write_set->transaction_record_revision != 1u
        || !quota_equal(&write_set->committed_quota, &plan->quota)
        || !ledger_equal(
            &write_set->committed_resource_ledger,
            &plan->resources.committed_ledger)
        || !initial_snapshot_and_manifest_are_valid(write_set)
        || !assurance_is_valid(&write_set->assurance, plan->family)) {
        return 0;
    }
    if (plan->family == NINLIL_FAMILY_EVENT_FACT
        || plan->family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || plan->family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        int event_id_ok = id_equal(
            &write_set->event_mapping.event_id, &plan->event_id);
        if (plan->family != NINLIL_FAMILY_EVENT_FACT) {
            event_id_ok = id_is_zero(&write_set->event_mapping.event_id)
                && id_is_zero(&plan->event_id);
        }
        return write_set->event_mapping_present == 1u
            && write_set->grant_snapshot_present == 1u
            && write_set->initial_queue_kind
                == NINLIL_MODEL_INITIAL_EVENT_SPOOL
            && write_set->event_spool_revision == 1u
            && write_set->command_cancel_reservation_present == 0u
            && write_set->event_management_reservation_present == 1u
            && mapping_scope_matches_plan(
                &write_set->event_mapping.scope, plan)
            && event_id_ok
            && id_equal(
                &write_set->event_mapping.transaction_id,
                &write_set->transaction_id)
            && digest_equal(
                &write_set->event_mapping.canonical_submission_digest,
                &plan->canonical_submission_digest)
            && key_equal(
                &write_set->event_mapping.caller_key,
                &plan->idempotency_key)
            && grant_equal(
                &write_set->grant_snapshot.decision, &plan->grant)
            && party_equal(&write_set->grant_snapshot.source, &plan->source)
            && service_identity_equal(
                &write_set->grant_snapshot.service, &plan->service)
            && target_equal(&write_set->grant_snapshot.target, &plan->target)
            && (plan->family == NINLIL_FAMILY_EVENT_FACT
                ? id_equal(
                    &write_set->grant_snapshot.event_id, &plan->event_id)
                : id_is_zero(&write_set->grant_snapshot.event_id)
                    && id_is_zero(&plan->event_id))
            && digest_equal(
                &write_set->grant_snapshot.content_digest,
                &plan->content_digest)
            && write_set->grant_snapshot.required_evidence
                == plan->required_evidence
            && write_set->grant_snapshot.payload_length
                == plan->payload_length;
    }
    return write_set->event_mapping_present == 0u
        && write_set->grant_snapshot_present == 0u
        && write_set->initial_queue_kind
            == NINLIL_MODEL_INITIAL_COMMAND_OUTBOX
        && write_set->event_spool_revision == 0u
        && write_set->command_cancel_reservation_present == 1u
        && write_set->event_management_reservation_present == 0u
        && event_mapping_is_zero(&write_set->event_mapping)
        && bound_grant_is_zero(&write_set->grant_snapshot);
}

static ninlil_model_admission_recovery_probe_t make_recovery_probe(
    const ninlil_model_admission_write_set_t *write_set)
{
    ninlil_model_admission_recovery_probe_t probe;

    (void)memset(&probe, 0, sizeof(probe));
    probe.transaction_id = write_set->transaction_id;
    probe.mapping_scope = write_set->caller_mapping.scope;
    probe.caller_key = write_set->caller_mapping.caller_key;
    probe.canonical_submission_digest =
        write_set->caller_mapping.canonical_submission_digest;
    if (write_set->plan.family == NINLIL_FAMILY_EVENT_FACT) {
        probe.event_id_present = 1u;
        probe.event_id = write_set->plan.event_id;
    }
    return probe;
}

ninlil_status_t ninlil_model_reduce_admission_commit(
    const ninlil_model_admission_commit_input_t *input,
    ninlil_model_admission_commit_result_t *out_result)
{
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (input == NULL || !write_set_is_valid(&input->write_set)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    switch (input->commit_state) {
    case NINLIL_MODEL_ADMISSION_COMMIT_OK:
        out_result->api_status = NINLIL_OK;
        initialize_public_result(&out_result->public_result, 1);
        out_result->public_result.kind = NINLIL_SUBMISSION_ADMITTED_READY;
        out_result->public_result.reason = NINLIL_REASON_NONE;
        out_result->public_result.retry_guidance = NINLIL_RETRY_NEVER;
        out_result->public_result.transaction_id = input->write_set.transaction_id;
        out_result->public_result.canonical_submission_digest =
            input->write_set.plan.canonical_submission_digest;
        out_result->public_result.assurance = input->write_set.assurance;
        out_result->ownership = NINLIL_MODEL_ADMISSION_OWNERSHIP_ESTABLISHED;
        out_result->durable_write_set_present = 1u;
        out_result->durable_write_set = input->write_set;
        return NINLIL_OK;
    case NINLIL_MODEL_ADMISSION_COMMIT_NO_SPACE:
        set_rejected_no_space(
            &out_result->public_result, &out_result->api_status);
        return NINLIL_OK;
    case NINLIL_MODEL_ADMISSION_COMMIT_BUSY:
        set_api_error_result(
            &out_result->public_result,
            NINLIL_E_WOULD_BLOCK,
            &out_result->api_status);
        return NINLIL_OK;
    case NINLIL_MODEL_ADMISSION_COMMIT_IO_ERROR:
        set_api_error_result(
            &out_result->public_result,
            NINLIL_E_STORAGE,
            &out_result->api_status);
        out_result->health_add_cause = NINLIL_REASON_STORAGE_IO;
        return NINLIL_OK;
    case NINLIL_MODEL_ADMISSION_COMMIT_CORRUPT:
        set_api_error_result(
            &out_result->public_result,
            NINLIL_E_STORAGE_CORRUPT,
            &out_result->api_status);
        out_result->health_add_cause = NINLIL_REASON_STORAGE_IO;
        return NINLIL_OK;
    case NINLIL_MODEL_ADMISSION_COMMIT_UNKNOWN:
        set_api_error_result(
            &out_result->public_result,
            NINLIL_E_STORAGE_COMMIT_UNKNOWN,
            &out_result->api_status);
        out_result->ownership = NINLIL_MODEL_ADMISSION_OWNERSHIP_UNRESOLVED;
        out_result->recovery_required = 1u;
        out_result->recovery_action =
            NINLIL_MODEL_ADMISSION_RECOVERY_FENCE_AND_REOPEN_JOURNAL;
        out_result->journal_operation_id = input->write_set.transaction_id;
        out_result->health_add_cause =
            NINLIL_REASON_STORAGE_COMMIT_UNKNOWN;
        out_result->recovery_probe_present = 1u;
        out_result->recovery_probe = make_recovery_probe(&input->write_set);
        out_result->staged_write_set_present = 1u;
        out_result->staged_write_set_for_reconcile = input->write_set;
        return NINLIL_OK;
    default:
        (void)memset(out_result, 0, sizeof(*out_result));
        return NINLIL_E_INVALID_ARGUMENT;
    }
}
