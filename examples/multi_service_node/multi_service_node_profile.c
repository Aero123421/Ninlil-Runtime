#include "multi_service_node_profile.h"

#include <limits.h>
#include <string.h>

static const uint8_t g_namespace_id[] =
    "org.ninlil.example.multi-service-node";
static const uint8_t g_display_service[] = "display.command";
static const uint8_t g_access_service[] = "access.event";
static const uint8_t g_temperature_service[] = "temperature.telemetry";
static const uint8_t g_query_service[] = "temperature.query";
static const uint8_t g_display_schema[] = "display-command-v1";
static const uint8_t g_access_schema[] = "access-event-v1";
static const uint8_t g_temperature_schema[] = "temperature-telemetry-v1";
static const uint8_t g_query_schema[] = "temperature-query-v1";

static const uint8_t *const g_service_ids[
    NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT] = {
    g_display_service,
    g_access_service,
    g_temperature_service,
    g_query_service
};
static const uint32_t g_service_id_lengths[
    NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT] = {
    (uint32_t)(sizeof(g_display_service) - 1u),
    (uint32_t)(sizeof(g_access_service) - 1u),
    (uint32_t)(sizeof(g_temperature_service) - 1u),
    (uint32_t)(sizeof(g_query_service) - 1u)
};
static const uint8_t *const g_schema_ids[
    NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT] = {
    g_display_schema,
    g_access_schema,
    g_temperature_schema,
    g_query_schema
};
static const uint32_t g_schema_id_lengths[
    NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT] = {
    (uint32_t)(sizeof(g_display_schema) - 1u),
    (uint32_t)(sizeof(g_access_schema) - 1u),
    (uint32_t)(sizeof(g_temperature_schema) - 1u),
    (uint32_t)(sizeof(g_query_schema) - 1u)
};
static const ninlil_family_t g_families[
    NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT] = {
    NINLIL_FAMILY_DESIRED_STATE,
    NINLIL_FAMILY_EVENT_FACT,
    NINLIL_FAMILY_EVENT_FACT,
    NINLIL_FAMILY_DESIRED_STATE
};

static void set_header(
    uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void set_id(ninlil_id128_t *id, uint8_t seed)
{
    uint32_t index;
    for (index = 0u; index < NINLIL_ID_BYTES; ++index) {
        id->bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static void set_descriptor_digest(
    ninlil_digest256_t *digest, uint8_t seed)
{
    uint32_t index;
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->reserved_zero = 0u;
    for (index = 0u; index < NINLIL_SHA256_BYTES; ++index) {
        digest->bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static int checked_increment(uint64_t *value)
{
    if (value == NULL || *value == UINT64_MAX) {
        return 0;
    }
    *value += 1u;
    return 1;
}

static int state_shape_valid(const ninlil_multi_service_node_state_t *state)
{
    return state != NULL && state->abi_version == NINLIL_ABI_VERSION
        && state->struct_size == (uint16_t)sizeof(*state)
        && state->reserved_zero == 0u
        && state->response_phase
            <= NINLIL_MULTI_SERVICE_NODE_RESPONSE_IN_FLIGHT
        && ((state->response_phase
                    == NINLIL_MULTI_SERVICE_NODE_RESPONSE_IDLE
                && state->pending_query_correlation == 0u)
            || (state->response_phase
                    != NINLIL_MULTI_SERVICE_NODE_RESPONSE_IDLE
                && state->pending_query_correlation != 0u));
}

static int descriptor_identity_valid(
    const ninlil_service_descriptor_t *descriptor, uint32_t index)
{
    uint8_t digest_seed = (uint8_t)(0x31u + (uint8_t)(index * 0x10u));
    uint32_t byte_index;
    uint32_t application_id_nonzero = 0u;
    uint32_t expected_evidence_mask;

    if (descriptor == NULL
        || descriptor->abi_version != NINLIL_ABI_VERSION
        || descriptor->struct_size != (uint16_t)sizeof(*descriptor)
        || descriptor->namespace_id.length != sizeof(g_namespace_id) - 1u
        || descriptor->namespace_id.data == NULL
        || memcmp(
               descriptor->namespace_id.data,
               g_namespace_id,
               sizeof(g_namespace_id) - 1u)
            != 0
        || descriptor->service_id.length != g_service_id_lengths[index]
        || descriptor->service_id.data == NULL
        || memcmp(
               descriptor->service_id.data,
               g_service_ids[index],
               g_service_id_lengths[index])
            != 0
        || descriptor->schema_id.length != g_schema_id_lengths[index]
        || descriptor->schema_id.data == NULL
        || memcmp(
               descriptor->schema_id.data,
               g_schema_ids[index],
               g_schema_id_lengths[index])
            != 0
        || descriptor->descriptor_revision != 1u
        || descriptor->descriptor_digest.algorithm != NINLIL_DIGEST_SHA256
        || descriptor->descriptor_digest.reserved_zero != 0u
        || descriptor->schema_major != 1u
        || descriptor->schema_minor_min != 0u
        || descriptor->schema_minor_max != 0u
        || descriptor->reserved_zero_u16 != 0u
        || descriptor->family != g_families[index]
        || descriptor->apply_contract != NINLIL_APPLY_APPLICATION_DEDUP
        || descriptor->custody_policy
            != NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE
        || descriptor->logical_payload_limit != 1024u
        || descriptor->target_limit != 1u
        || descriptor->inflight_limit != 8u
        || descriptor->max_attempts_per_target_per_cycle != 8u
        || descriptor->admission_window_ms != 10000u
        || descriptor->max_admissions_per_window != 20u
        || descriptor->max_payload_bytes_per_window != 20480u
        || descriptor->attempt_receipt_timeout_ms != 1000u
        || descriptor->retry_backoff_ms != 100u
        || descriptor->application_completion_timeout_ms != 60000u
        || descriptor->required_dedup_window_ms != 60000u
        || descriptor->reserved_zero_u32 != 0u) {
        return 0;
    }
    if (descriptor->family == NINLIL_FAMILY_DESIRED_STATE) {
        expected_evidence_mask =
            NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
            | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
            | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
            | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
        if (descriptor->direction != NINLIL_DIRECTION_DOWNLINK
            || descriptor->admission_authority
                != NINLIL_AUTHORITY_CONTROLLER_ONLY
            || descriptor->supported_evidence_mask
                != expected_evidence_mask
            || descriptor->minimum_deadline_ms != 60000u
            || descriptor->maximum_deadline_ms != 60000u
            || descriptor->maximum_evidence_grace_ms != 5000u) {
            return 0;
        }
    } else {
        expected_evidence_mask =
            NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
            | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
        if (descriptor->direction != NINLIL_DIRECTION_UPLINK
            || descriptor->admission_authority
                != NINLIL_AUTHORITY_ORIGIN_WITH_GRANT
            || descriptor->supported_evidence_mask
                != expected_evidence_mask
            || descriptor->minimum_deadline_ms != NINLIL_NO_DEADLINE
            || descriptor->maximum_deadline_ms != NINLIL_NO_DEADLINE
            || descriptor->maximum_evidence_grace_ms != 0u) {
            return 0;
        }
    }
    for (byte_index = 0u;
         byte_index < NINLIL_SHA256_BYTES;
         ++byte_index) {
        if (descriptor->descriptor_digest.bytes[byte_index]
            != (uint8_t)(digest_seed + (uint8_t)byte_index)) {
            return 0;
        }
    }
    for (byte_index = 0u; byte_index < NINLIL_ID_BYTES; ++byte_index) {
        application_id_nonzero |=
            (uint32_t)descriptor->local_application_instance_id
                .bytes[byte_index];
    }
    return application_id_nonzero != 0u;
}

ninlil_status_t ninlil_multi_service_node_profile_init(
    ninlil_multi_service_node_profile_t *out_profile,
    uint8_t application_instance_seed)
{
    uint32_t index;

    if (out_profile == NULL
        || application_instance_seed
            > (uint8_t)(UINT8_MAX
                - (NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT - 1u))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_profile, 0, sizeof(*out_profile));
    set_header(
        &out_profile->abi_version,
        &out_profile->struct_size,
        sizeof(*out_profile));
    set_header(
        &out_profile->manifest.abi_version,
        &out_profile->manifest.struct_size,
        sizeof(out_profile->manifest));
    out_profile->manifest.runtime_role_constraint =
        NINLIL_MULTI_SERVICE_NODE_ROLE_NEUTRAL;
    out_profile->manifest.service_count =
        NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT;
    out_profile->manifest.service_mask =
        NINLIL_MULTI_SERVICE_NODE_ALL_SERVICES_MASK;
    out_profile->manifest.receive_service_mask =
        NINLIL_MULTI_SERVICE_NODE_RECEIVE_MASK;
    out_profile->manifest.originate_service_mask =
        NINLIL_MULTI_SERVICE_NODE_ORIGINATE_MASK;
    out_profile->manifest.response_service_index =
        NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_TELEMETRY;

    for (index = 0u;
         index < NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT;
         ++index) {
        ninlil_service_descriptor_t *descriptor =
            &out_profile->services[index];

        set_header(
            &descriptor->abi_version,
            &descriptor->struct_size,
            sizeof(*descriptor));
        descriptor->namespace_id.data = g_namespace_id;
        descriptor->namespace_id.length =
            (uint32_t)(sizeof(g_namespace_id) - 1u);
        descriptor->service_id.data = g_service_ids[index];
        descriptor->service_id.length = g_service_id_lengths[index];
        descriptor->schema_id.data = g_schema_ids[index];
        descriptor->schema_id.length = g_schema_id_lengths[index];
        descriptor->descriptor_revision = 1u;
        set_descriptor_digest(
            &descriptor->descriptor_digest,
            (uint8_t)(0x31u + (uint8_t)(index * 0x10u)));
        set_id(
            &descriptor->local_application_instance_id,
            (uint8_t)(application_instance_seed + (uint8_t)index));
        descriptor->schema_major = 1u;
        descriptor->family = g_families[index];
        descriptor->apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
        descriptor->custody_policy =
            NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
        descriptor->logical_payload_limit = 1024u;
        descriptor->target_limit = 1u;
        descriptor->inflight_limit = 8u;
        descriptor->max_attempts_per_target_per_cycle = 8u;
        descriptor->admission_window_ms = 10000u;
        descriptor->max_admissions_per_window = 20u;
        descriptor->max_payload_bytes_per_window = 20480u;
        descriptor->attempt_receipt_timeout_ms = 1000u;
        descriptor->retry_backoff_ms = 100u;
        descriptor->application_completion_timeout_ms = 60000u;
        descriptor->required_dedup_window_ms = 60000u;

        if (descriptor->family == NINLIL_FAMILY_DESIRED_STATE) {
            descriptor->direction = NINLIL_DIRECTION_DOWNLINK;
            descriptor->admission_authority =
                NINLIL_AUTHORITY_CONTROLLER_ONLY;
            descriptor->supported_evidence_mask =
                NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
                | NINLIL_EVIDENCE_MASK(
                    NINLIL_EVIDENCE_DURABLY_RECORDED)
                | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
                | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
            descriptor->minimum_deadline_ms = 60000u;
            descriptor->maximum_deadline_ms = 60000u;
            descriptor->maximum_evidence_grace_ms = 5000u;
        } else {
            descriptor->direction = NINLIL_DIRECTION_UPLINK;
            descriptor->admission_authority =
                NINLIL_AUTHORITY_ORIGIN_WITH_GRANT;
            descriptor->supported_evidence_mask =
                NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
                | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
            descriptor->minimum_deadline_ms = NINLIL_NO_DEADLINE;
            descriptor->maximum_deadline_ms = NINLIL_NO_DEADLINE;
            descriptor->maximum_evidence_grace_ms = 0u;
        }
    }
    return ninlil_multi_service_node_profile_validate(out_profile);
}

ninlil_status_t ninlil_multi_service_node_profile_validate(
    const ninlil_multi_service_node_profile_t *profile)
{
    uint32_t index;

    if (profile == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (profile->abi_version != NINLIL_ABI_VERSION
        || profile->struct_size != (uint16_t)sizeof(*profile)
        || profile->manifest.abi_version != NINLIL_ABI_VERSION
        || profile->manifest.struct_size
            != (uint16_t)sizeof(profile->manifest)
        || profile->manifest.runtime_role_constraint
            != NINLIL_MULTI_SERVICE_NODE_ROLE_NEUTRAL
        || profile->manifest.service_count
            != NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT
        || profile->manifest.service_mask
            != NINLIL_MULTI_SERVICE_NODE_ALL_SERVICES_MASK
        || profile->manifest.receive_service_mask
            != NINLIL_MULTI_SERVICE_NODE_RECEIVE_MASK
        || profile->manifest.originate_service_mask
            != NINLIL_MULTI_SERVICE_NODE_ORIGINATE_MASK
        || profile->manifest.response_service_index
            != NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_TELEMETRY
        || profile->manifest.reserved_zero != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    for (index = 0u;
         index < NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT;
         ++index) {
        if (!descriptor_identity_valid(&profile->services[index], index)) {
            return NINLIL_E_INVALID_STATE;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_multi_service_node_state_init(
    ninlil_multi_service_node_state_t *out_state)
{
    if (out_state == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    set_header(
        &out_state->abi_version,
        &out_state->struct_size,
        sizeof(*out_state));
    out_state->response_phase = NINLIL_MULTI_SERVICE_NODE_RESPONSE_IDLE;
    return NINLIL_OK;
}

ninlil_status_t ninlil_multi_service_node_note_originated(
    ninlil_multi_service_node_state_t *state,
    uint32_t service_index)
{
    uint64_t *counter;

    if (!state_shape_valid(state)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (service_index == NINLIL_MULTI_SERVICE_NODE_ACCESS_EVENT) {
        counter = &state->access_events_originated;
    } else if (
        service_index
        == NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_TELEMETRY) {
        counter = &state->temperature_periodic_originated;
    } else {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return checked_increment(counter) ? NINLIL_OK
                                      : NINLIL_E_CAPACITY_EXHAUSTED;
}

ninlil_status_t ninlil_multi_service_node_note_delivery(
    ninlil_multi_service_node_state_t *state,
    uint32_t service_index,
    uint64_t query_correlation)
{
    if (!state_shape_valid(state)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (service_index == NINLIL_MULTI_SERVICE_NODE_DISPLAY_COMMAND) {
        return checked_increment(&state->display_commands_received)
            ? NINLIL_OK
            : NINLIL_E_CAPACITY_EXHAUSTED;
    }
    if (service_index != NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_QUERY
        || query_correlation == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (state->response_phase != NINLIL_MULTI_SERVICE_NODE_RESPONSE_IDLE) {
        return NINLIL_E_INVALID_STATE;
    }
    if (!checked_increment(&state->temperature_queries_received)) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    state->pending_query_correlation = query_correlation;
    state->response_phase = NINLIL_MULTI_SERVICE_NODE_RESPONSE_PENDING;
    return NINLIL_OK;
}

uint32_t ninlil_multi_service_node_temperature_response_pending(
    const ninlil_multi_service_node_state_t *state)
{
    return state_shape_valid(state)
            && state->response_phase
                == NINLIL_MULTI_SERVICE_NODE_RESPONSE_PENDING
        ? 1u
        : 0u;
}

ninlil_status_t ninlil_multi_service_node_temperature_response_begin(
    ninlil_multi_service_node_state_t *state,
    uint64_t *out_query_correlation)
{
    if (!state_shape_valid(state) || out_query_correlation == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (state->response_phase
        != NINLIL_MULTI_SERVICE_NODE_RESPONSE_PENDING) {
        return NINLIL_E_INVALID_STATE;
    }
    *out_query_correlation = state->pending_query_correlation;
    state->response_phase = NINLIL_MULTI_SERVICE_NODE_RESPONSE_IN_FLIGHT;
    return NINLIL_OK;
}

ninlil_status_t ninlil_multi_service_node_temperature_response_finish(
    ninlil_multi_service_node_state_t *state,
    uint32_t admitted)
{
    if (!state_shape_valid(state) || admitted > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (state->response_phase
        != NINLIL_MULTI_SERVICE_NODE_RESPONSE_IN_FLIGHT) {
        return NINLIL_E_INVALID_STATE;
    }
    if (admitted == 0u) {
        state->response_phase = NINLIL_MULTI_SERVICE_NODE_RESPONSE_PENDING;
        return NINLIL_OK;
    }
    if (!checked_increment(&state->temperature_responses_originated)) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    state->pending_query_correlation = 0u;
    state->response_phase = NINLIL_MULTI_SERVICE_NODE_RESPONSE_IDLE;
    return NINLIL_OK;
}

ninlil_status_t ninlil_multi_service_node_acceptance_complete(
    const ninlil_multi_service_node_state_t *state)
{
    if (!state_shape_valid(state)) {
        return NINLIL_E_INVALID_STATE;
    }
    return state->response_phase == NINLIL_MULTI_SERVICE_NODE_RESPONSE_IDLE
            && state->display_commands_received == 1u
            && state->access_events_originated == 1u
            && state->temperature_periodic_originated == 1u
            && state->temperature_queries_received == 1u
            && state->temperature_responses_originated == 1u
        ? NINLIL_OK
        : NINLIL_E_INVALID_STATE;
}
