/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_lab_radio_mapping.h"

#include "nfl1_codec.h"

#include "ninlil/version.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define V1_LAB_RADIO_MAPPER_MAGIC ((uint32_t)0x91c6a35bu)

_Static_assert(
    NINLIL_V1_LAB_RADIO_NFL1_MAX
        >= NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES
            + (3u * NINLIL_V1_LAB_TEXT_MAX)
            + NINLIL_NRA1_APPLICATION_PAYLOAD_MAX,
    "V1 LAB NFL1 capacity must fit the largest compact Application");

static void clear_bytes(void *pointer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    size_t i;

    if (pointer == NULL) {
        return;
    }
    for (i = 0u; i < length; ++i) {
        bytes[i] = 0u;
    }
}

static void mapper_scratch_clear(ninlil_v1_lab_radio_mapper_t *mapper)
{
    if (mapper == NULL) {
        return;
    }
    clear_bytes(&mapper->binding_scratch, sizeof(mapper->binding_scratch));
    clear_bytes(&mapper->nfl1_workspace, sizeof(mapper->nfl1_workspace));
    clear_bytes(&mapper->nfl1_envelope, sizeof(mapper->nfl1_envelope));
    clear_bytes(mapper->nra1_candidate, sizeof(mapper->nra1_candidate));
}

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t i;

    if (bytes == NULL) {
        return 1;
    }
    for (i = 0u; i < length; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any == 0u;
}

static int mapper_valid(const ninlil_v1_lab_radio_mapper_t *mapper)
{
    return mapper != NULL && mapper->magic == V1_LAB_RADIO_MAPPER_MAGIC
        && !bytes_zero(mapper->local_runtime_id, 16u)
        && ninlil_r7_crypto_provider_validate(&mapper->crypto)
            == NINLIL_R7_CRYPTO_OK;
}

static int sample_header_valid(const ninlil_time_sample_t *sample)
{
    return sample != NULL && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size == (uint16_t)sizeof(*sample)
        && sample->trust == NINLIL_CLOCK_TRUSTED
        && sample->reserved_zero == 0u
        && !bytes_zero(sample->clock_epoch_id.bytes, 16u);
}

static int flow_valid(uint8_t flow)
{
    return flow == NINLIL_V1_LAB_FLOW_A_TO_B
        || flow == NINLIL_V1_LAB_FLOW_B_TO_A;
}

static uint8_t opposite_flow(uint8_t flow)
{
    if (flow == NINLIL_V1_LAB_FLOW_A_TO_B) {
        return NINLIL_V1_LAB_FLOW_B_TO_A;
    }
    if (flow == NINLIL_V1_LAB_FLOW_B_TO_A) {
        return NINLIL_V1_LAB_FLOW_A_TO_B;
    }
    return 0u;
}

static const ninlil_v1_lab_endpoint_t *endpoint_for_side(
    const ninlil_v1_lab_binding_t *binding, uint8_t side)
{
    if (binding == NULL) {
        return NULL;
    }
    if (side == NINLIL_V1_LAB_SIDE_A) {
        return &binding->endpoint_a;
    }
    if (side == NINLIL_V1_LAB_SIDE_B) {
        return &binding->endpoint_b;
    }
    return NULL;
}

static int endpoints_for_flow(
    const ninlil_v1_lab_binding_t *binding,
    uint8_t flow,
    const ninlil_v1_lab_endpoint_t **out_source,
    const ninlil_v1_lab_endpoint_t **out_target)
{
    if (binding == NULL || out_source == NULL || out_target == NULL) {
        return 0;
    }
    if (flow == NINLIL_V1_LAB_FLOW_A_TO_B) {
        *out_source = &binding->endpoint_a;
        *out_target = &binding->endpoint_b;
        return 1;
    }
    if (flow == NINLIL_V1_LAB_FLOW_B_TO_A) {
        *out_source = &binding->endpoint_b;
        *out_target = &binding->endpoint_a;
        return 1;
    }
    return 0;
}

static void correlation_clear(ninlil_v1_lab_radio_correlation_t *correlation)
{
    clear_bytes(correlation, sizeof(*correlation));
}

static void clear_pair_correlations(
    ninlil_v1_lab_radio_mapper_t *mapper, uint8_t pair_slot)
{
    uint8_t i;

    for (i = 0u; i < NINLIL_V1_LAB_RADIO_CORRELATION_MAX; ++i) {
        if (mapper->correlations[i].active != 0u
            && mapper->correlations[i].pair_slot == pair_slot) {
            correlation_clear(&mapper->correlations[i]);
        }
    }
}

static ninlil_v1_lab_radio_mapping_status_t sample_pair_now(
    ninlil_v1_lab_radio_mapper_t *mapper,
    uint8_t pair_slot,
    const ninlil_time_sample_t *now)
{
    ninlil_v1_lab_radio_pair_slot_t *pair;
    const ninlil_v1_lab_endpoint_t *local;
    uint8_t i;

    if (!mapper_valid(mapper) || pair_slot >= NINLIL_V1_LAB_RADIO_PAIR_MAX
        || !sample_header_valid(now)) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    pair = &mapper->pairs[pair_slot];
    if (pair->active == 0u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND;
    }
    if (pair->fenced != 0u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_FENCED;
    }
    local = endpoint_for_side(&pair->binding, pair->local_side);
    if (local == NULL) {
        pair->fenced = 1u;
        clear_pair_correlations(mapper, pair_slot);
        return NINLIL_V1_LAB_RADIO_MAPPING_FENCED;
    }
    if (memcmp(
            local->clock_epoch_id,
            now->clock_epoch_id.bytes,
            16u)
            != 0
        || (pair->has_last_now != 0u && now->now_ms < pair->last_now_ms)) {
        pair->fenced = 1u;
        clear_pair_correlations(mapper, pair_slot);
        return NINLIL_V1_LAB_RADIO_MAPPING_FENCED;
    }
    pair->last_now_ms = now->now_ms;
    pair->has_last_now = 1u;

    for (i = 0u; i < NINLIL_V1_LAB_RADIO_CORRELATION_MAX; ++i) {
        ninlil_v1_lab_radio_correlation_t *correlation =
            &mapper->correlations[i];
        if (correlation->active != 0u
            && correlation->pair_slot == pair_slot
            && correlation->receipt_pending == 0u
            && now->now_ms >= correlation->expires_at_ms) {
            correlation_clear(correlation);
        }
    }
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

static int endpoint_matches_source(
    const ninlil_v1_lab_endpoint_t *endpoint,
    const ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    return endpoint != NULL && envelope != NULL
        && memcmp(endpoint->runtime_id, envelope->source_runtime_id.bytes, 16u)
            == 0
        && memcmp(
               endpoint->application_id,
               envelope->source_application_id.bytes,
               16u)
            == 0
        && memcmp(endpoint->device_id, envelope->source_device_id.bytes, 16u)
            == 0
        && memcmp(
               endpoint->installation_id,
               envelope->source_installation_id.bytes,
               16u)
            == 0
        && memcmp(endpoint->site_id, envelope->source_site_id.bytes, 16u) == 0
        && endpoint->binding_epoch == envelope->source_binding_epoch
        && endpoint->membership_epoch == envelope->source_membership_epoch
        && endpoint->identity_flags == envelope->source_flags;
}

static int endpoint_matches_target(
    const ninlil_v1_lab_endpoint_t *endpoint,
    const ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    return endpoint != NULL && envelope != NULL
        && memcmp(endpoint->runtime_id, envelope->target_runtime_id.bytes, 16u)
            == 0
        && memcmp(
               endpoint->application_id,
               envelope->target_application_id.bytes,
               16u)
            == 0
        && memcmp(endpoint->device_id, envelope->target_device_id.bytes, 16u)
            == 0
        && memcmp(
               endpoint->installation_id,
               envelope->target_installation_id.bytes,
               16u)
            == 0
        && memcmp(endpoint->site_id, envelope->target_site_id.bytes, 16u) == 0
        && endpoint->binding_epoch == envelope->target_binding_epoch
        && endpoint->membership_epoch == envelope->target_membership_epoch
        && endpoint->identity_flags == envelope->target_flags;
}

static void envelope_set_source(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->source_runtime_id.bytes, endpoint->runtime_id, 16u);
    (void)memcpy(
        envelope->source_application_id.bytes, endpoint->application_id, 16u);
    (void)memcpy(envelope->source_device_id.bytes, endpoint->device_id, 16u);
    (void)memcpy(
        envelope->source_installation_id.bytes,
        endpoint->installation_id,
        16u);
    (void)memcpy(envelope->source_site_id.bytes, endpoint->site_id, 16u);
    envelope->source_binding_epoch = endpoint->binding_epoch;
    envelope->source_membership_epoch = endpoint->membership_epoch;
    envelope->source_flags = endpoint->identity_flags;
}

static void envelope_set_target(
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    (void)memcpy(envelope->target_runtime_id.bytes, endpoint->runtime_id, 16u);
    (void)memcpy(
        envelope->target_application_id.bytes, endpoint->application_id, 16u);
    (void)memcpy(envelope->target_device_id.bytes, endpoint->device_id, 16u);
    (void)memcpy(
        envelope->target_installation_id.bytes,
        endpoint->installation_id,
        16u);
    (void)memcpy(envelope->target_site_id.bytes, endpoint->site_id, 16u);
    envelope->target_binding_epoch = endpoint->binding_epoch;
    envelope->target_membership_epoch = endpoint->membership_epoch;
    envelope->target_flags = endpoint->identity_flags;
}

static int envelope_service_matches(
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    return row != NULL && envelope != NULL
        && envelope->namespace_id.length == row->namespace_length
        && envelope->service_id.length == row->service_length
        && envelope->schema_id.length == row->schema_length
        && memcmp(
               envelope->namespace_id.bytes,
               row->namespace_id,
               row->namespace_length)
            == 0
        && memcmp(
               envelope->service_id.bytes,
               row->service_id,
               row->service_length)
            == 0
        && memcmp(
               envelope->schema_id.bytes,
               row->schema_id,
               row->schema_length)
            == 0
        && envelope->descriptor_revision == row->descriptor_revision
        && memcmp(
               envelope->descriptor_digest.bytes,
               row->descriptor_digest,
               32u)
            == 0
        && envelope->schema_major == row->schema_major
        && envelope->schema_minor == row->schema_minor
        && envelope->family == row->family
        && envelope->evidence_grace_ms == row->evidence_grace_ms;
}

static int envelope_family_matches(
    const ninlil_v1_lab_binding_t *binding,
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    const ninlil_v1_lab_endpoint_t *controller;

    if (binding == NULL || row == NULL || envelope == NULL) {
        return 0;
    }
    controller = endpoint_for_side(binding, binding->controller_side);
    if (controller == NULL) {
        return 0;
    }
    if (row->family == NINLIL_FAMILY_EVENT_FACT) {
        return !bytes_zero(envelope->event_id.bytes, 16u)
            && envelope->generation == 0u
            && bytes_zero(envelope->deadline_clock_epoch_id.bytes, 16u)
            && envelope->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE;
    }
    if (row->family == NINLIL_FAMILY_DESIRED_STATE) {
        return bytes_zero(envelope->event_id.bytes, 16u)
            && envelope->generation != 0u
            && memcmp(
                   envelope->deadline_clock_epoch_id.bytes,
                   controller->clock_epoch_id,
                   16u)
                == 0
            && envelope->absolute_effect_deadline_ms != 0u
            && envelope->absolute_effect_deadline_ms < NINLIL_NO_DEADLINE;
    }
    return 0;
}

static int envelope_static_matches(
    const ninlil_v1_lab_binding_t *binding,
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    const ninlil_v1_lab_endpoint_t *forward_source;
    const ninlil_v1_lab_endpoint_t *forward_target;
    const ninlil_v1_lab_endpoint_t *message_source;
    const ninlil_v1_lab_endpoint_t *message_target;
    const ninlil_v1_lab_endpoint_t *controller;

    if (binding == NULL || row == NULL || envelope == NULL
        || !endpoints_for_flow(
            binding, row->flow, &forward_source, &forward_target)) {
        return 0;
    }
    if (envelope->message_kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
        message_source = forward_source;
        message_target = forward_target;
    } else if (envelope->message_kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        message_source = forward_target;
        message_target = forward_source;
    } else {
        return 0;
    }
    controller = endpoint_for_side(binding, binding->controller_side);
    return controller != NULL
        && endpoint_matches_source(message_source, envelope)
        && endpoint_matches_target(message_target, envelope)
        && envelope_service_matches(row, envelope)
        && envelope_family_matches(binding, row, envelope)
        && memcmp(
               envelope->authority_id.bytes,
               controller->runtime_id,
               16u)
            == 0
        && envelope->authority_term == binding->pair_generation
        && envelope->assignment_epoch == (uint32_t)binding->pair_generation
        && memcmp(envelope->route_policy_id.bytes, row->policy_id, 16u) == 0
        && envelope->route_policy_revision == binding->pair_generation
        && memcmp(
               envelope->route_policy_digest.bytes,
               row->path_policy_digest,
               32u)
            == 0
        && memcmp(envelope->selected_path_id.bytes, row->selected_path_id, 16u)
            == 0
        && envelope->path_selection_epoch != 0u;
}

static int application_content_matches(
    const ninlil_v1_lab_radio_mapper_t *mapper,
    const ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    uint8_t digest[32];
    int match;

    if (mapper == NULL || envelope == NULL
        || envelope->payload.length < NINLIL_NRA1_APPLICATION_PAYLOAD_MIN
        || envelope->payload.length > NINLIL_NRA1_APPLICATION_PAYLOAD_MAX
        || envelope->payload.bytes == NULL) {
        return 0;
    }
    if (ninlil_r7_crypto_sha256(
            &mapper->crypto,
            envelope->payload.bytes,
            envelope->payload.length,
            digest)
        != NINLIL_R7_CRYPTO_OK) {
        clear_bytes(digest, sizeof(digest));
        return 0;
    }
    match = memcmp(digest, envelope->content_digest.bytes, 32u) == 0;
    clear_bytes(digest, sizeof(digest));
    return match;
}

static int row_candidate_matches(
    const ninlil_v1_lab_radio_mapper_t *mapper,
    const ninlil_v1_lab_radio_pair_slot_t *pair,
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    if (mapper == NULL || pair == NULL || row == NULL || envelope == NULL
        || pair->active == 0u || pair->fenced != 0u
        || !envelope_static_matches(&pair->binding, row, envelope)
        || memcmp(
               envelope->source_runtime_id.bytes,
               mapper->local_runtime_id,
               16u)
            != 0) {
        return 0;
    }
    if (envelope->message_kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
        return application_content_matches(mapper, envelope);
    }
    if (envelope->message_kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        const ninlil_v1_lab_endpoint_t *source;
        const ninlil_v1_lab_endpoint_t *target;
        if (!endpoints_for_flow(&pair->binding, row->flow, &source, &target)) {
            return 0;
        }
        (void)source;
        return envelope->receipt_stage >= NINLIL_EVIDENCE_RECEIVED
            && envelope->receipt_stage <= NINLIL_EVIDENCE_VERIFIED
            && memcmp(
                   envelope->evidence_time_clock_epoch_id.bytes,
                   target->clock_epoch_id,
                   16u)
                == 0
            && envelope->evidence_time_trust == target->clock_trust;
    }
    return 0;
}

static ninlil_v1_lab_radio_mapping_status_t find_outbound_row(
    const ninlil_v1_lab_radio_mapper_t *mapper,
    const ninlil_fabric_private_nfl1_envelope_t *envelope,
    uint8_t *out_pair_slot,
    uint8_t *out_row_index)
{
    uint8_t found_pair = 0u;
    uint8_t found_row = 0u;
    uint8_t matches = 0u;
    uint8_t p;

    for (p = 0u; p < NINLIL_V1_LAB_RADIO_PAIR_MAX; ++p) {
        uint8_t r;
        const ninlil_v1_lab_radio_pair_slot_t *pair = &mapper->pairs[p];
        if (pair->active == 0u || pair->fenced != 0u) {
            continue;
        }
        for (r = 0u; r < pair->binding.service_count; ++r) {
            if (row_candidate_matches(
                    mapper, pair, &pair->binding.services[r], envelope)) {
                matches++;
                found_pair = p;
                found_row = r;
            }
        }
    }
    if (matches == 0u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_BINDING;
    }
    if (matches != 1u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_CONFLICT;
    }
    *out_pair_slot = found_pair;
    *out_row_index = found_row;
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

static ninlil_v1_lab_radio_correlation_t *find_correlation(
    ninlil_v1_lab_radio_mapper_t *mapper,
    uint8_t pair_slot,
    uint8_t original_flow,
    uint8_t service_slot,
    const uint8_t transaction_id[16],
    const uint8_t attempt_id[16])
{
    uint8_t i;

    for (i = 0u; i < NINLIL_V1_LAB_RADIO_CORRELATION_MAX; ++i) {
        ninlil_v1_lab_radio_correlation_t *correlation =
            &mapper->correlations[i];
        if (correlation->active != 0u
            && correlation->pair_slot == pair_slot
            && correlation->original_flow == original_flow
            && correlation->service_slot == service_slot
            && memcmp(correlation->transaction_id, transaction_id, 16u) == 0
            && memcmp(correlation->attempt_id, attempt_id, 16u) == 0) {
            return correlation;
        }
    }
    return NULL;
}

static ninlil_v1_lab_radio_correlation_t *free_correlation(
    ninlil_v1_lab_radio_mapper_t *mapper)
{
    uint8_t i;

    for (i = 0u; i < NINLIL_V1_LAB_RADIO_CORRELATION_MAX; ++i) {
        if (mapper->correlations[i].active == 0u) {
            return &mapper->correlations[i];
        }
    }
    return NULL;
}

static ninlil_v1_lab_radio_mapping_status_t retain_application(
    ninlil_v1_lab_radio_mapper_t *mapper,
    uint8_t pair_slot,
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_fabric_private_nfl1_envelope_t *envelope,
    const uint8_t *nfl1,
    uint32_t nfl1_length,
    uint64_t now_ms)
{
    ninlil_v1_lab_radio_correlation_t *correlation;

    correlation = find_correlation(
        mapper,
        pair_slot,
        row->flow,
        row->slot,
        envelope->transaction_id.bytes,
        envelope->attempt_id.bytes);
    if (correlation != NULL) {
        if (correlation->nfl1_length != nfl1_length
            || memcmp(correlation->nfl1, nfl1, nfl1_length) != 0) {
            return NINLIL_V1_LAB_RADIO_MAPPING_CONFLICT;
        }
        return correlation->receipt_pending == 0u
            ? NINLIL_V1_LAB_RADIO_MAPPING_OK
            : NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY;
    }
    if (now_ms > UINT64_MAX - NINLIL_V1_LAB_RADIO_CORRELATION_MS) {
        mapper->pairs[pair_slot].fenced = 1u;
        clear_pair_correlations(mapper, pair_slot);
        return NINLIL_V1_LAB_RADIO_MAPPING_FENCED;
    }
    correlation = free_correlation(mapper);
    if (correlation == NULL) {
        return NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY;
    }
    correlation->active = 1u;
    correlation->pair_slot = pair_slot;
    correlation->original_flow = row->flow;
    correlation->service_slot = row->slot;
    correlation->required_evidence = (uint8_t)envelope->required_evidence;
    correlation->expires_at_ms =
        now_ms + NINLIL_V1_LAB_RADIO_CORRELATION_MS;
    (void)memcpy(
        correlation->transaction_id, envelope->transaction_id.bytes, 16u);
    (void)memcpy(correlation->attempt_id, envelope->attempt_id.bytes, 16u);
    correlation->nfl1_length = nfl1_length;
    (void)memcpy(correlation->nfl1, nfl1, nfl1_length);
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

static void application_to_nra1(
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_fabric_private_nfl1_envelope_t *envelope,
    ninlil_nra1_application_t *application)
{
    (void)memset(application, 0, sizeof(*application));
    application->service_slot = row->slot;
    application->required_evidence = (uint8_t)envelope->required_evidence;
    (void)memcpy(
        application->transaction_id, envelope->transaction_id.bytes, 16u);
    (void)memcpy(application->attempt_id, envelope->attempt_id.bytes, 16u);
    if (row->family == NINLIL_FAMILY_EVENT_FACT) {
        (void)memcpy(application->subject, envelope->event_id.bytes, 16u);
    } else {
        size_t i;
        for (i = 0u; i < 8u; ++i) {
            application->subject[15u - i] =
                (uint8_t)(envelope->generation >> (i * 8u));
        }
    }
    application->absolute_effect_deadline_ms =
        envelope->absolute_effect_deadline_ms;
    application->payload_len = envelope->payload.length;
    (void)memcpy(
        application->payload,
        envelope->payload.bytes,
        envelope->payload.length);
}

static uint64_t subject_generation(const uint8_t subject[16])
{
    uint64_t value = 0u;
    size_t i;

    for (i = 8u; i < 16u; ++i) {
        value = (value << 8u) | subject[i];
    }
    return value;
}

static void build_application_envelope(
    const ninlil_v1_lab_radio_mapper_t *mapper,
    const ninlil_v1_lab_binding_t *binding,
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_nra1_application_t *application,
    ninlil_fabric_private_nfl1_envelope_t *envelope,
    uint8_t content_digest[32])
{
    const ninlil_v1_lab_endpoint_t *source = NULL;
    const ninlil_v1_lab_endpoint_t *target = NULL;
    const ninlil_v1_lab_endpoint_t *controller;

    (void)mapper;
    (void)memset(envelope, 0, sizeof(*envelope));
    if (!endpoints_for_flow(binding, row->flow, &source, &target)
        || source == NULL || target == NULL) {
        return;
    }
    controller = endpoint_for_side(binding, binding->controller_side);
    envelope->api_version = NINLIL_ABI_VERSION;
    envelope->struct_size = (uint16_t)sizeof(*envelope);
    envelope->message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    (void)memcpy(
        envelope->transaction_id.bytes, application->transaction_id, 16u);
    (void)memcpy(envelope->attempt_id.bytes, application->attempt_id, 16u);
    envelope_set_source(envelope, source);
    envelope_set_target(envelope, target);
    (void)memcpy(
        envelope->authority_id.bytes, controller->runtime_id, 16u);
    envelope->authority_term = binding->pair_generation;
    envelope->assignment_epoch = (uint32_t)binding->pair_generation;
    envelope->descriptor_revision = row->descriptor_revision;
    envelope->descriptor_digest.algorithm =
        NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256;
    (void)memcpy(
        envelope->descriptor_digest.bytes, row->descriptor_digest, 32u);
    envelope->schema_major = row->schema_major;
    envelope->schema_minor = row->schema_minor;
    envelope->family = row->family;
    envelope->content_digest.algorithm =
        NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256;
    (void)memcpy(envelope->content_digest.bytes, content_digest, 32u);
    if (row->family == NINLIL_FAMILY_EVENT_FACT) {
        (void)memcpy(envelope->event_id.bytes, application->subject, 16u);
    } else {
        envelope->generation = subject_generation(application->subject);
        (void)memcpy(
            envelope->deadline_clock_epoch_id.bytes,
            controller->clock_epoch_id,
            16u);
    }
    envelope->absolute_effect_deadline_ms =
        application->absolute_effect_deadline_ms;
    envelope->evidence_grace_ms = row->evidence_grace_ms;
    envelope->required_evidence = application->required_evidence;
    (void)memcpy(envelope->route_policy_id.bytes, row->policy_id, 16u);
    envelope->route_policy_revision = binding->pair_generation;
    envelope->route_policy_digest.algorithm =
        NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256;
    (void)memcpy(
        envelope->route_policy_digest.bytes, row->path_policy_digest, 32u);
    (void)memcpy(
        envelope->selected_path_id.bytes, row->selected_path_id, 16u);
    envelope->path_selection_epoch = binding->pair_generation;
    envelope->namespace_id.bytes = row->namespace_id;
    envelope->namespace_id.length = row->namespace_length;
    envelope->service_id.bytes = row->service_id;
    envelope->service_id.length = row->service_length;
    envelope->schema_id.bytes = row->schema_id;
    envelope->schema_id.length = row->schema_length;
    envelope->payload.bytes = application->payload;
    envelope->payload.length = (uint32_t)application->payload_len;
}

static uint32_t next_receipt_token(ninlil_v1_lab_radio_mapper_t *mapper)
{
    mapper->next_receipt_token++;
    if (mapper->next_receipt_token == 0u) {
        mapper->next_receipt_token = 1u;
    }
    return mapper->next_receipt_token;
}

static const ninlil_v1_lab_service_row_t *find_row_by_slot_flow(
    const ninlil_v1_lab_binding_t *binding, uint8_t slot, uint8_t flow)
{
    const ninlil_v1_lab_service_row_t *found = NULL;
    uint8_t i;

    if (binding == NULL || !flow_valid(flow)) {
        return NULL;
    }
    for (i = 0u; i < binding->service_count; ++i) {
        if (binding->services[i].slot == slot
            && binding->services[i].flow == flow) {
            if (found != NULL) {
                return NULL;
            }
            found = &binding->services[i];
        }
    }
    return found;
}

static ninlil_v1_lab_radio_mapping_status_t decode_application_body(
    ninlil_v1_lab_radio_mapper_t *mapper,
    uint8_t pair_slot,
    uint8_t authenticated_radio_flow,
    const uint8_t *nra1,
    size_t nra1_length,
    uint8_t *out_nfl1,
    uint32_t out_capacity,
    uint32_t *out_length)
{
    const ninlil_v1_lab_binding_t *binding =
        &mapper->pairs[pair_slot].binding;
    const ninlil_v1_lab_service_row_t *row;
    ninlil_nra1_application_t application;
    ninlil_fabric_private_nfl1_envelope_t *envelope;
    uint8_t digest[32];
    uint32_t encoded_length = 0u;

    (void)memset(&application, 0, sizeof(application));
    (void)memset(digest, 0, sizeof(digest));
    mapper_scratch_clear(mapper);
    envelope = &mapper->nfl1_envelope;
    if (ninlil_nra1_decode_application(nra1, nra1_length, &application)
        != NINLIL_NRA1_OK) {
        mapper_scratch_clear(mapper);
        return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    row = find_row_by_slot_flow(
        binding, application.service_slot, authenticated_radio_flow);
    if (row == NULL) {
        clear_bytes(&application, sizeof(application));
        return NINLIL_V1_LAB_RADIO_MAPPING_BINDING;
    }
    if (ninlil_nra1_validate_application_family(&application, row->family)
        != NINLIL_NRA1_OK) {
        clear_bytes(&application, sizeof(application));
        return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    if (ninlil_r7_crypto_sha256(
            &mapper->crypto,
            application.payload,
            application.payload_len,
            digest)
        != NINLIL_R7_CRYPTO_OK) {
        clear_bytes(&application, sizeof(application));
        clear_bytes(digest, sizeof(digest));
        return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    build_application_envelope(
        mapper, binding, row, &application, envelope, digest);
    if (ninlil_fabric_private_nfl1_encode(
            envelope,
            out_nfl1,
            out_capacity,
            &encoded_length)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        clear_bytes(&application, sizeof(application));
        mapper_scratch_clear(mapper);
        clear_bytes(digest, sizeof(digest));
        return out_capacity < NINLIL_V1_LAB_RADIO_NFL1_MAX
            ? NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY
            : NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    *out_length = encoded_length;
    clear_bytes(&application, sizeof(application));
    mapper_scratch_clear(mapper);
    clear_bytes(digest, sizeof(digest));
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

static void receipt_envelope_from_application(
    const ninlil_v1_lab_binding_t *binding,
    const ninlil_v1_lab_service_row_t *row,
    const ninlil_nra1_receipt_t *receipt,
    ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    const ninlil_v1_lab_endpoint_t *forward_source = NULL;
    const ninlil_v1_lab_endpoint_t *forward_target = NULL;

    if (!endpoints_for_flow(
            binding, row->flow, &forward_source, &forward_target)
        || forward_source == NULL || forward_target == NULL) {
        return;
    }
    envelope->message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    envelope_set_source(envelope, forward_target);
    envelope_set_target(envelope, forward_source);
    envelope->receipt_stage = receipt->receipt_stage;
    envelope->payload.bytes = NULL;
    envelope->payload.length = 0u;
    envelope->evidence.bytes = NULL;
    envelope->evidence.length = 0u;
    (void)memcpy(
        envelope->evidence_time_clock_epoch_id.bytes,
        forward_target->clock_epoch_id,
        16u);
    envelope->evidence_time_now_ms = receipt->evidence_time_now_ms;
    envelope->evidence_time_trust = forward_target->clock_trust;
    envelope->disposition = 0u;
    envelope->effect_certainty = 0u;
    envelope->retry_guidance = 0u;
    envelope->cancel_kind = 0u;
    envelope->retry_delay_ms = 0u;
}

static ninlil_v1_lab_radio_mapping_status_t decode_receipt_body(
    ninlil_v1_lab_radio_mapper_t *mapper,
    uint8_t pair_slot,
    uint8_t authenticated_radio_flow,
    const uint8_t *nra1,
    size_t nra1_length,
    uint8_t *out_nfl1,
    uint32_t out_capacity,
    uint32_t *out_length,
    uint32_t *out_receipt_token)
{
    ninlil_v1_lab_radio_correlation_t *correlation;
    const ninlil_v1_lab_binding_t *binding =
        &mapper->pairs[pair_slot].binding;
    const ninlil_v1_lab_service_row_t *row;
    ninlil_nra1_receipt_t receipt;
    ninlil_fabric_private_nfl1_workspace_t *workspace;
    ninlil_fabric_private_nfl1_envelope_t *envelope;
    uint32_t required = 0u;
    uint32_t encoded_length = 0u;
    uint32_t token;
    uint8_t original_flow = opposite_flow(authenticated_radio_flow);

    (void)memset(&receipt, 0, sizeof(receipt));
    mapper_scratch_clear(mapper);
    workspace = &mapper->nfl1_workspace;
    envelope = &mapper->nfl1_envelope;
    if (ninlil_nra1_decode_receipt(nra1, nra1_length, &receipt)
        != NINLIL_NRA1_OK) {
        mapper_scratch_clear(mapper);
        return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    row = find_row_by_slot_flow(binding, receipt.service_slot, original_flow);
    if (row == NULL) {
        clear_bytes(&receipt, sizeof(receipt));
        return NINLIL_V1_LAB_RADIO_MAPPING_BINDING;
    }
    correlation = find_correlation(
        mapper,
        pair_slot,
        original_flow,
        receipt.service_slot,
        receipt.transaction_id,
        receipt.attempt_id);
    if (correlation == NULL) {
        clear_bytes(&receipt, sizeof(receipt));
        return NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND;
    }
    if (correlation->receipt_pending != 0u) {
        clear_bytes(&receipt, sizeof(receipt));
        return NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY;
    }
    if (ninlil_fabric_private_nfl1_decode(
            correlation->nfl1,
            correlation->nfl1_length,
            workspace,
            envelope,
            &required)
            != NINLIL_FABRIC_PRIVATE_NFL1_OK
        || envelope->message_kind != NINLIL_BEARER_MESSAGE_APPLICATION
        || !envelope_static_matches(binding, row, envelope)) {
        clear_bytes(&receipt, sizeof(receipt));
        mapper_scratch_clear(mapper);
        return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    receipt_envelope_from_application(binding, row, &receipt, envelope);
    if (ninlil_fabric_private_nfl1_encode(
            envelope,
            out_nfl1,
            out_capacity,
            &encoded_length)
            != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        clear_bytes(&receipt, sizeof(receipt));
        mapper_scratch_clear(mapper);
        return out_capacity < correlation->nfl1_length
            ? NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY
            : NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    token = next_receipt_token(mapper);
    correlation->receipt_pending = 1u;
    correlation->pending_stage = receipt.receipt_stage;
    correlation->receipt_token = token;
    *out_length = encoded_length;
    *out_receipt_token = token;
    clear_bytes(&receipt, sizeof(receipt));
    mapper_scratch_clear(mapper);
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

ninlil_v1_lab_radio_mapping_status_t ninlil_v1_lab_radio_mapper_init(
    ninlil_v1_lab_radio_mapper_t *mapper,
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t local_runtime_id[16])
{
    if (mapper == NULL || crypto == NULL || local_runtime_id == NULL
        || bytes_zero(local_runtime_id, 16u)
        || ninlil_r7_crypto_provider_validate(crypto)
            != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    (void)memset(mapper, 0, sizeof(*mapper));
    mapper->magic = V1_LAB_RADIO_MAPPER_MAGIC;
    mapper->crypto = *crypto;
    (void)memcpy(mapper->local_runtime_id, local_runtime_id, 16u);
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

ninlil_v1_lab_radio_mapping_status_t
ninlil_v1_lab_radio_mapper_install_pair(
    ninlil_v1_lab_radio_mapper_t *mapper,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    uint8_t *out_pair_slot)
{
    ninlil_v1_lab_binding_t *binding;
    uint8_t local_side = 0u;
    uint8_t free_slot = NINLIL_V1_LAB_RADIO_PAIR_MAX;
    uint8_t i;

    if (mapper == NULL || !mapper_valid(mapper) || encoded_binding == NULL
        || out_pair_slot == NULL) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    mapper_scratch_clear(mapper);
    binding = &mapper->binding_scratch;
    if (ninlil_v1_lab_binding_decode(
            &mapper->crypto,
            encoded_binding,
            encoded_length,
            binding)
            != NINLIL_V1_LAB_BINDING_OK
        || ninlil_v1_lab_binding_local_side(
               binding, mapper->local_runtime_id, &local_side)
            != NINLIL_V1_LAB_BINDING_OK
        || endpoint_for_side(binding, local_side)->clock_trust
            != NINLIL_CLOCK_TRUSTED) {
        mapper_scratch_clear(mapper);
        return NINLIL_V1_LAB_RADIO_MAPPING_BINDING;
    }

    for (i = 0u; i < NINLIL_V1_LAB_RADIO_PAIR_MAX; ++i) {
        ninlil_v1_lab_radio_pair_slot_t *pair = &mapper->pairs[i];
        if (pair->active == 0u) {
            if (free_slot == NINLIL_V1_LAB_RADIO_PAIR_MAX) {
                free_slot = i;
            }
            continue;
        }
        if (memcmp(pair->binding.pair_id, binding->pair_id, 32u) == 0) {
            if (pair->binding.raw_length == binding->raw_length
                && memcmp(
                       pair->binding.raw,
                       binding->raw,
                       binding->raw_length)
                    == 0
                && pair->fenced == 0u) {
                *out_pair_slot = i;
                mapper_scratch_clear(mapper);
                return NINLIL_V1_LAB_RADIO_MAPPING_OK;
            }
            mapper_scratch_clear(mapper);
            return NINLIL_V1_LAB_RADIO_MAPPING_CONFLICT;
        }
    }
    if (free_slot >= NINLIL_V1_LAB_RADIO_PAIR_MAX) {
        mapper_scratch_clear(mapper);
        return NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY;
    }
    mapper->pairs[free_slot].active = 1u;
    mapper->pairs[free_slot].local_side = local_side;
    mapper->pairs[free_slot].binding = *binding;
    *out_pair_slot = free_slot;
    mapper_scratch_clear(mapper);
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

ninlil_v1_lab_radio_mapping_status_t
ninlil_v1_lab_radio_mapper_remove_pair(
    ninlil_v1_lab_radio_mapper_t *mapper, uint8_t pair_slot)
{
    if (!mapper_valid(mapper) || pair_slot >= NINLIL_V1_LAB_RADIO_PAIR_MAX) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    if (mapper->pairs[pair_slot].active == 0u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND;
    }
    clear_pair_correlations(mapper, pair_slot);
    clear_bytes(&mapper->pairs[pair_slot], sizeof(mapper->pairs[pair_slot]));
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

ninlil_v1_lab_radio_mapping_status_t ninlil_v1_lab_radio_mapper_encode(
    ninlil_v1_lab_radio_mapper_t *mapper,
    const uint8_t *nfl1,
    uint32_t nfl1_length,
    const ninlil_time_sample_t *now,
    uint8_t *out_pair_slot,
    uint8_t *out_radio_flow,
    uint8_t *out_nra1,
    size_t out_capacity,
    size_t *out_length)
{
    ninlil_fabric_private_nfl1_workspace_t *workspace;
    ninlil_fabric_private_nfl1_envelope_t *envelope;
    ninlil_v1_lab_radio_mapping_status_t status;
    const ninlil_v1_lab_service_row_t *row;
    uint8_t pair_slot = 0u;
    uint8_t row_index = 0u;
    uint8_t *candidate;
    size_t candidate_length = 0u;
    uint32_t required = 0u;

    if (!mapper_valid(mapper) || nfl1 == NULL || now == NULL
        || out_pair_slot == NULL || out_radio_flow == NULL
        || out_nra1 == NULL || out_length == NULL
        || nfl1_length < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || nfl1_length > NINLIL_V1_LAB_RADIO_NFL1_MAX) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    mapper_scratch_clear(mapper);
    workspace = &mapper->nfl1_workspace;
    envelope = &mapper->nfl1_envelope;
    candidate = mapper->nra1_candidate;
    if (ninlil_fabric_private_nfl1_decode(
            nfl1,
            nfl1_length,
            workspace,
            envelope,
            &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        mapper_scratch_clear(mapper);
        return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
    }
    if (envelope->message_kind != NINLIL_BEARER_MESSAGE_APPLICATION
        && envelope->message_kind != NINLIL_BEARER_MESSAGE_RECEIPT) {
        mapper_scratch_clear(mapper);
        return NINLIL_V1_LAB_RADIO_MAPPING_UNSUPPORTED;
    }
    status = find_outbound_row(
        mapper, envelope, &pair_slot, &row_index);
    if (status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        mapper_scratch_clear(mapper);
        return status;
    }
    status = sample_pair_now(mapper, pair_slot, now);
    if (status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        mapper_scratch_clear(mapper);
        return status;
    }
    row = &mapper->pairs[pair_slot].binding.services[row_index];
    if (envelope->message_kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
        ninlil_nra1_application_t application;
        (void)memset(&application, 0, sizeof(application));
        application_to_nra1(row, envelope, &application);
        if (ninlil_nra1_encode_application(
                &application,
                candidate,
                sizeof(mapper->nra1_candidate),
                &candidate_length)
            != NINLIL_NRA1_OK) {
            clear_bytes(&application, sizeof(application));
            mapper_scratch_clear(mapper);
            return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
        }
        clear_bytes(&application, sizeof(application));
        if (out_capacity < candidate_length) {
            mapper_scratch_clear(mapper);
            return NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY;
        }
        if (envelope->required_evidence != NINLIL_EVIDENCE_NONE) {
            status = retain_application(
                mapper,
                pair_slot,
                row,
                envelope,
                nfl1,
                nfl1_length,
                now->now_ms);
            if (status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
                mapper_scratch_clear(mapper);
                return status;
            }
        }
        *out_radio_flow = row->flow;
    } else {
        ninlil_nra1_receipt_t receipt;
        (void)memset(&receipt, 0, sizeof(receipt));
        receipt.service_slot = row->slot;
        receipt.receipt_stage = (uint8_t)envelope->receipt_stage;
        (void)memcpy(
            receipt.transaction_id, envelope->transaction_id.bytes, 16u);
        (void)memcpy(receipt.attempt_id, envelope->attempt_id.bytes, 16u);
        receipt.evidence_time_now_ms = envelope->evidence_time_now_ms;
        if (ninlil_nra1_encode_receipt(
                &receipt,
                candidate,
                sizeof(mapper->nra1_candidate),
                &candidate_length)
            != NINLIL_NRA1_OK) {
            clear_bytes(&receipt, sizeof(receipt));
            mapper_scratch_clear(mapper);
            return NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT;
        }
        clear_bytes(&receipt, sizeof(receipt));
        if (out_capacity < candidate_length) {
            mapper_scratch_clear(mapper);
            return NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY;
        }
        *out_radio_flow = opposite_flow(row->flow);
    }
    (void)memcpy(out_nra1, candidate, candidate_length);
    *out_pair_slot = pair_slot;
    *out_length = candidate_length;
    mapper_scratch_clear(mapper);
    return NINLIL_V1_LAB_RADIO_MAPPING_OK;
}

ninlil_v1_lab_radio_mapping_status_t ninlil_v1_lab_radio_mapper_decode(
    ninlil_v1_lab_radio_mapper_t *mapper,
    uint8_t pair_slot,
    uint8_t authenticated_radio_flow,
    const uint8_t *nra1,
    size_t nra1_length,
    const ninlil_time_sample_t *now,
    uint8_t *out_nfl1,
    uint32_t out_capacity,
    uint32_t *out_length,
    uint32_t *out_receipt_token)
{
    ninlil_v1_lab_radio_mapping_status_t status;

    if (!mapper_valid(mapper) || pair_slot >= NINLIL_V1_LAB_RADIO_PAIR_MAX
        || !flow_valid(authenticated_radio_flow) || nra1 == NULL
        || now == NULL || out_nfl1 == NULL || out_length == NULL
        || out_receipt_token == NULL || nra1_length < 5u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    *out_receipt_token = 0u;
    status = sample_pair_now(mapper, pair_slot, now);
    if (status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        return status;
    }
    if (nra1[4] == NINLIL_NRA1_KIND_APPLICATION) {
        return decode_application_body(
            mapper,
            pair_slot,
            authenticated_radio_flow,
            nra1,
            nra1_length,
            out_nfl1,
            out_capacity,
            out_length);
    }
    if (nra1[4] == NINLIL_NRA1_KIND_RECEIPT) {
        return decode_receipt_body(
            mapper,
            pair_slot,
            authenticated_radio_flow,
            nra1,
            nra1_length,
            out_nfl1,
            out_capacity,
            out_length,
            out_receipt_token);
    }
    return NINLIL_V1_LAB_RADIO_MAPPING_UNSUPPORTED;
}

ninlil_v1_lab_radio_mapping_status_t
ninlil_v1_lab_radio_mapper_commit_received(
    ninlil_v1_lab_radio_mapper_t *mapper, uint32_t receipt_token)
{
    uint8_t i;

    if (!mapper_valid(mapper) || receipt_token == 0u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_CORRELATION_MAX; ++i) {
        ninlil_v1_lab_radio_correlation_t *correlation =
            &mapper->correlations[i];
        if (correlation->active == 0u
            || correlation->receipt_pending == 0u
            || correlation->receipt_token != receipt_token) {
            continue;
        }
        if (correlation->pending_stage >= correlation->required_evidence) {
            correlation_clear(correlation);
        } else {
            correlation->receipt_pending = 0u;
            correlation->pending_stage = 0u;
            correlation->receipt_token = 0u;
        }
        return NINLIL_V1_LAB_RADIO_MAPPING_OK;
    }
    return NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND;
}

ninlil_v1_lab_radio_mapping_status_t
ninlil_v1_lab_radio_mapper_abort_received(
    ninlil_v1_lab_radio_mapper_t *mapper, uint32_t receipt_token)
{
    uint8_t i;

    if (!mapper_valid(mapper) || receipt_token == 0u) {
        return NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_CORRELATION_MAX; ++i) {
        ninlil_v1_lab_radio_correlation_t *correlation =
            &mapper->correlations[i];
        if (correlation->active == 0u
            || correlation->receipt_pending == 0u
            || correlation->receipt_token != receipt_token) {
            continue;
        }
        correlation->receipt_pending = 0u;
        correlation->pending_stage = 0u;
        correlation->receipt_token = 0u;
        return NINLIL_V1_LAB_RADIO_MAPPING_OK;
    }
    return NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND;
}

void ninlil_v1_lab_radio_mapper_clear(
    ninlil_v1_lab_radio_mapper_t *mapper)
{
    if (mapper != NULL) {
        clear_bytes(mapper, sizeof(*mapper));
    }
}
