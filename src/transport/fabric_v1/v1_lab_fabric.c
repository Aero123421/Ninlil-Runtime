#include "v1_lab_fabric.h"

#include "fabric_private_records.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

#define V1_LAB_RF_CAPS                                                     \
    (NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE | NINLIL_FABRIC_CAP_UNICAST       \
        | NINLIL_FABRIC_CAP_RESERVATION                                   \
        | NINLIL_FABRIC_CAP_REGULATED_RF | NINLIL_FABRIC_CAP_EVIDENCE)
#define V1_LAB_RF_SECURITY                                                 \
    (NINLIL_FABRIC_SECURITY_INTEGRITY                                     \
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY                          \
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION                        \
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS)

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

static void put_u64_be(uint8_t out[8], uint64_t value)
{
    size_t i;
    for (i = 0u; i < 8u; ++i) {
        out[i] = (uint8_t)(value >> (56u - (unsigned)(i * 8u)));
    }
}

static int crypto_valid(const ninlil_r7_crypto_provider *crypto)
{
    return ninlil_r7_crypto_provider_validate(crypto)
        == NINLIL_R7_CRYPTO_OK;
}

static int hash_tagged(
    const ninlil_r7_crypto_provider *crypto,
    const char *tag,
    const uint8_t *body,
    size_t body_length,
    uint8_t out[32])
{
    uint8_t input[192];
    size_t tag_length;
    size_t total;
    int ok;

    if (crypto == NULL || tag == NULL || body == NULL || out == NULL) {
        return 0;
    }
    tag_length = strlen(tag);
    if (tag_length > sizeof(input)
        || body_length > sizeof(input) - tag_length) {
        return 0;
    }
    total = tag_length + body_length;
    (void)memcpy(input, tag, tag_length);
    (void)memcpy(input + tag_length, body, body_length);
    ok = ninlil_r7_crypto_sha256(crypto, input, total, out)
        == NINLIL_R7_CRYPTO_OK;
    clear_bytes(input, total);
    return ok;
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

static int flow_endpoints(
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

static const ninlil_v1_lab_service_row_t *first_flow_row(
    const ninlil_v1_lab_binding_t *binding, uint8_t flow)
{
    uint8_t i;
    const ninlil_v1_lab_service_row_t *found = NULL;

    if (binding == NULL || binding->service_count == 0u
        || binding->service_count > NINLIL_V1_LAB_SERVICE_MAX) {
        return NULL;
    }
    for (i = 0u; i < binding->service_count; ++i) {
        if (binding->services[i].flow != flow) {
            continue;
        }
        if (found == NULL) {
            found = &binding->services[i];
        } else if (memcmp(
                       found->selected_path_id,
                       binding->services[i].selected_path_id,
                       16u)
            != 0) {
            return NULL;
        }
    }
    return found;
}

static int descriptor_common(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t path_id[16],
    const uint8_t local_runtime_id[16],
    const uint8_t peer_runtime_id[16],
    uint8_t out[120])
{
    if (binding == NULL || path_id == NULL || local_runtime_id == NULL
        || peer_runtime_id == NULL || out == NULL
        || binding->pair_generation == 0u
        || binding->pair_generation > UINT32_MAX) {
        return 0;
    }
    (void)memcpy(out, binding->pair_binding_digest, 32u);
    (void)memcpy(out + 32u, binding->e2e_security_id, 32u);
    (void)memcpy(out + 64u, path_id, 16u);
    (void)memcpy(out + 80u, local_runtime_id, 16u);
    (void)memcpy(out + 96u, peer_runtime_id, 16u);
    put_u64_be(out + 112u, binding->pair_generation);
    return 1;
}

ninlil_v1_lab_fabric_status_t ninlil_v1_lab_fabric_build_path(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t local_runtime_id[16],
    uint8_t flow,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor,
    ninlil_fabric_link_state_v1_t *out_state)
{
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_link_state_v1_t state;
    const ninlil_v1_lab_service_row_t *row;
    const ninlil_v1_lab_endpoint_t *local;
    const ninlil_v1_lab_endpoint_t *peer;
    const ninlil_v1_lab_endpoint_t *controller;
    uint8_t local_side = 0u;
    uint8_t common[120];
    uint8_t digest[32];

    if (crypto == NULL || binding == NULL || local_runtime_id == NULL
        || out_descriptor == NULL || out_state == NULL) {
        return NINLIL_V1_LAB_FABRIC_INVALID_ARGUMENT;
    }
    if (!crypto_valid(crypto)) {
        return NINLIL_V1_LAB_FABRIC_CRYPTO;
    }
    if (ninlil_v1_lab_binding_local_side(
            binding, local_runtime_id, &local_side)
        != NINLIL_V1_LAB_BINDING_OK) {
        return NINLIL_V1_LAB_FABRIC_BINDING;
    }
    row = first_flow_row(binding, flow);
    local = endpoint_for_side(binding, local_side);
    peer = endpoint_for_side(
        binding,
        local_side == NINLIL_V1_LAB_SIDE_A ? NINLIL_V1_LAB_SIDE_B
                                            : NINLIL_V1_LAB_SIDE_A);
    controller = endpoint_for_side(binding, binding->controller_side);
    if (row == NULL || local == NULL || peer == NULL || controller == NULL
        || !descriptor_common(
            binding,
            row->selected_path_id,
            local->runtime_id,
            peer->runtime_id,
            common)) {
        clear_bytes(common, sizeof(common));
        return row == NULL ? NINLIL_V1_LAB_FABRIC_FLOW
                           : NINLIL_V1_LAB_FABRIC_BINDING;
    }

    (void)memset(&descriptor, 0, sizeof(descriptor));
    descriptor.api_version = NINLIL_FABRIC_API_VERSION;
    descriptor.struct_size = (uint16_t)sizeof(descriptor);
    (void)memcpy(descriptor.instance_id.bytes, row->selected_path_id, 16u);
    descriptor.link_kind = NINLIL_FABRIC_LINK_KIND_RF;
    descriptor.direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor.capability_flags = V1_LAB_RF_CAPS;
    descriptor.descriptor_revision = binding->pair_generation;
    if (!hash_tagged(
            crypto,
            "NINLIL-V1-LAB-RF-DESCRIPTOR",
            common,
            sizeof(common),
            descriptor.descriptor_digest)
        || !hash_tagged(
            crypto,
            "NINLIL-V1-LAB-RF-SECURITY-PROFILE",
            common,
            sizeof(common),
            digest)) {
        clear_bytes(common, sizeof(common));
        clear_bytes(digest, sizeof(digest));
        return NINLIL_V1_LAB_FABRIC_CRYPTO;
    }
    (void)memcpy(descriptor.security_profile_id.bytes, digest, 16u);
    descriptor.security_capability_flags = V1_LAB_RF_SECURITY;
    if (!hash_tagged(
            crypto,
            "NINLIL-V1-LAB-RF-SECURITY-BINDING",
            common,
            sizeof(common),
            descriptor.security_binding_digest)
        || !hash_tagged(
            crypto,
            "NINLIL-V1-LAB-RF-ATTESTATION",
            common,
            sizeof(common),
            descriptor.attestation_digest)
        || !hash_tagged(
            crypto,
            "NINLIL-V1-LAB-RF-CONFIGURATION",
            common,
            sizeof(common),
            descriptor.configuration_digest)) {
        clear_bytes(common, sizeof(common));
        clear_bytes(digest, sizeof(digest));
        clear_bytes(&descriptor, sizeof(descriptor));
        return NINLIL_V1_LAB_FABRIC_CRYPTO;
    }
    descriptor.attestation_epoch = binding->pair_generation;
    (void)memcpy(
        descriptor.attestation_clock_epoch_id.bytes,
        local->clock_epoch_id,
        16u);
    descriptor.attestation_expires_at_ms = UINT64_MAX;
    (void)memcpy(
        descriptor.authenticated_peer_runtime_id.bytes,
        peer->runtime_id,
        16u);
    (void)memcpy(
        descriptor.attachment_authority_id.bytes,
        controller->runtime_id,
        16u);
    (void)memcpy(
        descriptor.attachment_binding_digest,
        binding->e2e_security_id,
        32u);
    descriptor.maximum_packet_bytes = NINLIL_V1_LAB_FABRIC_PACKET_MAX;
    descriptor.maximum_transfer_bytes = NINLIL_V1_LAB_FABRIC_PACKET_MAX;
    descriptor.latency_class = 0u;
    descriptor.cost_class = 0u;
    descriptor.reservation_capacity = 1u;
    descriptor.peer_nfl1_version = 1u;
    descriptor.peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor.configuration_revision = binding->pair_generation;

    (void)memset(&state, 0, sizeof(state));
    state.api_version = NINLIL_FABRIC_API_VERSION;
    state.struct_size = (uint16_t)sizeof(state);
    state.availability_epoch = binding->pair_generation;
    (void)memcpy(
        state.availability_clock_epoch_id.bytes,
        local->clock_epoch_id,
        16u);
    state.available_until_ms = UINT64_MAX;
    state.available = 1u;

    *out_descriptor = descriptor;
    *out_state = state;
    clear_bytes(common, sizeof(common));
    clear_bytes(digest, sizeof(digest));
    clear_bytes(&descriptor, sizeof(descriptor));
    clear_bytes(&state, sizeof(state));
    return NINLIL_V1_LAB_FABRIC_OK;
}

ninlil_v1_lab_fabric_status_t ninlil_v1_lab_fabric_build_service(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t local_runtime_id[16],
    uint8_t row_index,
    ninlil_fabric_path_policy_v1_t *out_policy,
    ninlil_fabric_authority_binding_v1_t *out_authority)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_authority_binding_v1_t authority;
    const ninlil_v1_lab_service_row_t *row;
    const ninlil_v1_lab_endpoint_t *local;
    const ninlil_v1_lab_endpoint_t *controller;
    const ninlil_v1_lab_endpoint_t *source;
    const ninlil_v1_lab_endpoint_t *target;
    uint8_t side = 0u;
    uint8_t id_material[73];
    uint8_t digest[32];
    uint8_t *tuple;

    if (crypto == NULL || binding == NULL || local_runtime_id == NULL
        || out_policy == NULL || out_authority == NULL) {
        return NINLIL_V1_LAB_FABRIC_INVALID_ARGUMENT;
    }
    if (!crypto_valid(crypto)) {
        return NINLIL_V1_LAB_FABRIC_CRYPTO;
    }
    if (row_index >= binding->service_count
        || binding->service_count > NINLIL_V1_LAB_SERVICE_MAX
        || ninlil_v1_lab_binding_local_side(binding, local_runtime_id, &side)
            != NINLIL_V1_LAB_BINDING_OK) {
        return NINLIL_V1_LAB_FABRIC_BINDING;
    }
    row = &binding->services[row_index];
    local = endpoint_for_side(binding, side);
    controller = endpoint_for_side(binding, binding->controller_side);
    if (local == NULL || controller == NULL
        || !flow_endpoints(binding, row->flow, &source, &target)) {
        return NINLIL_V1_LAB_FABRIC_BINDING;
    }

    (void)memset(&policy, 0, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    (void)memcpy(policy.policy_id.bytes, row->policy_id, 16u);
    policy.revision = binding->pair_generation;
    (void)memcpy(
        policy.service_identity_digest, row->service_identity_digest, 32u);
    policy.family = row->family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = V1_LAB_RF_CAPS;
    policy.required_security_flags = V1_LAB_RF_SECURITY;
    policy.maximum_latency_class = 0u;
    policy.maximum_cost_class = 0u;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 0u;
    policy.candidate_count = 1u;
    (void)memcpy(
        policy.candidates[0].instance_id.bytes, row->selected_path_id, 16u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;

    (void)memset(&authority, 0, sizeof(authority));
    authority.api_version = NINLIL_FABRIC_API_VERSION;
    authority.struct_size = (uint16_t)sizeof(authority);
    (void)memcpy(id_material, binding->pair_id, 32u);
    put_u64_be(id_material + 32u, binding->pair_generation);
    id_material[40] = row->slot;
    (void)memcpy(id_material + 41u, row->service_identity_digest, 32u);
    if (!hash_tagged(
            crypto,
            "NINLIL-V1-LAB-AUTHORITY-ID",
            id_material,
            sizeof(id_material),
            digest)) {
        clear_bytes(id_material, sizeof(id_material));
        clear_bytes(&policy, sizeof(policy));
        return NINLIL_V1_LAB_FABRIC_CRYPTO;
    }
    (void)memcpy(authority.binding_id.bytes, digest, 16u);
    (void)memcpy(
        authority.service_identity_digest, row->service_identity_digest, 32u);
    authority.family = row->family;
    authority.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    authority.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    authority.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    (void)memcpy(authority.endpoint_runtime_id.bytes, target->runtime_id, 16u);
    (void)memcpy(authority.target_runtime_id.bytes, target->runtime_id, 16u);
    (void)memcpy(
        authority.target_application_id.bytes, target->application_id, 16u);
    (void)memcpy(authority.policy_id.bytes, row->policy_id, 16u);
    authority.policy_revision = binding->pair_generation;
    (void)memcpy(authority.policy_digest, row->path_policy_digest, 32u);
    authority.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    (void)memcpy(authority.authority_id.bytes, controller->runtime_id, 16u);
    authority.authority_term = binding->pair_generation;
    authority.assignment_epoch = (uint32_t)binding->pair_generation;
    (void)memcpy(authority.owner_scope_id.bytes, binding->pair_id, 16u);
    tuple = authority.owner_tuple_canonical;
    (void)memcpy(tuple, "NVO1", 4u);
    tuple[4] = 1u;
    tuple[5] = row->flow;
    tuple[6] = row->slot;
    put_u64_be(tuple + 8u, binding->pair_generation);
    (void)memcpy(tuple + 16u, controller->runtime_id, 16u);
    (void)memcpy(tuple + 32u, source->runtime_id, 16u);
    (void)memcpy(tuple + 48u, target->runtime_id, 16u);
    (void)memcpy(tuple + 64u, target->application_id, 16u);
    (void)memcpy(tuple + 80u, row->policy_id, 16u);
    (void)memcpy(tuple + 96u, row->path_policy_digest, 32u);
    (void)memcpy(tuple + 128u, binding->e2e_security_id, 32u);
    (void)memcpy(tuple + 160u, row->service_identity_digest, 32u);
    ninlil_fabric_private_owner_tuple_digest(
        authority.owner_tuple_canonical, authority.owner_tuple_digest);
    (void)memcpy(
        authority.authority_clock_epoch_id.bytes,
        local->clock_epoch_id,
        16u);
    authority.lease_expires_at_ms = UINT64_MAX;
    authority.assignment_revision = binding->pair_generation;

    *out_policy = policy;
    *out_authority = authority;
    clear_bytes(id_material, sizeof(id_material));
    clear_bytes(digest, sizeof(digest));
    clear_bytes(&policy, sizeof(policy));
    clear_bytes(&authority, sizeof(authority));
    return NINLIL_V1_LAB_FABRIC_OK;
}

ninlil_v1_lab_fabric_status_t ninlil_v1_lab_fabric_build_descriptor(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t local_runtime_id[16],
    uint8_t row_index,
    ninlil_service_descriptor_t *out_descriptor)
{
    ninlil_service_descriptor_t descriptor;
    const ninlil_v1_lab_endpoint_t *local;
    const ninlil_v1_lab_service_row_t *row;
    uint8_t local_side = 0u;

    if (binding == NULL || local_runtime_id == NULL
        || out_descriptor == NULL || row_index >= binding->service_count
        || binding->service_count == 0u
        || binding->service_count > NINLIL_V1_LAB_SERVICE_MAX
        || ninlil_v1_lab_binding_local_side(
               binding, local_runtime_id, &local_side)
            != NINLIL_V1_LAB_BINDING_OK) {
        return NINLIL_V1_LAB_FABRIC_INVALID_ARGUMENT;
    }
    local = endpoint_for_side(binding, local_side);
    row = &binding->services[row_index];
    if (local == NULL || row->namespace_length == 0u
        || row->service_length == 0u || row->schema_length == 0u) {
        return NINLIL_V1_LAB_FABRIC_BINDING;
    }

    (void)memset(&descriptor, 0, sizeof(descriptor));
    descriptor.abi_version = NINLIL_ABI_VERSION;
    descriptor.struct_size = (uint16_t)sizeof(descriptor);
    descriptor.namespace_id.data = row->namespace_id;
    descriptor.namespace_id.length = row->namespace_length;
    descriptor.service_id.data = row->service_id;
    descriptor.service_id.length = row->service_length;
    descriptor.schema_id.data = row->schema_id;
    descriptor.schema_id.length = row->schema_length;
    descriptor.descriptor_revision = row->descriptor_revision;
    descriptor.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(descriptor.descriptor_digest.bytes,
        row->descriptor_digest, sizeof(row->descriptor_digest));
    (void)memcpy(descriptor.local_application_instance_id.bytes,
        local->application_id, sizeof(local->application_id));
    descriptor.schema_major = row->schema_major;
    descriptor.schema_minor_min = row->schema_minor;
    descriptor.schema_minor_max = row->schema_minor;
    descriptor.family = row->family;
    descriptor.direction = row->direction;
    descriptor.admission_authority =
        row->family == NINLIL_FAMILY_DESIRED_STATE
        ? NINLIL_AUTHORITY_CONTROLLER_ONLY
        : NINLIL_AUTHORITY_ORIGIN_WITH_GRANT;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
    descriptor.logical_payload_limit = NINLIL_V1_LAB_APPLICATION_MAX;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = NINLIL_V1_LAB_ADMISSION_WINDOW_MS;
    descriptor.max_admissions_per_window =
        NINLIL_V1_LAB_ADMISSIONS_PER_WINDOW;
    descriptor.max_payload_bytes_per_window =
        NINLIL_V1_LAB_APPLICATION_MAX
        * NINLIL_V1_LAB_ADMISSIONS_PER_WINDOW;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 60000u;
    if (row->family == NINLIL_FAMILY_DESIRED_STATE) {
        descriptor.minimum_deadline_ms = 1u;
        descriptor.maximum_deadline_ms = 60000u;
        descriptor.maximum_evidence_grace_ms =
            NINLIL_V1_LAB_EVIDENCE_GRACE_MAX_MS;
    } else if (row->family == NINLIL_FAMILY_EVENT_FACT) {
        descriptor.minimum_deadline_ms = NINLIL_NO_DEADLINE;
        descriptor.maximum_deadline_ms = NINLIL_NO_DEADLINE;
    } else {
        clear_bytes(&descriptor, sizeof(descriptor));
        return NINLIL_V1_LAB_FABRIC_BINDING;
    }
    *out_descriptor = descriptor;
    clear_bytes(&descriptor, sizeof(descriptor));
    return NINLIL_V1_LAB_FABRIC_OK;
}
