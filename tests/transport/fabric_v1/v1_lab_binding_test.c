#include "fabric_private_records.h"
#include "nfl1_codec.h"
#include "r7_crypto_openssl3.h"
#include "v1_lab_binding.h"
#include "v1_lab_fabric.h"

#include "ninlil/fabric_v1.h"
#include "ninlil/platform.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static uint8_t hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    return (uint8_t)(value - 'a' + 10);
}

static int matches_hex(
    const uint8_t *bytes, size_t length, const char *expected)
{
    size_t i;

    for (i = 0u; i < length; ++i) {
        uint8_t high = hex_nibble(expected[i * 2u]);
        uint8_t low = hex_nibble(expected[i * 2u + 1u]);
        if (bytes[i] != (uint8_t)((high << 4u) | low)) {
            return 0;
        }
    }
    return expected[length * 2u] == '\0';
}

static void fill_endpoint(
    ninlil_v1_lab_endpoint_t *endpoint, uint8_t seed)
{
    (void)memset(endpoint, 0, sizeof(*endpoint));
    fill_bytes(endpoint->runtime_id, 16u, seed);
    fill_bytes(endpoint->application_id, 16u, (uint8_t)(seed + 0x10u));
    fill_bytes(endpoint->device_id, 16u, (uint8_t)(seed + 0x20u));
    fill_bytes(endpoint->installation_id, 16u, (uint8_t)(seed + 0x30u));
    fill_bytes(endpoint->site_id, 16u, (uint8_t)(seed + 0x40u));
    endpoint->binding_epoch = 4u;
    endpoint->membership_epoch = 9u;
    endpoint->identity_flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    fill_bytes(endpoint->clock_epoch_id, 16u, (uint8_t)(seed + 0x50u));
    endpoint->clock_trust = NINLIL_CLOCK_TRUSTED;
}

static void fill_text(
    uint8_t out[NINLIL_V1_LAB_TEXT_MAX], uint8_t length, uint8_t seed)
{
    (void)memset(out, 0, NINLIL_V1_LAB_TEXT_MAX);
    fill_bytes(out, length, seed);
}

static void fill_row(
    ninlil_v1_lab_service_row_t *row, uint8_t index, uint8_t text_length)
{
    uint8_t seed = (uint8_t)(0x70u + index * 7u);

    (void)memset(row, 0, sizeof(*row));
    row->slot = (uint8_t)(index + 1u);
    row->namespace_length = text_length;
    row->service_length = text_length;
    row->schema_length = text_length;
    row->descriptor_revision = (uint64_t)(10u + index);
    fill_bytes(row->descriptor_digest, 32u, seed);
    row->schema_major = 1u;
    row->schema_minor = index;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    if (index == 1u) {
        row->flow = NINLIL_V1_LAB_FLOW_B_TO_A;
        row->family = NINLIL_FAMILY_EVENT_FACT;
        row->direction = NINLIL_DIRECTION_UPLINK;
        row->evidence_grace_ms = 0u;
    } else {
        row->flow = NINLIL_V1_LAB_FLOW_A_TO_B;
        row->family = NINLIL_FAMILY_DESIRED_STATE;
        row->direction = NINLIL_DIRECTION_DOWNLINK;
        row->evidence_grace_ms = 500u;
    }
    fill_text(row->namespace_id, text_length, seed);
    fill_text(row->service_id, text_length, (uint8_t)(seed + 1u));
    fill_text(row->schema_id, text_length, (uint8_t)(seed + 2u));
}

static void fill_binding(
    ninlil_v1_lab_binding_t *binding,
    uint8_t service_count,
    uint8_t text_length)
{
    uint8_t i;

    (void)memset(binding, 0, sizeof(*binding));
    binding->service_count = service_count;
    binding->pair_generation = 3u;
    fill_endpoint(&binding->endpoint_a, 0x10u);
    fill_endpoint(&binding->endpoint_b, 0x30u);
    (void)memcpy(
        binding->endpoint_b.clock_epoch_id,
        binding->endpoint_a.clock_epoch_id,
        16u);
    fill_bytes(binding->radio_site_domain_id, 16u, 0x90u);
    binding->radio_membership_epoch = 11u;
    binding->a_to_b_hop_context_id = 1u;
    binding->a_to_b_e2e_context_id = 2u;
    binding->b_to_a_hop_context_id = 3u;
    binding->b_to_a_e2e_context_id = 4u;
    fill_bytes(binding->a_to_b_hop_secret, 32u, 0xa0u);
    fill_bytes(binding->a_to_b_e2e_secret, 32u, 0xb0u);
    fill_bytes(binding->b_to_a_hop_secret, 32u, 0xc0u);
    fill_bytes(binding->b_to_a_e2e_secret, 32u, 0xd0u);
    for (i = 0u; i < service_count; ++i) {
        fill_row(&binding->services[i], i, text_length);
    }
}

static int verify_existing_canonical_helpers(
    const ninlil_v1_lab_binding_t *binding, uint8_t row_index)
{
    const ninlil_v1_lab_service_row_t *row = &binding->services[row_index];
    ninlil_fabric_private_fbp1_t policy;
    uint8_t service_digest[32];

    ninlil_fabric_private_nfl1_service_identity_digest(
        row->namespace_id,
        row->namespace_length,
        row->service_id,
        row->service_length,
        row->schema_id,
        row->schema_length,
        row->descriptor_revision,
        row->descriptor_digest,
        row->schema_major,
        row->schema_minor,
        row->family,
        service_digest);
    REQUIRE(memcmp(service_digest, row->service_identity_digest, 32u) == 0);

    (void)memset(&policy, 0, sizeof(policy));
    (void)memcpy(policy.policy_id, row->policy_id, 16u);
    policy.revision = binding->pair_generation;
    (void)memcpy(
        policy.service_identity_digest, row->service_identity_digest, 32u);
    policy.family = row->family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_RESERVATION
        | NINLIL_FABRIC_CAP_REGULATED_RF | NINLIL_FABRIC_CAP_EVIDENCE;
    policy.required_security_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.candidate_count = 1u;
    (void)memcpy(
        policy.candidates[0].instance_id, row->selected_path_id, 16u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;
    ninlil_fabric_private_fbp1_compute_digest(&policy);
    REQUIRE(memcmp(policy.canonical_digest, row->path_policy_digest, 32u) == 0);
    return 0;
}

static int test_minimum_round_trip(ninlil_r7_crypto_provider *crypto)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_binding_t decoded;
    uint8_t encoded[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    size_t encoded_length = 0u;
    uint8_t side = 0u;

    fill_binding(&binding, 1u, 1u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(binding.raw_length == NINLIL_V1_LAB_BINDING_MIN_BYTES);
    REQUIRE(binding.controller_side == NINLIL_V1_LAB_SIDE_A);
    REQUIRE(verify_existing_canonical_helpers(&binding, 0u) == 0);
    REQUIRE(ninlil_v1_lab_binding_encode(
                crypto, &binding, encoded, sizeof(encoded), &encoded_length)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(encoded_length == NINLIL_V1_LAB_BINDING_MIN_BYTES);
    (void)memset(&decoded, 0, sizeof(decoded));
    REQUIRE(ninlil_v1_lab_binding_decode(
                crypto, encoded, encoded_length, &decoded)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(decoded.raw_length == encoded_length);
    REQUIRE(memcmp(decoded.raw, encoded, encoded_length) == 0);
    REQUIRE(memcmp(decoded.pair_id, binding.pair_id, 32u) == 0);
    REQUIRE(memcmp(
                decoded.pair_binding_digest,
                binding.pair_binding_digest,
                32u)
        == 0);
    REQUIRE(memcmp(decoded.e2e_security_id, binding.e2e_security_id, 32u)
        == 0);
    REQUIRE(ninlil_v1_lab_binding_local_side(
                &decoded, decoded.endpoint_b.runtime_id, &side)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(side == NINLIL_V1_LAB_SIDE_B);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_v1_lab_binding_clear(&decoded);
    return 0;
}

static int test_maximum_and_e2e_projection(
    ninlil_r7_crypto_provider *crypto)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_binding_t hop_rotated;
    ninlil_v1_lab_binding_t e2e_rotated;

    fill_binding(&binding, 3u, 16u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(binding.raw_length == NINLIL_V1_LAB_BINDING_MAX_BYTES);
    REQUIRE(verify_existing_canonical_helpers(&binding, 0u) == 0);
    REQUIRE(verify_existing_canonical_helpers(&binding, 1u) == 0);
    REQUIRE(verify_existing_canonical_helpers(&binding, 2u) == 0);

    hop_rotated = binding;
    hop_rotated.a_to_b_hop_context_id = 20u;
    fill_bytes(hop_rotated.a_to_b_hop_secret, 32u, 0x33u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &hop_rotated)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(memcmp(
                hop_rotated.e2e_security_id, binding.e2e_security_id, 32u)
        == 0);
    REQUIRE(memcmp(
                hop_rotated.pair_binding_digest,
                binding.pair_binding_digest,
                32u)
        != 0);

    e2e_rotated = binding;
    e2e_rotated.a_to_b_e2e_context_id = 21u;
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &e2e_rotated)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(memcmp(
                e2e_rotated.e2e_security_id, binding.e2e_security_id, 32u)
        != 0);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_v1_lab_binding_clear(&hop_rotated);
    ninlil_v1_lab_binding_clear(&e2e_rotated);
    return 0;
}

static int test_rejection_is_atomic(ninlil_r7_crypto_provider *crypto)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_binding_t output;
    ninlil_v1_lab_binding_t before;
    uint8_t encoded[NINLIL_V1_LAB_BINDING_MAX_BYTES + 1u];

    fill_binding(&binding, 1u, 1u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    (void)memcpy(encoded, binding.raw, binding.raw_length);
    (void)memset(&output, 0xa5, sizeof(output));
    before = output;
    encoded[2] = 1u;
    REQUIRE(ninlil_v1_lab_binding_decode(
                crypto, encoded, binding.raw_length, &output)
        == NINLIL_V1_LAB_BINDING_STRUCTURAL);
    REQUIRE(memcmp(&output, &before, sizeof(output)) == 0);
    encoded[2] = 0u;
    encoded[420u + 70u] ^= 1u;
    REQUIRE(ninlil_v1_lab_binding_decode(
                crypto, encoded, binding.raw_length, &output)
        == NINLIL_V1_LAB_BINDING_DIGEST);
    REQUIRE(memcmp(&output, &before, sizeof(output)) == 0);
    encoded[420u + 70u] ^= 1u;
    encoded[binding.raw_length] = 0u;
    REQUIRE(ninlil_v1_lab_binding_decode(
                crypto, encoded, binding.raw_length + 1u, &output)
        == NINLIL_V1_LAB_BINDING_LENGTH);
    REQUIRE(memcmp(&output, &before, sizeof(output)) == 0);
    REQUIRE(ninlil_v1_lab_binding_decode(
                crypto, binding.raw, binding.raw_length, &binding)
        == NINLIL_V1_LAB_BINDING_ALIAS);

    fill_binding(&binding, 2u, 1u);
    binding.services[1].flow = NINLIL_V1_LAB_FLOW_A_TO_B;
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_SEMANTIC);
    fill_binding(&binding, 1u, 1u);
    (void)memset(binding.endpoint_b.clock_epoch_id, 0, 16u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_STRUCTURAL);
    fill_binding(&binding, 1u, 1u);
    binding.endpoint_b.runtime_id[0] = 1u;
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_STRUCTURAL);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_v1_lab_binding_clear(&output);
    ninlil_v1_lab_binding_clear(&before);
    return 0;
}

static int test_distinct_endpoint_clock_epochs(
    ninlil_r7_crypto_provider *crypto)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_fabric_link_descriptor_v1_t descriptor_a;
    ninlil_fabric_link_descriptor_v1_t descriptor_b;
    ninlil_fabric_link_state_v1_t state_a;
    ninlil_fabric_link_state_v1_t state_b;
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_authority_binding_v1_t authority_a;
    ninlil_fabric_authority_binding_v1_t authority_b;

    fill_binding(&binding, 2u, 4u);
    binding.endpoint_b.clock_epoch_id[0] ^= 0x5au;
    REQUIRE(memcmp(binding.endpoint_a.clock_epoch_id,
                binding.endpoint_b.clock_epoch_id, 16u)
        != 0);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_fabric_build_path(crypto, &binding,
                binding.endpoint_a.runtime_id,
                NINLIL_V1_LAB_FLOW_A_TO_B, &descriptor_a, &state_a)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(ninlil_v1_lab_fabric_build_path(crypto, &binding,
                binding.endpoint_b.runtime_id,
                NINLIL_V1_LAB_FLOW_A_TO_B, &descriptor_b, &state_b)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(memcmp(descriptor_a.attestation_clock_epoch_id.bytes,
                binding.endpoint_a.clock_epoch_id, 16u)
        == 0);
    REQUIRE(memcmp(state_a.availability_clock_epoch_id.bytes,
                binding.endpoint_a.clock_epoch_id, 16u)
        == 0);
    REQUIRE(memcmp(descriptor_b.attestation_clock_epoch_id.bytes,
                binding.endpoint_b.clock_epoch_id, 16u)
        == 0);
    REQUIRE(memcmp(state_b.availability_clock_epoch_id.bytes,
                binding.endpoint_b.clock_epoch_id, 16u)
        == 0);
    REQUIRE(ninlil_v1_lab_fabric_build_service(crypto, &binding,
                binding.endpoint_a.runtime_id, 0u, &policy, &authority_a)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(ninlil_v1_lab_fabric_build_service(crypto, &binding,
                binding.endpoint_b.runtime_id, 0u, &policy, &authority_b)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(memcmp(authority_a.authority_clock_epoch_id.bytes,
                binding.endpoint_a.clock_epoch_id, 16u)
        == 0);
    REQUIRE(memcmp(authority_b.authority_clock_epoch_id.bytes,
                binding.endpoint_b.clock_epoch_id, 16u)
        == 0);
    REQUIRE(memcmp(authority_a.binding_id.bytes,
                authority_b.binding_id.bytes, 16u)
        == 0);
    ninlil_v1_lab_binding_clear(&binding);
    return 0;
}

static int test_closed_fabric_builder(ninlil_r7_crypto_provider *crypto)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_fabric_link_descriptor_v1_t descriptor_a;
    ninlil_fabric_link_descriptor_v1_t descriptor_b;
    ninlil_fabric_link_state_v1_t state_a;
    ninlil_fabric_link_state_v1_t state_b;
    ninlil_fabric_path_policy_v1_t policy_0;
    ninlil_fabric_path_policy_v1_t policy_0_b;
    ninlil_fabric_path_policy_v1_t policy_2;
    ninlil_fabric_authority_binding_v1_t authority_0;
    ninlil_fabric_authority_binding_v1_t authority_0_b;
    ninlil_fabric_authority_binding_v1_t authority_2;
    ninlil_fabric_link_descriptor_v1_t descriptor_kat;
    ninlil_fabric_link_descriptor_v1_t descriptor_before;
    ninlil_fabric_link_state_v1_t state_before;

    fill_binding(&binding, 3u, 16u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(memcmp(
                binding.services[0].selected_path_id,
                binding.services[2].selected_path_id,
                16u)
        == 0);
    REQUIRE(ninlil_v1_lab_fabric_build_path(
                crypto,
                &binding,
                binding.endpoint_a.runtime_id,
                NINLIL_V1_LAB_FLOW_A_TO_B,
                &descriptor_a,
                &state_a)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(ninlil_v1_lab_fabric_build_path(
                crypto,
                &binding,
                binding.endpoint_b.runtime_id,
                NINLIL_V1_LAB_FLOW_A_TO_B,
                &descriptor_b,
                &state_b)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(memcmp(
                descriptor_a.instance_id.bytes,
                binding.services[0].selected_path_id,
                16u)
        == 0);
    REQUIRE(memcmp(
                descriptor_b.instance_id.bytes,
                binding.services[0].selected_path_id,
                16u)
        == 0);
    REQUIRE(memcmp(
                descriptor_a.authenticated_peer_runtime_id.bytes,
                binding.endpoint_b.runtime_id,
                16u)
        == 0);
    REQUIRE(memcmp(
                descriptor_b.authenticated_peer_runtime_id.bytes,
                binding.endpoint_a.runtime_id,
                16u)
        == 0);
    REQUIRE(memcmp(descriptor_a.descriptor_digest, descriptor_b.descriptor_digest, 32u)
        != 0);
    REQUIRE(descriptor_a.api_version == NINLIL_FABRIC_API_VERSION);
    REQUIRE(descriptor_a.struct_size == sizeof(descriptor_a));
    REQUIRE(descriptor_a.link_kind == NINLIL_FABRIC_LINK_KIND_RF);
    REQUIRE(descriptor_a.direction_mask
        == (NINLIL_FABRIC_LINK_DIRECTION_SEND
            | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE));
    REQUIRE(descriptor_a.capability_flags
        == (NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
            | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_RESERVATION
            | NINLIL_FABRIC_CAP_REGULATED_RF
            | NINLIL_FABRIC_CAP_EVIDENCE));
    REQUIRE(descriptor_a.security_capability_flags
        == (NINLIL_FABRIC_SECURITY_INTEGRITY
            | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
            | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
            | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS));
    REQUIRE(descriptor_a.maximum_packet_bytes
        == NINLIL_V1_LAB_FABRIC_PACKET_MAX);
    REQUIRE(descriptor_a.maximum_transfer_bytes
        == NINLIL_V1_LAB_FABRIC_PACKET_MAX);
    REQUIRE(descriptor_a.reservation_capacity == 1u);
    REQUIRE(descriptor_a.peer_nfl1_version == 1u);
    REQUIRE(descriptor_a.peer_fabric_capability_flags
        == NINLIL_FABRIC_PEER_CAP_NFL1_V1);
    REQUIRE(state_a.available == 1u && state_b.available == 1u);
    REQUIRE(state_a.available_until_ms == UINT64_MAX);
    REQUIRE(state_b.available_until_ms == UINT64_MAX);

    REQUIRE(ninlil_v1_lab_fabric_build_service(
                crypto,
                &binding,
                binding.endpoint_a.runtime_id,
                0u,
                &policy_0,
                &authority_0)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(ninlil_v1_lab_fabric_build_service(
                crypto,
                &binding,
                binding.endpoint_b.runtime_id,
                0u,
                &policy_0_b,
                &authority_0_b)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(ninlil_v1_lab_fabric_build_service(
                crypto,
                &binding,
                binding.endpoint_b.runtime_id,
                2u,
                &policy_2,
                &authority_2)
        == NINLIL_V1_LAB_FABRIC_OK);
    REQUIRE(memcmp(
                policy_0.candidates[0].instance_id.bytes,
                policy_2.candidates[0].instance_id.bytes,
                16u)
        == 0);
    REQUIRE(memcmp(policy_0.policy_id.bytes, policy_2.policy_id.bytes, 16u)
        != 0);
    REQUIRE(memcmp(&policy_0, &policy_0_b, sizeof(policy_0)) == 0);
    REQUIRE(memcmp(&authority_0, &authority_0_b, sizeof(authority_0)) == 0);
    REQUIRE(policy_0.direction == NINLIL_FABRIC_POLICY_DIRECTION_FORWARD);
    REQUIRE(policy_0.traffic_class == NINLIL_FABRIC_TRAFFIC_APPLICATION);
    REQUIRE(policy_0.scope_selector == NINLIL_FABRIC_SCOPE_TARGET_RUNTIME);
    REQUIRE(policy_0.minimum_packet_bytes == 587u);
    REQUIRE(policy_0.authority_mode
        == NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED);
    REQUIRE(policy_0.candidate_count == 1u);
    REQUIRE(policy_0.candidates[0].rank == 1u);
    REQUIRE(policy_0.candidates[0].reservation_units == 1u);
    REQUIRE(memcmp(
                authority_0.endpoint_runtime_id.bytes,
                binding.endpoint_b.runtime_id,
                16u)
        == 0);
    REQUIRE(memcmp(authority_0.target_runtime_id.bytes, binding.endpoint_b.runtime_id, 16u)
        == 0);
    REQUIRE(memcmp(
                authority_0.target_application_id.bytes,
                binding.endpoint_b.application_id,
                16u)
        == 0);
    REQUIRE(memcmp(authority_0.owner_tuple_canonical, "NVO1", 4u) == 0);
    REQUIRE(authority_0.owner_tuple_canonical[4] == 1u);
    REQUIRE(authority_0.owner_tuple_canonical[5]
        == NINLIL_V1_LAB_FLOW_A_TO_B);
    REQUIRE(authority_0.owner_tuple_canonical[6] == 1u);
    REQUIRE(authority_0.owner_tuple_canonical[7] == 0u);
    REQUIRE(authority_0.authority_state == NINLIL_FABRIC_AUTHORITY_BOUND);
    REQUIRE(authority_0.authority_term == binding.pair_generation);
    REQUIRE(authority_0.assignment_epoch == binding.pair_generation);
    REQUIRE(authority_0.assignment_revision == binding.pair_generation);
    REQUIRE(authority_0.lease_expires_at_ms == UINT64_MAX);

    descriptor_kat = descriptor_a;
    (void)memset(&descriptor_a, 0xa5, sizeof(descriptor_a));
    (void)memset(&state_a, 0x5a, sizeof(state_a));
    descriptor_before = descriptor_a;
    state_before = state_a;
    REQUIRE(ninlil_v1_lab_fabric_build_path(
                crypto,
                &binding,
                binding.endpoint_a.runtime_id,
                0xffu,
                &descriptor_a,
                &state_a)
        == NINLIL_V1_LAB_FABRIC_FLOW);
    REQUIRE(memcmp(&descriptor_a, &descriptor_before, sizeof(descriptor_a))
        == 0);
    REQUIRE(memcmp(&state_a, &state_before, sizeof(state_a)) == 0);

    REQUIRE(matches_hex(
        binding.pair_id,
        32u,
        "7e0718528c0554488488ed01f7d5e76b6bc1f735c2f166adbebdf69d50c0b2a3"));
    REQUIRE(matches_hex(
        binding.pair_binding_digest,
        32u,
        "0391877581dc07bd25d34c396bca9cb3baded9d42e8926c92bc97e118a026725"));
    REQUIRE(matches_hex(
        binding.e2e_security_id,
        32u,
        "0efb78cccd9f100daf61813ff11bbbe84469494d1de1cda54686e237329ef36d"));
    REQUIRE(matches_hex(
        binding.services[0].selected_path_id,
        16u,
        "c8797b99bbfaff4acf0c4d9014f67536"));
    REQUIRE(matches_hex(
        descriptor_kat.descriptor_digest,
        32u,
        "1e9514d40c399426d26be888d86d927110549313cf4c18fdb445c82e82e4f31d"));
    REQUIRE(matches_hex(
        descriptor_kat.security_profile_id.bytes,
        16u,
        "0f14bb276f3ad9bb59a12e67a1e4b6ab"));
    REQUIRE(matches_hex(
        descriptor_kat.security_binding_digest,
        32u,
        "87c6cfcd3f1356eb93c2b6c7ef376b3f5f4fe0a8fa71a1b9d5bf3fa294ca42fe"));
    REQUIRE(matches_hex(
        descriptor_kat.attestation_digest,
        32u,
        "ea948352338fbab99b329546dcaa4420cce195252f59de8df7c5f049972d8964"));
    REQUIRE(matches_hex(
        descriptor_kat.configuration_digest,
        32u,
        "632edeeeb1931726a2f1d496978cb16756d79d7de0e3cf4b12cba548ddafaa96"));
    REQUIRE(matches_hex(
        policy_0.policy_id.bytes,
        16u,
        "87531761f36d0138502aac242b8c8dc6"));
    REQUIRE(matches_hex(
        binding.services[0].service_identity_digest,
        32u,
        "becfb5f291c7e53009fdf78b3bc9a67e162ca4d127f303fc7b0e602b3a5c7073"));
    REQUIRE(matches_hex(
        binding.services[0].path_policy_digest,
        32u,
        "1f5c94fe99194d6faf326ac612d538e354f8e94dc8a77a239086f9ea7706c052"));
    REQUIRE(matches_hex(
        authority_0.binding_id.bytes,
        16u,
        "277c2836b351f5f7fc21b43b378c0f0a"));
    REQUIRE(matches_hex(
        authority_0.owner_tuple_digest,
        32u,
        "bd823e8e42c4ca114314cfc8f908dbfff9ec710be397d9db08e7e73dc6fdfbf2"));

    ninlil_v1_lab_binding_clear(&binding);
    return 0;
}

int main(void)
{
    ninlil_r7_crypto_provider crypto;

    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&crypto)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(test_minimum_round_trip(&crypto) == 0);
    REQUIRE(test_maximum_and_e2e_projection(&crypto) == 0);
    REQUIRE(test_rejection_is_atomic(&crypto) == 0);
    REQUIRE(test_distinct_endpoint_clock_epochs(&crypto) == 0);
    REQUIRE(test_closed_fabric_builder(&crypto) == 0);
    (void)fprintf(stdout, "v1_lab_binding_test OK\n");
    return 0;
}
