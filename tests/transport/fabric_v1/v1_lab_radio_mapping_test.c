/* SPDX-License-Identifier: Apache-2.0 */
#include "nfl1_codec.h"
#include "r7_crypto_openssl3.h"
#include "v1_lab_binding.h"
#include "v1_lab_radio_mapping.h"

#include "ninlil/fabric_v1.h"
#include "ninlil/platform.h"
#include "ninlil/version.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                   \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "mapping failure %s:%d: %s\n",          \
                __FILE__, __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
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
    fill_bytes(
        endpoint->clock_epoch_id, 16u, (uint8_t)(seed + 0x51u));
    endpoint->clock_trust = NINLIL_CLOCK_TRUSTED;
}

static void fill_row(
    ninlil_v1_lab_service_row_t *row,
    uint8_t slot,
    uint8_t flow,
    uint32_t family,
    uint8_t seed)
{
    (void)memset(row, 0, sizeof(*row));
    row->slot = slot;
    row->flow = flow;
    row->namespace_length = 3u;
    row->service_length = 4u;
    row->schema_length = 2u;
    row->descriptor_revision = (uint64_t)(20u + slot);
    fill_bytes(row->descriptor_digest, 32u, seed);
    row->schema_major = 1u;
    row->schema_minor = 0u;
    row->family = family;
    row->direction = family == NINLIL_FAMILY_DESIRED_STATE
        ? NINLIL_DIRECTION_DOWNLINK
        : NINLIL_DIRECTION_UPLINK;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    row->evidence_grace_ms = family == NINLIL_FAMILY_DESIRED_STATE ? 500u : 0u;
    fill_bytes(row->namespace_id, row->namespace_length, seed);
    fill_bytes(row->service_id, row->service_length, (uint8_t)(seed + 8u));
    fill_bytes(row->schema_id, row->schema_length, (uint8_t)(seed + 16u));
}

static int make_binding(
    ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *binding,
    uint8_t encoded[NINLIL_V1_LAB_BINDING_MAX_BYTES],
    size_t *encoded_length)
{
    (void)memset(binding, 0, sizeof(*binding));
    binding->service_count = 2u;
    binding->pair_generation = 7u;
    fill_endpoint(&binding->endpoint_a, 0x10u);
    fill_endpoint(&binding->endpoint_b, 0x30u);
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
    fill_row(
        &binding->services[0],
        1u,
        NINLIL_V1_LAB_FLOW_A_TO_B,
        NINLIL_FAMILY_DESIRED_STATE,
        0x70u);
    fill_row(
        &binding->services[1],
        2u,
        NINLIL_V1_LAB_FLOW_B_TO_A,
        NINLIL_FAMILY_EVENT_FACT,
        0x80u);
    if (ninlil_v1_lab_binding_finalize(crypto, binding)
            != NINLIL_V1_LAB_BINDING_OK
        || ninlil_v1_lab_binding_encode(
               crypto,
               binding,
               encoded,
               NINLIL_V1_LAB_BINDING_MAX_BYTES,
               encoded_length)
            != NINLIL_V1_LAB_BINDING_OK) {
        return 1;
    }
    return 0;
}

static void set_source(
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

static void set_target(
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

static int make_desired_application(
    ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t transaction_seed,
    uint64_t path_epoch,
    uint32_t required_evidence,
    uint8_t *out,
    uint32_t *out_length)
{
    const ninlil_v1_lab_service_row_t *row = &binding->services[0];
    ninlil_fabric_private_nfl1_envelope_t envelope;
    static const uint8_t payload[] = "display:occupied";
    uint8_t digest[32];

    (void)memset(&envelope, 0, sizeof(envelope));
    envelope.api_version = NINLIL_ABI_VERSION;
    envelope.struct_size = (uint16_t)sizeof(envelope);
    envelope.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    fill_bytes(envelope.transaction_id.bytes, 16u, transaction_seed);
    fill_bytes(
        envelope.attempt_id.bytes, 16u, (uint8_t)(transaction_seed + 0x20u));
    set_source(&envelope, &binding->endpoint_a);
    set_target(&envelope, &binding->endpoint_b);
    (void)memcpy(
        envelope.authority_id.bytes, binding->endpoint_a.runtime_id, 16u);
    envelope.authority_term = binding->pair_generation;
    envelope.assignment_epoch = (uint32_t)binding->pair_generation;
    envelope.descriptor_revision = row->descriptor_revision;
    envelope.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(
        envelope.descriptor_digest.bytes, row->descriptor_digest, 32u);
    envelope.schema_major = row->schema_major;
    envelope.schema_minor = row->schema_minor;
    envelope.family = row->family;
    envelope.content_digest.algorithm = NINLIL_DIGEST_SHA256;
    if (ninlil_r7_crypto_sha256(
            crypto, payload, sizeof(payload) - 1u, digest)
        != NINLIL_R7_CRYPTO_OK) {
        return 1;
    }
    (void)memcpy(envelope.content_digest.bytes, digest, 32u);
    envelope.generation = 42u;
    (void)memcpy(
        envelope.deadline_clock_epoch_id.bytes,
        binding->endpoint_a.clock_epoch_id,
        16u);
    envelope.absolute_effect_deadline_ms = 90000u;
    envelope.evidence_grace_ms = row->evidence_grace_ms;
    envelope.required_evidence = required_evidence;
    (void)memcpy(envelope.route_policy_id.bytes, row->policy_id, 16u);
    envelope.route_policy_revision = binding->pair_generation;
    envelope.route_policy_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(
        envelope.route_policy_digest.bytes, row->path_policy_digest, 32u);
    (void)memcpy(
        envelope.selected_path_id.bytes, row->selected_path_id, 16u);
    envelope.path_selection_epoch = path_epoch;
    envelope.namespace_id.bytes = row->namespace_id;
    envelope.namespace_id.length = row->namespace_length;
    envelope.service_id.bytes = row->service_id;
    envelope.service_id.length = row->service_length;
    envelope.schema_id.bytes = row->schema_id;
    envelope.schema_id.length = row->schema_length;
    envelope.payload.bytes = payload;
    envelope.payload.length = (uint32_t)(sizeof(payload) - 1u);
    return ninlil_fabric_private_nfl1_encode(
               &envelope,
               out,
               NINLIL_V1_LAB_RADIO_NFL1_MAX,
               out_length)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
        ? 0
        : 1;
}

static int make_receipt(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *application,
    uint32_t application_length,
    uint64_t path_epoch,
    uint8_t *out,
    uint32_t *out_length)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint32_t required = 0u;

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    if (ninlil_fabric_private_nfl1_decode(
            application,
            application_length,
            &workspace,
            &envelope,
            &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        return 1;
    }
    envelope.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    set_source(&envelope, &binding->endpoint_b);
    set_target(&envelope, &binding->endpoint_a);
    envelope.receipt_stage = NINLIL_EVIDENCE_APPLIED;
    envelope.payload.bytes = NULL;
    envelope.payload.length = 0u;
    (void)memcpy(
        envelope.evidence_time_clock_epoch_id.bytes,
        binding->endpoint_b.clock_epoch_id,
        16u);
    envelope.evidence_time_now_ms = 1600u;
    envelope.evidence_time_trust = binding->endpoint_b.clock_trust;
    envelope.path_selection_epoch = path_epoch;
    return ninlil_fabric_private_nfl1_encode(
               &envelope,
               out,
               NINLIL_V1_LAB_RADIO_NFL1_MAX,
               out_length)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
        ? 0
        : 1;
}

static void make_now(
    ninlil_time_sample_t *now,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t local_side,
    uint64_t now_ms)
{
    const ninlil_v1_lab_endpoint_t *local =
        local_side == NINLIL_V1_LAB_SIDE_A
        ? &binding->endpoint_a
        : &binding->endpoint_b;

    (void)memset(now, 0, sizeof(*now));
    now->abi_version = NINLIL_ABI_VERSION;
    now->struct_size = (uint16_t)sizeof(*now);
    (void)memcpy(
        now->clock_epoch_id.bytes, local->clock_epoch_id, 16u);
    now->now_ms = now_ms;
    now->trust = NINLIL_CLOCK_TRUSTED;
}

static int test_application_receipt_round_trip(
    ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *encoded_binding,
    size_t encoded_length)
{
    ninlil_v1_lab_radio_mapper_t mapper_a;
    ninlil_v1_lab_radio_mapper_t mapper_b;
    ninlil_time_sample_t now;
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint8_t app_nfl1[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t peer_app_nfl1[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t receipt_nfl1[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t origin_receipt_nfl1[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t body[NINLIL_NRA1_APPLICATION_BODY_MAX];
    uint8_t pair_slot = 0xffu;
    uint8_t flow = 0u;
    uint32_t app_length = 0u;
    uint32_t peer_app_length = 0u;
    uint32_t receipt_length = 0u;
    uint32_t origin_receipt_length = 0u;
    uint32_t receipt_token = 0u;
    uint32_t required = 0u;
    size_t body_length = 0u;

    REQUIRE(ninlil_v1_lab_radio_mapper_init(
                &mapper_a, crypto, binding->endpoint_a.runtime_id)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(ninlil_v1_lab_radio_mapper_init(
                &mapper_b, crypto, binding->endpoint_b.runtime_id)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(ninlil_v1_lab_radio_mapper_install_pair(
                &mapper_a,
                encoded_binding,
                encoded_length,
                &pair_slot)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(pair_slot == 0u);
    REQUIRE(ninlil_v1_lab_radio_mapper_install_pair(
                &mapper_b,
                encoded_binding,
                encoded_length,
                &pair_slot)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(pair_slot == 0u);
    REQUIRE(make_desired_application(
                crypto, binding, 0x01u, 77u, NINLIL_EVIDENCE_APPLIED,
                app_nfl1, &app_length)
        == 0);
    make_now(&now, binding, NINLIL_V1_LAB_SIDE_A, 1000u);
    REQUIRE(ninlil_v1_lab_radio_mapper_encode(
                &mapper_a,
                app_nfl1,
                app_length,
                &now,
                &pair_slot,
                &flow,
                body,
                sizeof(body),
                &body_length)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(pair_slot == 0u);
    REQUIRE(flow == NINLIL_V1_LAB_FLOW_A_TO_B);
    REQUIRE(body_length >= NINLIL_NRA1_APPLICATION_BODY_MIN);

    make_now(&now, binding, NINLIL_V1_LAB_SIDE_B, 1100u);
    REQUIRE(ninlil_v1_lab_radio_mapper_decode(
                &mapper_b,
                0u,
                flow,
                body,
                body_length,
                &now,
                peer_app_nfl1,
                sizeof(peer_app_nfl1),
                &peer_app_length,
                &receipt_token)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(receipt_token == 0u);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    REQUIRE(ninlil_fabric_private_nfl1_decode(
                peer_app_nfl1,
                peer_app_length,
                &workspace,
                &envelope,
                &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    REQUIRE(envelope.path_selection_epoch == binding->pair_generation);
    REQUIRE(envelope.generation == 42u);
    REQUIRE(memcmp(envelope.deadline_clock_epoch_id.bytes,
                binding->endpoint_a.clock_epoch_id, 16u)
        == 0);
    REQUIRE(envelope.payload.length == sizeof("display:occupied") - 1u);
    REQUIRE(memcmp(envelope.payload.bytes, "display:occupied",
                sizeof("display:occupied") - 1u)
        == 0);

    REQUIRE(make_receipt(
                binding,
                peer_app_nfl1,
                peer_app_length,
                91u,
                receipt_nfl1,
                &receipt_length)
        == 0);
    make_now(&now, binding, NINLIL_V1_LAB_SIDE_B, 1200u);
    REQUIRE(ninlil_v1_lab_radio_mapper_encode(
                &mapper_b,
                receipt_nfl1,
                receipt_length,
                &now,
                &pair_slot,
                &flow,
                body,
                sizeof(body),
                &body_length)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(flow == NINLIL_V1_LAB_FLOW_B_TO_A);

    make_now(&now, binding, NINLIL_V1_LAB_SIDE_A, 1300u);
    REQUIRE(ninlil_v1_lab_radio_mapper_decode(
                &mapper_a,
                0u,
                flow,
                body,
                body_length,
                &now,
                origin_receipt_nfl1,
                sizeof(origin_receipt_nfl1),
                &origin_receipt_length,
                &receipt_token)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(receipt_token != 0u);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    REQUIRE(ninlil_fabric_private_nfl1_decode(
                origin_receipt_nfl1,
                origin_receipt_length,
                &workspace,
                &envelope,
                &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    REQUIRE(envelope.message_kind == NINLIL_BEARER_MESSAGE_RECEIPT);
    REQUIRE(envelope.path_selection_epoch == 77u);
    REQUIRE(envelope.receipt_stage == NINLIL_EVIDENCE_APPLIED);
    REQUIRE(memcmp(envelope.deadline_clock_epoch_id.bytes,
                binding->endpoint_a.clock_epoch_id, 16u)
        == 0);
    REQUIRE(memcmp(envelope.evidence_time_clock_epoch_id.bytes,
                binding->endpoint_b.clock_epoch_id, 16u)
        == 0);
    REQUIRE(memcmp(
                envelope.source_runtime_id.bytes,
                binding->endpoint_b.runtime_id,
                16u)
        == 0);
    REQUIRE(ninlil_v1_lab_radio_mapper_commit_received(
                &mapper_a, receipt_token)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(ninlil_v1_lab_radio_mapper_decode(
                &mapper_a,
                0u,
                flow,
                body,
                body_length,
                &now,
                origin_receipt_nfl1,
                sizeof(origin_receipt_nfl1),
                &origin_receipt_length,
                &receipt_token)
        == NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND);

    ninlil_v1_lab_radio_mapper_clear(&mapper_a);
    ninlil_v1_lab_radio_mapper_clear(&mapper_b);
    return 0;
}

static int test_conflict_expiry_and_clock_fence(
    ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *encoded_binding,
    size_t encoded_length)
{
    ninlil_v1_lab_radio_mapper_t mapper;
    ninlil_time_sample_t now;
    uint8_t packet[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t changed[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t decoded[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t body[NINLIL_NRA1_APPLICATION_BODY_MAX];
    uint8_t receipt_body[NINLIL_NRA1_RECEIPT_BODY_BYTES];
    uint8_t pair_slot = 0u;
    uint8_t flow = 0u;
    uint32_t packet_length = 0u;
    uint32_t changed_length = 0u;
    uint32_t decoded_length = 0u;
    uint32_t receipt_token = 0u;
    size_t body_length = 0u;
    size_t receipt_body_length = 0u;
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    uint32_t required = 0u;

    REQUIRE(ninlil_v1_lab_radio_mapper_init(
                &mapper, crypto, binding->endpoint_a.runtime_id)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(ninlil_v1_lab_radio_mapper_install_pair(
                &mapper,
                encoded_binding,
                encoded_length,
                &pair_slot)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(make_desired_application(
                crypto, binding, 0x41u, 100u, NINLIL_EVIDENCE_APPLIED,
                packet, &packet_length)
        == 0);
    make_now(&now, binding, NINLIL_V1_LAB_SIDE_A, 2000u);
    REQUIRE(ninlil_v1_lab_radio_mapper_encode(
                &mapper,
                packet,
                packet_length,
                &now,
                &pair_slot,
                &flow,
                body,
                sizeof(body),
                &body_length)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(ninlil_v1_lab_radio_mapper_decode(
                &mapper,
                0u,
                NINLIL_V1_LAB_FLOW_B_TO_A,
                body,
                body_length,
                &now,
                decoded,
                sizeof(decoded),
                &decoded_length,
                &receipt_token)
        == NINLIL_V1_LAB_RADIO_MAPPING_BINDING);
    REQUIRE(ninlil_v1_lab_radio_mapper_encode(
                &mapper,
                packet,
                packet_length,
                &now,
                &pair_slot,
                &flow,
                body,
                sizeof(body),
                &body_length)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);

    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    REQUIRE(ninlil_fabric_private_nfl1_decode(
                packet,
                packet_length,
                &workspace,
                &envelope,
                &required)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    envelope.path_selection_epoch = 101u;
    REQUIRE(ninlil_fabric_private_nfl1_encode(
                &envelope,
                changed,
                sizeof(changed),
                &changed_length)
        == NINLIL_FABRIC_PRIVATE_NFL1_OK);
    REQUIRE(ninlil_v1_lab_radio_mapper_encode(
                &mapper,
                changed,
                changed_length,
                &now,
                &pair_slot,
                &flow,
                body,
                sizeof(body),
                &body_length)
        == NINLIL_V1_LAB_RADIO_MAPPING_CONFLICT);

    {
        ninlil_nra1_receipt_t receipt;
        (void)memset(&receipt, 0, sizeof(receipt));
        receipt.service_slot = 1u;
        receipt.receipt_stage = NINLIL_EVIDENCE_APPLIED;
        (void)memcpy(
            receipt.transaction_id, envelope.transaction_id.bytes, 16u);
        (void)memcpy(receipt.attempt_id, envelope.attempt_id.bytes, 16u);
        receipt.evidence_time_now_ms = 3000u;
        REQUIRE(ninlil_nra1_encode_receipt(
                    &receipt,
                    receipt_body,
                    sizeof(receipt_body),
                    &receipt_body_length)
            == NINLIL_NRA1_OK);
    }
    make_now(&now, binding, NINLIL_V1_LAB_SIDE_A, 32000u);
    REQUIRE(ninlil_v1_lab_radio_mapper_decode(
                &mapper,
                0u,
                NINLIL_V1_LAB_FLOW_B_TO_A,
                receipt_body,
                receipt_body_length,
                &now,
                decoded,
                sizeof(decoded),
                &decoded_length,
                &receipt_token)
        == NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND);

    make_now(&now, binding, NINLIL_V1_LAB_SIDE_A, 31999u);
    REQUIRE(ninlil_v1_lab_radio_mapper_encode(
                &mapper,
                packet,
                packet_length,
                &now,
                &pair_slot,
                &flow,
                body,
                sizeof(body),
                &body_length)
        == NINLIL_V1_LAB_RADIO_MAPPING_FENCED);
    REQUIRE(ninlil_v1_lab_radio_mapper_remove_pair(&mapper, 0u)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    ninlil_v1_lab_radio_mapper_clear(&mapper);
    return 0;
}

static int test_none_evidence_does_not_consume_correlations(
    ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *encoded_binding,
    size_t encoded_length)
{
    ninlil_v1_lab_radio_mapper_t mapper;
    ninlil_time_sample_t now;
    uint8_t packet[NINLIL_V1_LAB_RADIO_NFL1_MAX];
    uint8_t body[NINLIL_NRA1_APPLICATION_BODY_MAX];
    uint8_t pair_slot = 0u;
    uint8_t flow = 0u;
    uint32_t packet_length = 0u;
    size_t body_length = 0u;
    uint8_t i;

    REQUIRE(ninlil_v1_lab_radio_mapper_init(
                &mapper, crypto, binding->endpoint_a.runtime_id)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    REQUIRE(ninlil_v1_lab_radio_mapper_install_pair(
                &mapper, encoded_binding, encoded_length, &pair_slot)
        == NINLIL_V1_LAB_RADIO_MAPPING_OK);
    for (i = 0u; i < 8u; ++i) {
        REQUIRE(make_desired_application(crypto, binding,
                    (uint8_t)(0x81u + i), (uint64_t)(200u + i),
                    NINLIL_EVIDENCE_NONE, packet, &packet_length)
            == 0);
        make_now(&now, binding, NINLIL_V1_LAB_SIDE_A,
            (uint64_t)(4000u + i));
        REQUIRE(ninlil_v1_lab_radio_mapper_encode(&mapper, packet,
                    packet_length, &now, &pair_slot, &flow, body,
                    sizeof(body), &body_length)
            == NINLIL_V1_LAB_RADIO_MAPPING_OK);
        REQUIRE(flow == NINLIL_V1_LAB_FLOW_A_TO_B);
    }
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_CORRELATION_MAX; ++i) {
        REQUIRE(mapper.correlations[i].active == 0u);
    }
    ninlil_v1_lab_radio_mapper_clear(&mapper);
    return 0;
}

int main(void)
{
    ninlil_r7_crypto_provider crypto;
    ninlil_v1_lab_binding_t binding;
    uint8_t encoded[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    size_t encoded_length = 0u;

    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&crypto)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(make_binding(&crypto, &binding, encoded, &encoded_length) == 0);
    REQUIRE(test_application_receipt_round_trip(
                &crypto, &binding, encoded, encoded_length)
        == 0);
    REQUIRE(test_conflict_expiry_and_clock_fence(
                &crypto, &binding, encoded, encoded_length)
        == 0);
    REQUIRE(test_none_evidence_does_not_consume_correlations(
                &crypto, &binding, encoded, encoded_length)
        == 0);
    ninlil_v1_lab_binding_clear(&binding);
    (void)fprintf(stdout, "v1_lab_radio_mapping_test OK\n");
    return 0;
}
