/* SPDX-License-Identifier: Apache-2.0 */
/*
 * FBM1/FBR1/FBP1/FBC1/FBA1/FBT1 codecs, keys, digests, CRC, COMMIT_UNKNOWN.
 */
#include "fabric_v1_test_common.h"

static int test_meta_roundtrip(void)
{
    ninlil_fabric_private_fbm1_t in;
    ninlil_fabric_private_fbm1_t out;
    uint8_t payload[40];
    uint8_t value[64];
    uint8_t key[4];
    uint32_t vlen = 0u;
    ninlil_fabric_private_common_envelope_t env;
    const uint8_t *pl = NULL;

    ninlil_fabric_private_memzero(&in, sizeof(in));
    in.source_schema = 1u;
    in.target_schema = 1u;
    in.migration_state = 1u;
    in.migration_generation = 1u;
    in.outer_availability_epoch = 1u;
    in.outer_available = 0u;
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_fbm1_encode(&in, payload),
        NINLIL_FABRIC_PRIVATE_RECORD_OK);
    ninlil_fabric_private_key_fbm1(key);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_record_encode_envelope(
            key, 1u, payload, 40u, value, 64u, &vlen),
        NINLIL_FABRIC_PRIVATE_RECORD_OK);
    FABRIC_REQUIRE_EQ_U32(vlen, 64u);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_record_decode_envelope(
            value, vlen, key, 40u, &env, &pl),
        NINLIL_FABRIC_PRIVATE_RECORD_OK);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_fbm1_decode(pl, &out),
        NINLIL_FABRIC_PRIVATE_RECORD_OK);
    FABRIC_REQUIRE_EQ_U32(out.outer_availability_epoch, 1u);

    /* CRC mutation */
    value[20] ^= 0xffu;
    FABRIC_REQUIRE(
        ninlil_fabric_private_record_decode_envelope(
            value, vlen, key, 40u, &env, &pl)
        == NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT);
    return 0;
}

static int test_registry_and_policy_digests(void)
{
    ninlil_fabric_private_fbr1_t reg;
    ninlil_fabric_private_fbp1_t pol;
    uint8_t payload[348];
    uint8_t value[372];
    uint8_t key[20];
    uint8_t dig[32];
    uint32_t vlen = 0u;
    uint8_t magic[4] = { 'F', 'B', 'R', '1' };

    ninlil_fabric_private_memzero(&reg, sizeof(reg));
    fabric_test_pattern(reg.instance_id, 0x61u, 16u);
    reg.link_kind = 2u;
    reg.direction_mask = 3u;
    reg.capability_flags = 0x6Fu;
    reg.descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-descriptor-v1", 29u,
        reg.descriptor_digest);
    fabric_test_pattern(reg.security_profile_id, 0x21u, 16u);
    reg.security_capability_flags = 0x0Fu;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-binding-v1", 26u,
        reg.security_binding_digest);
    reg.attestation_epoch = 5u;
    fabric_test_pattern(reg.attestation_clock_epoch_id, 0xA1u, 16u);
    reg.attestation_expires_at_ms = 300000u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-attestation-v1", 30u,
        reg.attestation_digest);
    fabric_test_pattern(reg.authenticated_peer_runtime_id, 0x31u, 16u);
    fabric_test_pattern(reg.attachment_authority_id, 0x41u, 16u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-attachment-binding-v1", 28u,
        reg.attachment_binding_digest);
    reg.maximum_packet_bytes = 1925u;
    reg.maximum_transfer_bytes = 1925u;
    reg.latency_class = 10u;
    reg.cost_class = 20u;
    reg.reservation_capacity = 8u;
    reg.availability_epoch = 7u;
    fabric_test_pattern(reg.availability_clock_epoch_id, 0xA1u, 16u);
    reg.available = 1u;
    reg.lifecycle = 1u;
    reg.availability_expires_at_ms = 250000u;
    reg.peer_nfl1_version = 1u;
    reg.peer_fabric_capability_flags = 1u;
    reg.configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-config-v1", 25u,
        reg.configuration_digest);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_fbr1_encode(&reg, payload),
        NINLIL_FABRIC_PRIVATE_RECORD_OK);
    ninlil_fabric_private_key_fbr1(reg.instance_id, key);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_record_encode_envelope(
            magic, 1u, payload, 348u, value, 372u, &vlen),
        NINLIL_FABRIC_PRIVATE_RECORD_OK);
    FABRIC_REQUIRE_EQ_U32(vlen, 372u);
    ninlil_fabric_private_registry_record_digest(key, value, dig);
    FABRIC_REQUIRE(!ninlil_fabric_private_is_zero(dig, 32u));

    ninlil_fabric_private_memzero(&pol, sizeof(pol));
    fabric_test_pattern(pol.policy_id, 0x71u, 16u);
    pol.revision = 3u;
    fabric_test_pattern(pol.service_identity_digest, 0x11u, 32u);
    pol.family = 2u;
    pol.direction = 1u;
    pol.traffic_class = 1u;
    pol.scope_selector = 2u;
    pol.required_capability_flags = 2u;
    pol.required_security_flags = 0x0Fu;
    pol.maximum_latency_class = 50u;
    pol.maximum_cost_class = 50u;
    pol.minimum_packet_bytes = 587u;
    pol.authority_mode = 1u;
    pol.deadline_guard_ms = 100u;
    pol.candidate_count = 2u;
    fabric_test_pattern(pol.candidates[0].instance_id, 0x01u, 16u);
    pol.candidates[0].rank = 20u;
    pol.candidates[0].reservation_units = 1u;
    fabric_test_pattern(pol.candidates[1].instance_id, 0x61u, 16u);
    pol.candidates[1].rank = 10u;
    pol.candidates[1].reservation_units = 1u;
    ninlil_fabric_private_fbp1_compute_digest(&pol);
    FABRIC_REQUIRE(!ninlil_fabric_private_is_zero(pol.canonical_digest, 32u));
    return 0;
}

static int test_fba_key_and_dispatch(void)
{
    uint8_t key[76];
    uint8_t digest[32];
    uint8_t local[32];
    uint8_t tx[16];
    uint8_t at[16];
    fabric_test_pattern(tx, 0x10u, 16u);
    fabric_test_pattern(at, 0x20u, 16u);
    fabric_test_pattern(digest, 0xC8u, 32u);
    ninlil_fabric_private_key_fba1(tx, at, 1u, 0u, digest, key);
    FABRIC_REQUIRE(key[0] == (uint8_t)'F' && key[3] == (uint8_t)'1');
    ninlil_fabric_private_local_dispatch_id(key, local);
    FABRIC_REQUIRE(!ninlil_fabric_private_is_zero(local, 32u));
    return 0;
}

static int test_commit_unknown_matrix(void)
{
    uint8_t old_key[4] = { 'F', 'B', 'M', '1' };
    uint8_t new_key[4] = { 'F', 'B', 'M', '1' };
    uint8_t old_val[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t new_val[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    uint8_t third[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            old_key, 4u, old_val, 8u, new_key, 4u, new_val, 8u, old_key, 4u,
            old_val, 8u, 1),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            old_key, 4u, old_val, 8u, new_key, 4u, new_val, 8u, new_key, 4u,
            new_val, 8u, 1),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            NULL, 0u, NULL, 0u, new_key, 4u, new_val, 8u, NULL, 0u, NULL, 0u,
            0),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_ABSENT);
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_commit_unknown_classify(
            old_key, 4u, old_val, 8u, new_key, 4u, new_val, 8u, new_key, 4u,
            third, 8u, 1),
        NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT);
    return 0;
}

static int test_owner_tuple_digest(void)
{
    uint8_t canonical[200];
    uint8_t dig[32];
    fabric_test_pattern(canonical, 0x81u, 200u);
    ninlil_fabric_private_owner_tuple_digest(canonical, dig);
    FABRIC_REQUIRE(!ninlil_fabric_private_is_zero(dig, 32u));
    return 0;
}

int main(void)
{
    g_fabric_test_failures = 0;
    (void)test_meta_roundtrip();
    (void)test_registry_and_policy_digests();
    (void)test_fba_key_and_dispatch();
    (void)test_commit_unknown_matrix();
    (void)test_owner_tuple_digest();
    if (g_fabric_test_failures != 0) {
        (void)fprintf(
            stderr,
            "fabric_v1_records_test failures=%d\n",
            g_fabric_test_failures);
        return 1;
    }
    (void)printf("fabric_v1_records_test OK\n");
    return 0;
}
