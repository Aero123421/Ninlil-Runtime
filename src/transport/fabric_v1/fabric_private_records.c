#include "fabric_private_records.h"

ninlil_fabric_private_record_status_t
ninlil_fabric_private_record_encode_envelope(
    const uint8_t magic[4],
    uint64_t revision,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_value,
    uint32_t out_capacity,
    uint32_t *out_length)
{
    uint32_t total;
    uint32_t crc;

    if (magic == NULL || out_value == NULL || out_length == NULL
        || (payload_len > 0u && payload == NULL) || revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    total = NINLIL_FABRIC_RECORD_ENVELOPE_BYTES + payload_len;
    if (total > out_capacity || total > NINLIL_FABRIC_VALUE_CEILING) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    (void)memcpy(out_value, magic, 4u);
    ninlil_fabric_private_put_u16_be(out_value + 4, 1u);
    ninlil_fabric_private_put_u16_be(out_value + 6, 24u);
    ninlil_fabric_private_put_u32_be(out_value + 8, total);
    ninlil_fabric_private_put_u64_be(out_value + 12, revision);
    ninlil_fabric_private_put_u32_be(out_value + 20, 0u);
    if (payload_len > 0u) {
        (void)memcpy(out_value + 24, payload, payload_len);
    }
    crc = ninlil_fabric_private_crc32c(out_value, total);
    ninlil_fabric_private_put_u32_be(out_value + 20, crc);
    *out_length = total;
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t
ninlil_fabric_private_record_decode_envelope(
    const uint8_t *value,
    uint32_t value_len,
    const uint8_t expected_magic[4],
    uint32_t expected_payload_len,
    ninlil_fabric_private_common_envelope_t *out_header,
    const uint8_t **out_payload)
{
    uint32_t stored_crc;
    uint32_t computed;
    uint8_t scratch[NINLIL_FABRIC_VALUE_CEILING];

    if (value == NULL || expected_magic == NULL || out_header == NULL
        || out_payload == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    if (value_len < NINLIL_FABRIC_RECORD_ENVELOPE_BYTES
        || value_len > NINLIL_FABRIC_VALUE_CEILING) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    if (!ninlil_fabric_private_memeq(value, expected_magic, 4u)) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    out_header->magic[0] = value[0];
    out_header->magic[1] = value[1];
    out_header->magic[2] = value[2];
    out_header->magic[3] = value[3];
    out_header->schema = ninlil_fabric_private_get_u16_be(value + 4);
    out_header->header_length = ninlil_fabric_private_get_u16_be(value + 6);
    out_header->total_length = ninlil_fabric_private_get_u32_be(value + 8);
    out_header->revision = ninlil_fabric_private_get_u64_be(value + 12);
    out_header->crc32c = ninlil_fabric_private_get_u32_be(value + 20);
    if (out_header->schema != 1u || out_header->header_length != 24u
        || out_header->total_length != value_len
        || out_header->revision == 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    if (value_len - 24u != expected_payload_len) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    (void)memcpy(scratch, value, value_len);
    ninlil_fabric_private_put_u32_be(scratch + 20, 0u);
    computed = ninlil_fabric_private_crc32c(scratch, value_len);
    ninlil_fabric_private_memzero(scratch, value_len);
    stored_crc = out_header->crc32c;
    if (stored_crc != computed) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    *out_payload = value + 24;
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

void ninlil_fabric_private_key_fbm1(uint8_t out_key[4])
{
    out_key[0] = (uint8_t)'F';
    out_key[1] = (uint8_t)'B';
    out_key[2] = (uint8_t)'M';
    out_key[3] = (uint8_t)'1';
}

void ninlil_fabric_private_key_fbr1(
    const uint8_t instance_id[16], uint8_t out_key[20])
{
    out_key[0] = (uint8_t)'F';
    out_key[1] = (uint8_t)'B';
    out_key[2] = (uint8_t)'R';
    out_key[3] = (uint8_t)'1';
    (void)memcpy(out_key + 4, instance_id, 16u);
}

void ninlil_fabric_private_key_fbp1(
    const uint8_t policy_id[16],
    uint64_t revision,
    uint8_t out_key[28])
{
    out_key[0] = (uint8_t)'F';
    out_key[1] = (uint8_t)'B';
    out_key[2] = (uint8_t)'P';
    out_key[3] = (uint8_t)'1';
    (void)memcpy(out_key + 4, policy_id, 16u);
    ninlil_fabric_private_put_u64_be(out_key + 20, revision);
}

void ninlil_fabric_private_key_fbc1(
    const uint8_t binding_id[16], uint8_t out_key[20])
{
    out_key[0] = (uint8_t)'F';
    out_key[1] = (uint8_t)'B';
    out_key[2] = (uint8_t)'C';
    out_key[3] = (uint8_t)'1';
    (void)memcpy(out_key + 4, binding_id, 16u);
}

void ninlil_fabric_private_key_fba1(
    const uint8_t transaction_id[16],
    const uint8_t attempt_id[16],
    uint32_t message_kind,
    uint32_t response_slot,
    const uint8_t foundation_message_digest[32],
    uint8_t out_key[76])
{
    out_key[0] = (uint8_t)'F';
    out_key[1] = (uint8_t)'B';
    out_key[2] = (uint8_t)'A';
    out_key[3] = (uint8_t)'1';
    (void)memcpy(out_key + 4, transaction_id, 16u);
    (void)memcpy(out_key + 20, attempt_id, 16u);
    ninlil_fabric_private_put_u32_be(out_key + 36, message_kind);
    ninlil_fabric_private_put_u32_be(out_key + 40, response_slot);
    (void)memcpy(out_key + 44, foundation_message_digest, 32u);
}

void ninlil_fabric_private_key_fbt1(
    const uint8_t transaction_id[16],
    const uint8_t triggering_attempt_id[16],
    uint32_t triggering_kind,
    uint8_t out_key[40])
{
    out_key[0] = (uint8_t)'F';
    out_key[1] = (uint8_t)'B';
    out_key[2] = (uint8_t)'T';
    out_key[3] = (uint8_t)'1';
    (void)memcpy(out_key + 4, transaction_id, 16u);
    (void)memcpy(out_key + 20, triggering_attempt_id, 16u);
    ninlil_fabric_private_put_u32_be(out_key + 36, triggering_kind);
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbm1_encode(
    const ninlil_fabric_private_fbm1_t *in,
    uint8_t out_payload[40])
{
    if (in == NULL || out_payload == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_put_u16_be(out_payload + 0, in->source_schema);
    ninlil_fabric_private_put_u16_be(out_payload + 2, in->target_schema);
    ninlil_fabric_private_put_u16_be(out_payload + 4, in->migration_state);
    ninlil_fabric_private_put_u16_be(out_payload + 6, in->reserved_zero);
    ninlil_fabric_private_put_u64_be(
        out_payload + 8, in->migration_generation);
    ninlil_fabric_private_put_u64_be(
        out_payload + 16, in->rollback_floor_generation);
    ninlil_fabric_private_put_u64_be(
        out_payload + 24, in->outer_availability_epoch);
    ninlil_fabric_private_put_u32_be(out_payload + 32, in->outer_available);
    ninlil_fabric_private_put_u32_be(
        out_payload + 36, in->reserved_zero_u32);
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbm1_decode(
    const uint8_t payload[40],
    ninlil_fabric_private_fbm1_t *out)
{
    if (payload == NULL || out == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out, sizeof(*out));
    out->source_schema = ninlil_fabric_private_get_u16_be(payload + 0);
    out->target_schema = ninlil_fabric_private_get_u16_be(payload + 2);
    out->migration_state = ninlil_fabric_private_get_u16_be(payload + 4);
    out->reserved_zero = ninlil_fabric_private_get_u16_be(payload + 6);
    out->migration_generation =
        ninlil_fabric_private_get_u64_be(payload + 8);
    out->rollback_floor_generation =
        ninlil_fabric_private_get_u64_be(payload + 16);
    out->outer_availability_epoch =
        ninlil_fabric_private_get_u64_be(payload + 24);
    out->outer_available = ninlil_fabric_private_get_u32_be(payload + 32);
    out->reserved_zero_u32 =
        ninlil_fabric_private_get_u32_be(payload + 36);
    if (out->reserved_zero != 0u || out->reserved_zero_u32 != 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbr1_encode(
    const ninlil_fabric_private_fbr1_t *in,
    uint8_t out_payload[348])
{
    if (in == NULL || out_payload == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out_payload, 348u);
    (void)memcpy(out_payload + 0, in->instance_id, 16u);
    ninlil_fabric_private_put_u32_be(out_payload + 16, in->link_kind);
    ninlil_fabric_private_put_u32_be(out_payload + 20, in->direction_mask);
    ninlil_fabric_private_put_u32_be(out_payload + 24, in->capability_flags);
    ninlil_fabric_private_put_u64_be(
        out_payload + 28, in->descriptor_revision);
    (void)memcpy(out_payload + 36, in->descriptor_digest, 32u);
    (void)memcpy(out_payload + 68, in->security_profile_id, 16u);
    ninlil_fabric_private_put_u32_be(
        out_payload + 84, in->security_capability_flags);
    (void)memcpy(out_payload + 88, in->security_binding_digest, 32u);
    ninlil_fabric_private_put_u64_be(out_payload + 120, in->attestation_epoch);
    (void)memcpy(out_payload + 128, in->attestation_clock_epoch_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 144, in->attestation_expires_at_ms);
    (void)memcpy(out_payload + 152, in->attestation_digest, 32u);
    (void)memcpy(out_payload + 184, in->authenticated_peer_runtime_id, 16u);
    (void)memcpy(out_payload + 200, in->attachment_authority_id, 16u);
    (void)memcpy(out_payload + 216, in->attachment_binding_digest, 32u);
    ninlil_fabric_private_put_u32_be(
        out_payload + 248, in->maximum_packet_bytes);
    ninlil_fabric_private_put_u32_be(
        out_payload + 252, in->maximum_transfer_bytes);
    ninlil_fabric_private_put_u16_be(out_payload + 256, in->latency_class);
    ninlil_fabric_private_put_u16_be(out_payload + 258, in->cost_class);
    ninlil_fabric_private_put_u16_be(
        out_payload + 260, in->reservation_capacity);
    ninlil_fabric_private_put_u16_be(
        out_payload + 262, in->reserved_zero_u16);
    ninlil_fabric_private_put_u64_be(
        out_payload + 264, in->availability_epoch);
    (void)memcpy(out_payload + 272, in->availability_clock_epoch_id, 16u);
    out_payload[288] = in->available;
    out_payload[289] = in->lifecycle;
    ninlil_fabric_private_put_u16_be(
        out_payload + 290, in->reserved_avail_u16);
    ninlil_fabric_private_put_u64_be(
        out_payload + 292, in->availability_expires_at_ms);
    ninlil_fabric_private_put_u16_be(
        out_payload + 300, in->peer_nfl1_version);
    ninlil_fabric_private_put_u16_be(
        out_payload + 302, in->reserved_peer_u16);
    ninlil_fabric_private_put_u32_be(
        out_payload + 304, in->peer_fabric_capability_flags);
    ninlil_fabric_private_put_u64_be(
        out_payload + 308, in->configuration_revision);
    (void)memcpy(out_payload + 316, in->configuration_digest, 32u);
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbr1_decode(
    const uint8_t payload[348],
    ninlil_fabric_private_fbr1_t *out)
{
    if (payload == NULL || out == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out, sizeof(*out));
    (void)memcpy(out->instance_id, payload + 0, 16u);
    out->link_kind = ninlil_fabric_private_get_u32_be(payload + 16);
    out->direction_mask = ninlil_fabric_private_get_u32_be(payload + 20);
    out->capability_flags = ninlil_fabric_private_get_u32_be(payload + 24);
    out->descriptor_revision =
        ninlil_fabric_private_get_u64_be(payload + 28);
    (void)memcpy(out->descriptor_digest, payload + 36, 32u);
    (void)memcpy(out->security_profile_id, payload + 68, 16u);
    out->security_capability_flags =
        ninlil_fabric_private_get_u32_be(payload + 84);
    (void)memcpy(out->security_binding_digest, payload + 88, 32u);
    out->attestation_epoch =
        ninlil_fabric_private_get_u64_be(payload + 120);
    (void)memcpy(out->attestation_clock_epoch_id, payload + 128, 16u);
    out->attestation_expires_at_ms =
        ninlil_fabric_private_get_u64_be(payload + 144);
    (void)memcpy(out->attestation_digest, payload + 152, 32u);
    (void)memcpy(out->authenticated_peer_runtime_id, payload + 184, 16u);
    (void)memcpy(out->attachment_authority_id, payload + 200, 16u);
    (void)memcpy(out->attachment_binding_digest, payload + 216, 32u);
    out->maximum_packet_bytes =
        ninlil_fabric_private_get_u32_be(payload + 248);
    out->maximum_transfer_bytes =
        ninlil_fabric_private_get_u32_be(payload + 252);
    out->latency_class = ninlil_fabric_private_get_u16_be(payload + 256);
    out->cost_class = ninlil_fabric_private_get_u16_be(payload + 258);
    out->reservation_capacity =
        ninlil_fabric_private_get_u16_be(payload + 260);
    out->reserved_zero_u16 =
        ninlil_fabric_private_get_u16_be(payload + 262);
    out->availability_epoch =
        ninlil_fabric_private_get_u64_be(payload + 264);
    (void)memcpy(out->availability_clock_epoch_id, payload + 272, 16u);
    out->available = payload[288];
    out->lifecycle = payload[289];
    out->reserved_avail_u16 =
        ninlil_fabric_private_get_u16_be(payload + 290);
    out->availability_expires_at_ms =
        ninlil_fabric_private_get_u64_be(payload + 292);
    out->peer_nfl1_version =
        ninlil_fabric_private_get_u16_be(payload + 300);
    out->reserved_peer_u16 =
        ninlil_fabric_private_get_u16_be(payload + 302);
    out->peer_fabric_capability_flags =
        ninlil_fabric_private_get_u32_be(payload + 304);
    out->configuration_revision =
        ninlil_fabric_private_get_u64_be(payload + 308);
    (void)memcpy(out->configuration_digest, payload + 316, 32u);
    if (out->reserved_zero_u16 != 0u || out->reserved_avail_u16 != 0u
        || out->reserved_peer_u16 != 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbp1_encode(
    const ninlil_fabric_private_fbp1_t *in,
    uint8_t out_payload[328])
{
    uint32_t i;
    uint32_t off;

    if (in == NULL || out_payload == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out_payload, 328u);
    (void)memcpy(out_payload + 0, in->policy_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 16, in->revision);
    (void)memcpy(out_payload + 24, in->canonical_digest, 32u);
    (void)memcpy(out_payload + 56, in->service_identity_digest, 32u);
    ninlil_fabric_private_put_u32_be(out_payload + 88, in->family);
    ninlil_fabric_private_put_u32_be(out_payload + 92, in->direction);
    ninlil_fabric_private_put_u16_be(out_payload + 96, in->traffic_class);
    ninlil_fabric_private_put_u16_be(out_payload + 98, in->scope_selector);
    ninlil_fabric_private_put_u32_be(
        out_payload + 100, in->required_capability_flags);
    ninlil_fabric_private_put_u32_be(
        out_payload + 104, in->required_security_flags);
    ninlil_fabric_private_put_u16_be(
        out_payload + 108, in->maximum_latency_class);
    ninlil_fabric_private_put_u16_be(
        out_payload + 110, in->maximum_cost_class);
    ninlil_fabric_private_put_u32_be(
        out_payload + 112, in->minimum_packet_bytes);
    out_payload[116] = in->authority_mode;
    out_payload[117] = in->reserved_zero_u8[0];
    out_payload[118] = in->reserved_zero_u8[1];
    out_payload[119] = in->reserved_zero_u8[2];
    ninlil_fabric_private_put_u64_be(
        out_payload + 120, in->deadline_guard_ms);
    ninlil_fabric_private_put_u16_be(
        out_payload + 128, in->candidate_count);
    ninlil_fabric_private_put_u16_be(
        out_payload + 130, in->reserved_zero_u16);
    ninlil_fabric_private_put_u32_be(
        out_payload + 132, in->reserved_zero_u32);
    off = 136u;
    for (i = 0u; i < 8u; ++i) {
        (void)memcpy(out_payload + off, in->candidates[i].instance_id, 16u);
        ninlil_fabric_private_put_u16_be(
            out_payload + off + 16, in->candidates[i].rank);
        ninlil_fabric_private_put_u16_be(
            out_payload + off + 18, in->candidates[i].flags);
        ninlil_fabric_private_put_u16_be(
            out_payload + off + 20, in->candidates[i].reservation_units);
        ninlil_fabric_private_put_u16_be(
            out_payload + off + 22, in->candidates[i].reserved_zero);
        off += 24u;
    }
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

void ninlil_fabric_private_fbp1_compute_digest(
    ninlil_fabric_private_fbp1_t *inout)
{
    uint8_t payload[328];
    if (inout == NULL) {
        return;
    }
    ninlil_fabric_private_memzero(inout->canonical_digest, 32u);
    (void)ninlil_fabric_private_fbp1_encode(inout, payload);
    ninlil_fabric_private_tagged_sha256(
        "NINLIL-FABRIC-POLICY-V1", payload, 328u, inout->canonical_digest);
    ninlil_fabric_private_memzero(payload, sizeof(payload));
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbp1_decode(
    const uint8_t payload[328],
    ninlil_fabric_private_fbp1_t *out)
{
    uint32_t i;
    uint32_t off;

    if (payload == NULL || out == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out, sizeof(*out));
    (void)memcpy(out->policy_id, payload + 0, 16u);
    out->revision = ninlil_fabric_private_get_u64_be(payload + 16);
    (void)memcpy(out->canonical_digest, payload + 24, 32u);
    (void)memcpy(out->service_identity_digest, payload + 56, 32u);
    out->family = ninlil_fabric_private_get_u32_be(payload + 88);
    out->direction = ninlil_fabric_private_get_u32_be(payload + 92);
    out->traffic_class = ninlil_fabric_private_get_u16_be(payload + 96);
    out->scope_selector = ninlil_fabric_private_get_u16_be(payload + 98);
    out->required_capability_flags =
        ninlil_fabric_private_get_u32_be(payload + 100);
    out->required_security_flags =
        ninlil_fabric_private_get_u32_be(payload + 104);
    out->maximum_latency_class =
        ninlil_fabric_private_get_u16_be(payload + 108);
    out->maximum_cost_class =
        ninlil_fabric_private_get_u16_be(payload + 110);
    out->minimum_packet_bytes =
        ninlil_fabric_private_get_u32_be(payload + 112);
    out->authority_mode = payload[116];
    out->reserved_zero_u8[0] = payload[117];
    out->reserved_zero_u8[1] = payload[118];
    out->reserved_zero_u8[2] = payload[119];
    out->deadline_guard_ms =
        ninlil_fabric_private_get_u64_be(payload + 120);
    out->candidate_count = ninlil_fabric_private_get_u16_be(payload + 128);
    out->reserved_zero_u16 =
        ninlil_fabric_private_get_u16_be(payload + 130);
    out->reserved_zero_u32 =
        ninlil_fabric_private_get_u32_be(payload + 132);
    off = 136u;
    for (i = 0u; i < 8u; ++i) {
        (void)memcpy(out->candidates[i].instance_id, payload + off, 16u);
        out->candidates[i].rank =
            ninlil_fabric_private_get_u16_be(payload + off + 16);
        out->candidates[i].flags =
            ninlil_fabric_private_get_u16_be(payload + off + 18);
        out->candidates[i].reservation_units =
            ninlil_fabric_private_get_u16_be(payload + off + 20);
        out->candidates[i].reserved_zero =
            ninlil_fabric_private_get_u16_be(payload + off + 22);
        off += 24u;
    }
    if (out->reserved_zero_u8[0] != 0u || out->reserved_zero_u8[1] != 0u
        || out->reserved_zero_u8[2] != 0u || out->reserved_zero_u16 != 0u
        || out->reserved_zero_u32 != 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

void ninlil_fabric_private_owner_tuple_digest(
    const uint8_t canonical[200], uint8_t out[32])
{
    ninlil_fabric_private_tagged_sha256(
        "NINLIL-FABRIC-OWNER-TUPLE-V1", canonical, 200u, out);
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbc1_encode(
    const ninlil_fabric_private_fbc1_t *in,
    uint8_t out_payload[488])
{
    if (in == NULL || out_payload == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out_payload, 488u);
    (void)memcpy(out_payload + 0, in->binding_id, 16u);
    (void)memcpy(out_payload + 16, in->service_identity_digest, 32u);
    ninlil_fabric_private_put_u32_be(out_payload + 48, in->family);
    ninlil_fabric_private_put_u32_be(out_payload + 52, in->direction);
    ninlil_fabric_private_put_u16_be(out_payload + 56, in->traffic_class);
    ninlil_fabric_private_put_u16_be(out_payload + 58, in->scope_selector);
    (void)memcpy(out_payload + 60, in->endpoint_runtime_id, 16u);
    (void)memcpy(out_payload + 76, in->target_runtime_id, 16u);
    (void)memcpy(out_payload + 92, in->target_application_id, 16u);
    (void)memcpy(out_payload + 108, in->policy_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 124, in->policy_revision);
    (void)memcpy(out_payload + 132, in->policy_digest, 32u);
    ninlil_fabric_private_put_u32_be(out_payload + 164, in->authority_state);
    (void)memcpy(out_payload + 168, in->authority_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 184, in->authority_term);
    ninlil_fabric_private_put_u32_be(
        out_payload + 192, in->assignment_epoch);
    ninlil_fabric_private_put_u32_be(
        out_payload + 196, in->reserved_zero_u32);
    (void)memcpy(out_payload + 200, in->owner_scope_id, 16u);
    (void)memcpy(out_payload + 216, in->owner_tuple_digest, 32u);
    (void)memcpy(out_payload + 248, in->owner_tuple_canonical, 200u);
    (void)memcpy(out_payload + 448, in->authority_clock_epoch_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 464, in->lease_expires_at_ms);
    ninlil_fabric_private_put_u64_be(
        out_payload + 472, in->assignment_revision);
    ninlil_fabric_private_put_u64_be(
        out_payload + 480, in->reserved_zero_u64);
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbc1_decode(
    const uint8_t payload[488],
    ninlil_fabric_private_fbc1_t *out)
{
    if (payload == NULL || out == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out, sizeof(*out));
    (void)memcpy(out->binding_id, payload + 0, 16u);
    (void)memcpy(out->service_identity_digest, payload + 16, 32u);
    out->family = ninlil_fabric_private_get_u32_be(payload + 48);
    out->direction = ninlil_fabric_private_get_u32_be(payload + 52);
    out->traffic_class = ninlil_fabric_private_get_u16_be(payload + 56);
    out->scope_selector = ninlil_fabric_private_get_u16_be(payload + 58);
    (void)memcpy(out->endpoint_runtime_id, payload + 60, 16u);
    (void)memcpy(out->target_runtime_id, payload + 76, 16u);
    (void)memcpy(out->target_application_id, payload + 92, 16u);
    (void)memcpy(out->policy_id, payload + 108, 16u);
    out->policy_revision = ninlil_fabric_private_get_u64_be(payload + 124);
    (void)memcpy(out->policy_digest, payload + 132, 32u);
    out->authority_state = ninlil_fabric_private_get_u32_be(payload + 164);
    (void)memcpy(out->authority_id, payload + 168, 16u);
    out->authority_term = ninlil_fabric_private_get_u64_be(payload + 184);
    out->assignment_epoch = ninlil_fabric_private_get_u32_be(payload + 192);
    out->reserved_zero_u32 =
        ninlil_fabric_private_get_u32_be(payload + 196);
    (void)memcpy(out->owner_scope_id, payload + 200, 16u);
    (void)memcpy(out->owner_tuple_digest, payload + 216, 32u);
    (void)memcpy(out->owner_tuple_canonical, payload + 248, 200u);
    (void)memcpy(out->authority_clock_epoch_id, payload + 448, 16u);
    out->lease_expires_at_ms =
        ninlil_fabric_private_get_u64_be(payload + 464);
    out->assignment_revision =
        ninlil_fabric_private_get_u64_be(payload + 472);
    out->reserved_zero_u64 =
        ninlil_fabric_private_get_u64_be(payload + 480);
    if (out->reserved_zero_u32 != 0u || out->reserved_zero_u64 != 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fba1_encode(
    const ninlil_fabric_private_fba1_t *in,
    uint8_t out_payload[688])
{
    if (in == NULL || out_payload == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out_payload, 688u);
    (void)memcpy(out_payload + 0, in->transaction_id, 16u);
    (void)memcpy(out_payload + 16, in->attempt_id, 16u);
    ninlil_fabric_private_put_u32_be(out_payload + 32, in->message_kind);
    ninlil_fabric_private_put_u32_be(out_payload + 36, in->response_slot);
    ninlil_fabric_private_put_u32_be(out_payload + 40, in->state);
    (void)memcpy(out_payload + 44, in->foundation_message_digest, 32u);
    (void)memcpy(out_payload + 76, in->policy_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 92, in->policy_revision);
    (void)memcpy(out_payload + 100, in->policy_digest, 32u);
    (void)memcpy(out_payload + 132, in->selected_path_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 148, in->path_selection_epoch);
    ninlil_fabric_private_put_u32_be(out_payload + 156, in->route_flags);
    ninlil_fabric_private_put_u32_be(out_payload + 160, in->authority_state);
    (void)memcpy(out_payload + 164, in->authority_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 180, in->authority_term);
    ninlil_fabric_private_put_u32_be(
        out_payload + 188, in->assignment_epoch);
    (void)memcpy(out_payload + 192, in->owner_scope_id, 16u);
    (void)memcpy(out_payload + 208, in->owner_tuple_digest, 32u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 240, in->registry_record_revision);
    (void)memcpy(out_payload + 248, in->registry_record_digest, 32u);
    (void)memcpy(out_payload + 280, in->descriptor_digest, 32u);
    (void)memcpy(out_payload + 312, in->security_profile_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 328, in->attestation_epoch);
    (void)memcpy(out_payload + 336, in->attestation_clock_epoch_id, 16u);
    (void)memcpy(out_payload + 352, in->attestation_digest, 32u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 384, in->attestation_expires_at_ms);
    (void)memcpy(out_payload + 392, in->peer_runtime_id, 16u);
    (void)memcpy(out_payload + 408, in->attachment_authority_id, 16u);
    (void)memcpy(out_payload + 424, in->attachment_binding_digest, 32u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 456, in->availability_epoch);
    (void)memcpy(out_payload + 464, in->availability_clock_epoch_id, 16u);
    out_payload[480] = in->availability_state;
    (void)memcpy(out_payload + 481, in->reserved_avail, 7u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 488, in->availability_expires_at_ms);
    (void)memcpy(out_payload + 496, in->reservation_id, 16u);
    (void)memcpy(out_payload + 512, in->deadline_clock_epoch_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 528, in->deadline_ms);
    ninlil_fabric_private_put_u32_be(out_payload + 536, in->nfl1_length);
    (void)memcpy(out_payload + 540, in->nfl1_sha256, 32u);
    (void)memcpy(out_payload + 572, in->retention_clock_epoch_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 588, in->retention_until_ms);
    (void)memcpy(out_payload + 596, in->retry_lifetime_clock_epoch_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 612, in->retry_expires_at_ms);
    (void)memcpy(out_payload + 620, in->local_dispatch_id, 32u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 652, in->runtime_terminal_revision);
    (void)memcpy(out_payload + 660, in->permit_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 676, in->permit_expires_at_ms);
    ninlil_fabric_private_put_u32_be(
        out_payload + 684, in->permit_claim_state);
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fba1_decode(
    const uint8_t payload[688],
    ninlil_fabric_private_fba1_t *out)
{
    if (payload == NULL || out == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out, sizeof(*out));
    (void)memcpy(out->transaction_id, payload + 0, 16u);
    (void)memcpy(out->attempt_id, payload + 16, 16u);
    out->message_kind = ninlil_fabric_private_get_u32_be(payload + 32);
    out->response_slot = ninlil_fabric_private_get_u32_be(payload + 36);
    out->state = ninlil_fabric_private_get_u32_be(payload + 40);
    (void)memcpy(out->foundation_message_digest, payload + 44, 32u);
    (void)memcpy(out->policy_id, payload + 76, 16u);
    out->policy_revision = ninlil_fabric_private_get_u64_be(payload + 92);
    (void)memcpy(out->policy_digest, payload + 100, 32u);
    (void)memcpy(out->selected_path_id, payload + 132, 16u);
    out->path_selection_epoch =
        ninlil_fabric_private_get_u64_be(payload + 148);
    out->route_flags = ninlil_fabric_private_get_u32_be(payload + 156);
    out->authority_state = ninlil_fabric_private_get_u32_be(payload + 160);
    (void)memcpy(out->authority_id, payload + 164, 16u);
    out->authority_term = ninlil_fabric_private_get_u64_be(payload + 180);
    out->assignment_epoch = ninlil_fabric_private_get_u32_be(payload + 188);
    (void)memcpy(out->owner_scope_id, payload + 192, 16u);
    (void)memcpy(out->owner_tuple_digest, payload + 208, 32u);
    out->registry_record_revision =
        ninlil_fabric_private_get_u64_be(payload + 240);
    (void)memcpy(out->registry_record_digest, payload + 248, 32u);
    (void)memcpy(out->descriptor_digest, payload + 280, 32u);
    (void)memcpy(out->security_profile_id, payload + 312, 16u);
    out->attestation_epoch =
        ninlil_fabric_private_get_u64_be(payload + 328);
    (void)memcpy(out->attestation_clock_epoch_id, payload + 336, 16u);
    (void)memcpy(out->attestation_digest, payload + 352, 32u);
    out->attestation_expires_at_ms =
        ninlil_fabric_private_get_u64_be(payload + 384);
    (void)memcpy(out->peer_runtime_id, payload + 392, 16u);
    (void)memcpy(out->attachment_authority_id, payload + 408, 16u);
    (void)memcpy(out->attachment_binding_digest, payload + 424, 32u);
    out->availability_epoch =
        ninlil_fabric_private_get_u64_be(payload + 456);
    (void)memcpy(out->availability_clock_epoch_id, payload + 464, 16u);
    out->availability_state = payload[480];
    (void)memcpy(out->reserved_avail, payload + 481, 7u);
    out->availability_expires_at_ms =
        ninlil_fabric_private_get_u64_be(payload + 488);
    (void)memcpy(out->reservation_id, payload + 496, 16u);
    (void)memcpy(out->deadline_clock_epoch_id, payload + 512, 16u);
    out->deadline_ms = ninlil_fabric_private_get_u64_be(payload + 528);
    out->nfl1_length = ninlil_fabric_private_get_u32_be(payload + 536);
    (void)memcpy(out->nfl1_sha256, payload + 540, 32u);
    (void)memcpy(out->retention_clock_epoch_id, payload + 572, 16u);
    out->retention_until_ms =
        ninlil_fabric_private_get_u64_be(payload + 588);
    (void)memcpy(out->retry_lifetime_clock_epoch_id, payload + 596, 16u);
    out->retry_expires_at_ms =
        ninlil_fabric_private_get_u64_be(payload + 612);
    (void)memcpy(out->local_dispatch_id, payload + 620, 32u);
    out->runtime_terminal_revision =
        ninlil_fabric_private_get_u64_be(payload + 652);
    (void)memcpy(out->permit_id, payload + 660, 16u);
    out->permit_expires_at_ms =
        ninlil_fabric_private_get_u64_be(payload + 676);
    out->permit_claim_state =
        ninlil_fabric_private_get_u32_be(payload + 684);
    if (!ninlil_fabric_private_is_zero(out->reserved_avail, 7u)
        || out->route_flags != 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbt1_encode(
    const ninlil_fabric_private_fbt1_t *in,
    uint8_t out_payload[224])
{
    if (in == NULL || out_payload == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out_payload, 224u);
    (void)memcpy(out_payload + 0, in->transaction_id, 16u);
    (void)memcpy(out_payload + 16, in->triggering_attempt_id, 16u);
    ninlil_fabric_private_put_u32_be(out_payload + 32, in->triggering_kind);
    ninlil_fabric_private_put_u32_be(out_payload + 36, in->authority_state);
    (void)memcpy(out_payload + 40, in->endpoint_runtime_id, 16u);
    (void)memcpy(out_payload + 56, in->owner_scope_id, 16u);
    (void)memcpy(out_payload + 72, in->authority_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 88, in->authority_term);
    ninlil_fabric_private_put_u32_be(
        out_payload + 96, in->assignment_epoch);
    ninlil_fabric_private_put_u32_be(
        out_payload + 100, in->reserved_zero_u32);
    (void)memcpy(out_payload + 104, in->owner_tuple_digest, 32u);
    (void)memcpy(out_payload + 136, in->policy_id, 16u);
    ninlil_fabric_private_put_u64_be(out_payload + 152, in->policy_revision);
    (void)memcpy(out_payload + 160, in->policy_digest, 32u);
    (void)memcpy(out_payload + 192, in->retention_clock_epoch_id, 16u);
    ninlil_fabric_private_put_u64_be(
        out_payload + 208, in->retention_until_ms);
    ninlil_fabric_private_put_u64_be(
        out_payload + 216, in->runtime_terminal_revision);
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbt1_decode(
    const uint8_t payload[224],
    ninlil_fabric_private_fbt1_t *out)
{
    if (payload == NULL || out == NULL) {
        return NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT;
    }
    ninlil_fabric_private_memzero(out, sizeof(*out));
    (void)memcpy(out->transaction_id, payload + 0, 16u);
    (void)memcpy(out->triggering_attempt_id, payload + 16, 16u);
    out->triggering_kind = ninlil_fabric_private_get_u32_be(payload + 32);
    out->authority_state = ninlil_fabric_private_get_u32_be(payload + 36);
    (void)memcpy(out->endpoint_runtime_id, payload + 40, 16u);
    (void)memcpy(out->owner_scope_id, payload + 56, 16u);
    (void)memcpy(out->authority_id, payload + 72, 16u);
    out->authority_term = ninlil_fabric_private_get_u64_be(payload + 88);
    out->assignment_epoch = ninlil_fabric_private_get_u32_be(payload + 96);
    out->reserved_zero_u32 =
        ninlil_fabric_private_get_u32_be(payload + 100);
    (void)memcpy(out->owner_tuple_digest, payload + 104, 32u);
    (void)memcpy(out->policy_id, payload + 136, 16u);
    out->policy_revision = ninlil_fabric_private_get_u64_be(payload + 152);
    (void)memcpy(out->policy_digest, payload + 160, 32u);
    (void)memcpy(out->retention_clock_epoch_id, payload + 192, 16u);
    out->retention_until_ms =
        ninlil_fabric_private_get_u64_be(payload + 208);
    out->runtime_terminal_revision =
        ninlil_fabric_private_get_u64_be(payload + 216);
    if (out->reserved_zero_u32 != 0u) {
        return NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT;
    }
    return NINLIL_FABRIC_PRIVATE_RECORD_OK;
}

void ninlil_fabric_private_registry_record_digest(
    const uint8_t key[20],
    const uint8_t value[372],
    uint8_t out[32])
{
    uint8_t combined[20u + 372u];
    (void)memcpy(combined, key, 20u);
    (void)memcpy(combined + 20, value, 372u);
    ninlil_fabric_private_tagged_sha256(
        "NINLIL-FABRIC-REGISTRY-RECORD-V1", combined, sizeof(combined), out);
    ninlil_fabric_private_memzero(combined, sizeof(combined));
}

void ninlil_fabric_private_local_dispatch_id(
    const uint8_t fba1_key[76], uint8_t out[32])
{
    ninlil_fabric_private_tagged_sha256(
        "NINLIL-FABRIC-LOCAL-DISPATCH-V1", fba1_key, 76u, out);
}

uint32_t ninlil_fabric_private_commit_unknown_classify(
    const uint8_t *old_key,
    uint32_t old_key_len,
    const uint8_t *old_value,
    uint32_t old_value_len,
    const uint8_t *new_key,
    uint32_t new_key_len,
    const uint8_t *new_value,
    uint32_t new_value_len,
    const uint8_t *observed_key,
    uint32_t observed_key_len,
    const uint8_t *observed_value,
    uint32_t observed_value_len,
    int observed_present)
{
    int old_present = old_key != NULL && old_value != NULL && old_key_len > 0u
        && old_value_len > 0u;
    int new_present = new_key != NULL && new_value != NULL && new_key_len > 0u
        && new_value_len > 0u;

    if (!observed_present) {
        if (!old_present && new_present) {
            return NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_ABSENT;
        }
        return NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT;
    }
    if (observed_key == NULL || observed_value == NULL) {
        return NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT;
    }
    if (old_present && observed_key_len == old_key_len
        && observed_value_len == old_value_len
        && ninlil_fabric_private_memeq(observed_key, old_key, old_key_len)
        && ninlil_fabric_private_memeq(
               observed_value, old_value, old_value_len)) {
        return NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD;
    }
    if (new_present && observed_key_len == new_key_len
        && observed_value_len == new_value_len
        && ninlil_fabric_private_memeq(observed_key, new_key, new_key_len)
        && ninlil_fabric_private_memeq(
               observed_value, new_value, new_value_len)) {
        return NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW;
    }
    return NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT;
}
