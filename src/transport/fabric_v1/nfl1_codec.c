/* SPDX-License-Identifier: Apache-2.0 */
#include "nfl1_codec.h"

#include "fabric_private_util.h"

#include <string.h>

_Static_assert(
    NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES == 584u, "NFL1 header 584");
_Static_assert(
    NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN == 587u, "NFL1 min 587");
_Static_assert(
    NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MAX == 1925u, "NFL1 max 1925");
_Static_assert(
    NINLIL_FABRIC_PRIVATE_NFL1_SEMANTIC_MAX == 1797u, "NFL1 semantic max 1797");

#define NFL1_IDENTITY_FLAG_MASK ((uint32_t)0x7u)

static void put_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)((value >> 8) & 0xffu);
    out[1] = (uint8_t)(value & 0xffu);
}

static void put_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

static void put_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)((value >> 56) & 0xffu);
    out[1] = (uint8_t)((value >> 48) & 0xffu);
    out[2] = (uint8_t)((value >> 40) & 0xffu);
    out[3] = (uint8_t)((value >> 32) & 0xffu);
    out[4] = (uint8_t)((value >> 24) & 0xffu);
    out[5] = (uint8_t)((value >> 16) & 0xffu);
    out[6] = (uint8_t)((value >> 8) & 0xffu);
    out[7] = (uint8_t)(value & 0xffu);
}

static uint16_t get_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t get_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t get_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

static int is_zero(const uint8_t *bytes, size_t length)
{
    size_t i;
    if (bytes == NULL) {
        return length == 0u;
    }
    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int id_is_zero(const ninlil_id128_t *id)
{
    return is_zero(id->bytes, 16u);
}

static int id_is_nonzero(const ninlil_id128_t *id)
{
    return !id_is_zero(id);
}

uint32_t ninlil_fabric_private_nfl1_crc32c(
    const uint8_t *data, size_t length)
{
    uint32_t crc = UINT32_C(0xffffffff);
    uint8_t value;
    size_t i;
    unsigned bit;

    if (data == NULL && length != 0u) {
        return 0u;
    }
    for (i = 0u; i < length; ++i) {
        value = (i >= 12u && i < 16u) ? 0u : data[i];
        crc ^= (uint32_t)value;
        for (bit = 0u; bit < 8u; ++bit) {
            if ((crc & 1u) != 0u) {
                crc = (crc >> 1) ^ UINT32_C(0x82f63b78);
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

void ninlil_fabric_private_nfl1_clear(
    ninlil_fabric_private_nfl1_envelope_t *envelope)
{
    if (envelope == NULL) {
        return;
    }
    (void)memset(envelope, 0, sizeof(*envelope));
}

static int family_known(uint32_t family)
{
    return family == NINLIL_FAMILY_EVENT_FACT
        || family == NINLIL_FAMILY_DESIRED_STATE
        || family == NINLIL_FAMILY_LATEST_STATE_RESERVED
        || family == NINLIL_FAMILY_MEASUREMENT_RESERVED
        || family == NINLIL_FAMILY_TRANSFER_RESERVED
        || family == NINLIL_FAMILY_CONFIG_RESERVED
        || family == NINLIL_FAMILY_NETWORK_CONTROL_RESERVED;
}

static int evidence_stage_known(uint32_t stage)
{
    return stage <= NINLIL_EVIDENCE_VERIFIED;
}

static int disposition_known(uint32_t value)
{
    return value <= NINLIL_DISPOSITION_OUTCOME_UNKNOWN;
}

static int effect_certainty_known(uint32_t value)
{
    return value <= NINLIL_EFFECT_CERTAINTY_POSSIBLE;
}

static int retry_guidance_known(uint32_t value)
{
    return value <= NINLIL_RETRY_OPERATOR_ACTION;
}

static int cancel_kind_known(uint32_t value)
{
    /* Foundation closed catalog: 0..8 */
    return value <= 8u;
}

static int clock_trust_known(uint32_t value)
{
    return value == 0u || value == NINLIL_CLOCK_TRUSTED
        || value == NINLIL_CLOCK_UNCERTAIN;
}

static int digest_ok(const ninlil_digest256_t *d)
{
    return d->algorithm == NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256
        && d->reserved_zero == 0u && !is_zero(d->bytes, 32u);
}

static int authority_group_ok(
    const ninlil_id128_t *authority_id,
    uint64_t authority_term,
    uint32_t assignment_epoch)
{
    int id_zero = id_is_zero(authority_id);
    int term_zero = authority_term == 0u;
    int epoch_zero = assignment_epoch == 0u;
    if (id_zero && term_zero && epoch_zero) {
        return 1; /* ABSENT */
    }
    if (!id_zero && !term_zero && !epoch_zero) {
        return 1; /* BOUND */
    }
    return 0;
}

static int text_len_ok(uint32_t length)
{
    return length >= 1u && length <= NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX;
}

static int identity_flags_ok(uint32_t flags)
{
    return (flags & ~NFL1_IDENTITY_FLAG_MASK) == 0u;
}

static int kind_matrix_ok(const ninlil_fabric_private_nfl1_envelope_t *e)
{
    uint32_t kind = e->message_kind;
    int payload_empty = e->payload.length == 0u;
    int evidence_empty = e->evidence.length == 0u;
    int receipt_zero = e->receipt_stage == 0u;
    int disp_zero = e->disposition == 0u && e->effect_certainty == 0u
        && e->retry_guidance == 0u && e->retry_delay_ms == 0u;
    int cancel_zero = e->cancel_kind == 0u;
    int evidence_time_zero = id_is_zero(&e->evidence_time_clock_epoch_id)
        && e->evidence_time_now_ms == 0u && e->evidence_time_trust == 0u;
    /*
     * now_ms=0 is a valid first instant in a non-zero clock epoch.  Presence
     * is carried by the epoch/trust group, not by treating timestamp zero as
     * an absent sentinel.
     */
    int evidence_time_valid = id_is_nonzero(&e->evidence_time_clock_epoch_id)
        && (e->evidence_time_trust == NINLIL_CLOCK_TRUSTED
            || e->evidence_time_trust == NINLIL_CLOCK_UNCERTAIN);

    if (e->message_flags != 0u) {
        return 0;
    }
    if (!id_is_nonzero(&e->transaction_id)
        || !id_is_nonzero(&e->attempt_id)) {
        return 0;
    }
    if (!id_is_nonzero(&e->source_runtime_id)
        || !id_is_nonzero(&e->source_application_id)
        || !id_is_nonzero(&e->target_runtime_id)
        || !id_is_nonzero(&e->target_application_id)) {
        return 0;
    }
    if (!identity_flags_ok(e->source_flags)
        || !identity_flags_ok(e->target_flags)) {
        return 0;
    }
    if (!authority_group_ok(
            &e->authority_id, e->authority_term, e->assignment_epoch)) {
        return 0;
    }
    if (!digest_ok(&e->descriptor_digest) || !digest_ok(&e->content_digest)
        || !digest_ok(&e->route_policy_digest)) {
        return 0;
    }
    if (!family_known(e->family) || !evidence_stage_known(e->required_evidence)
        || !clock_trust_known(e->evidence_time_trust)) {
        return 0;
    }
    if (!text_len_ok(e->namespace_id.length)
        || !text_len_ok(e->service_id.length)
        || !text_len_ok(e->schema_id.length)) {
        return 0;
    }
    if (e->payload.length > NINLIL_FABRIC_PRIVATE_NFL1_PAYLOAD_MAX
        || e->evidence.length > NINLIL_FABRIC_PRIVATE_NFL1_EVIDENCE_MAX) {
        return 0;
    }
    /* 6-kind matrix: payload and evidence cannot both be non-empty. */
    if (!payload_empty && !evidence_empty) {
        return 0;
    }
    if (e->route_flags != 0u) {
        return 0;
    }
    if (!id_is_nonzero(&e->route_policy_id)
        || !id_is_nonzero(&e->selected_path_id)
        || e->route_policy_revision == 0u || e->path_selection_epoch == 0u) {
        return 0;
    }
    if (e->descriptor_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256
        || e->content_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256
        || e->route_policy_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256) {
        return 0;
    }

    switch (kind) {
    case NINLIL_BEARER_MESSAGE_APPLICATION:
        return evidence_empty && receipt_zero && disp_zero && cancel_zero
            && evidence_time_zero;
    case NINLIL_BEARER_MESSAGE_RECEIPT:
        return payload_empty && !receipt_zero
            && evidence_stage_known(e->receipt_stage)
            && e->receipt_stage != 0u && disp_zero && cancel_zero
            && evidence_time_valid;
    case NINLIL_BEARER_MESSAGE_DISPOSITION:
        return payload_empty && evidence_empty && receipt_zero && cancel_zero
            && evidence_time_zero && e->disposition != 0u
            && disposition_known(e->disposition)
            && effect_certainty_known(e->effect_certainty)
            && retry_guidance_known(e->retry_guidance);
    case NINLIL_BEARER_MESSAGE_CANCEL_REQUEST:
        return payload_empty && evidence_empty && receipt_zero && disp_zero
            && cancel_zero && evidence_time_zero;
    case NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED:
        return payload_empty && evidence_empty && receipt_zero && disp_zero
            && cancel_zero && evidence_time_zero;
    case NINLIL_BEARER_MESSAGE_CANCEL_RESULT:
        return payload_empty && evidence_empty && receipt_zero && disp_zero
            && evidence_time_zero && e->cancel_kind != 0u
            && cancel_kind_known(e->cancel_kind);
    default:
        return 0;
    }
}

static uint32_t structural_length(
    const ninlil_fabric_private_nfl1_envelope_t *e)
{
    return NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES + e->namespace_id.length
        + e->service_id.length + e->schema_id.length + e->payload.length
        + e->evidence.length;
}

static int enum_algorithms_known(const ninlil_fabric_private_nfl1_envelope_t *e)
{
    if (e->descriptor_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256
        || e->content_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256
        || e->route_policy_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256) {
        return 0;
    }
    return 1;
}

static int closed_catalog_decode_ok(
    const ninlil_fabric_private_nfl1_envelope_t *e)
{
    if (!family_known(e->family)) {
        return 0;
    }
    if (!evidence_stage_known(e->required_evidence)) {
        return 0;
    }
    if (!evidence_stage_known(e->receipt_stage)) {
        return 0;
    }
    if (!disposition_known(e->disposition)) {
        return 0;
    }
    if (!effect_certainty_known(e->effect_certainty)) {
        return 0;
    }
    if (!retry_guidance_known(e->retry_guidance)) {
        return 0;
    }
    if (!cancel_kind_known(e->cancel_kind)) {
        return 0;
    }
    if (!clock_trust_known(e->evidence_time_trust)) {
        return 0;
    }
    return 1;
}

ninlil_fabric_private_nfl1_status_t ninlil_fabric_private_nfl1_encode(
    const ninlil_fabric_private_nfl1_envelope_t *in,
    uint8_t *out_packet,
    uint32_t out_capacity,
    uint32_t *out_length)
{
    uint32_t total;
    uint32_t off;
    uint32_t crc;

    if (in == NULL || out_packet == NULL || out_length == NULL) {
        return NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT;
    }
    if (in->namespace_id.bytes == NULL || in->service_id.bytes == NULL
        || in->schema_id.bytes == NULL) {
        return NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT;
    }
    if (in->payload.length > 0u && in->payload.bytes == NULL) {
        return NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT;
    }
    if (in->evidence.length > 0u && in->evidence.bytes == NULL) {
        return NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT;
    }
    if (!enum_algorithms_known(in) || !closed_catalog_decode_ok(in)) {
        return NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED;
    }
    if (!kind_matrix_ok(in)) {
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }

    total = structural_length(in);
    if (total < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || total > NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MAX) {
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }
    if (total > out_capacity) {
        return NINLIL_FABRIC_PRIVATE_NFL1_BUFFER_TOO_SMALL;
    }

    (void)memset(out_packet, 0, total);
    out_packet[0] = (uint8_t)'N';
    out_packet[1] = (uint8_t)'F';
    out_packet[2] = (uint8_t)'L';
    out_packet[3] = (uint8_t)'1';
    put_u16_be(out_packet + 4, NINLIL_FABRIC_PRIVATE_NFL1_VERSION);
    put_u16_be(out_packet + 6, (uint16_t)NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES);
    put_u32_be(out_packet + 8, total);
    put_u32_be(out_packet + 12, 0u);
    put_u32_be(out_packet + 16, in->message_kind);
    put_u32_be(out_packet + 20, in->message_flags);
    (void)memcpy(out_packet + 24, in->transaction_id.bytes, 16u);
    (void)memcpy(out_packet + 40, in->attempt_id.bytes, 16u);
    (void)memcpy(out_packet + 56, in->event_id.bytes, 16u);
    (void)memcpy(out_packet + 72, in->source_runtime_id.bytes, 16u);
    (void)memcpy(out_packet + 88, in->source_application_id.bytes, 16u);
    (void)memcpy(out_packet + 104, in->source_device_id.bytes, 16u);
    (void)memcpy(out_packet + 120, in->source_installation_id.bytes, 16u);
    (void)memcpy(out_packet + 136, in->source_site_id.bytes, 16u);
    put_u64_be(out_packet + 152, in->source_binding_epoch);
    put_u64_be(out_packet + 160, in->source_membership_epoch);
    put_u32_be(out_packet + 168, in->source_flags);
    (void)memcpy(out_packet + 172, in->target_runtime_id.bytes, 16u);
    (void)memcpy(out_packet + 188, in->target_application_id.bytes, 16u);
    (void)memcpy(out_packet + 204, in->target_device_id.bytes, 16u);
    (void)memcpy(out_packet + 220, in->target_installation_id.bytes, 16u);
    (void)memcpy(out_packet + 236, in->target_site_id.bytes, 16u);
    put_u64_be(out_packet + 252, in->target_binding_epoch);
    put_u64_be(out_packet + 260, in->target_membership_epoch);
    put_u32_be(out_packet + 268, in->target_flags);
    (void)memcpy(out_packet + 272, in->authority_id.bytes, 16u);
    put_u64_be(out_packet + 288, in->authority_term);
    put_u32_be(out_packet + 296, in->assignment_epoch);
    put_u64_be(out_packet + 300, in->descriptor_revision);
    put_u16_be(out_packet + 308, in->descriptor_digest.algorithm);
    (void)memcpy(out_packet + 310, in->descriptor_digest.bytes, 32u);
    put_u16_be(out_packet + 342, in->schema_major);
    put_u16_be(out_packet + 344, in->schema_minor);
    put_u32_be(out_packet + 346, in->family);
    put_u16_be(out_packet + 350, in->content_digest.algorithm);
    (void)memcpy(out_packet + 352, in->content_digest.bytes, 32u);
    put_u64_be(out_packet + 384, in->generation);
    (void)memcpy(out_packet + 392, in->deadline_clock_epoch_id.bytes, 16u);
    put_u64_be(out_packet + 408, in->absolute_effect_deadline_ms);
    put_u64_be(out_packet + 416, in->evidence_grace_ms);
    put_u32_be(out_packet + 424, in->required_evidence);
    put_u32_be(out_packet + 428, in->receipt_stage);
    put_u32_be(out_packet + 432, in->disposition);
    put_u32_be(out_packet + 436, in->effect_certainty);
    put_u32_be(out_packet + 440, in->retry_guidance);
    put_u32_be(out_packet + 444, in->cancel_kind);
    put_u64_be(out_packet + 448, in->retry_delay_ms);
    (void)memcpy(out_packet + 456, in->evidence_time_clock_epoch_id.bytes, 16u);
    put_u64_be(out_packet + 472, in->evidence_time_now_ms);
    put_u32_be(out_packet + 480, in->evidence_time_trust);
    (void)memcpy(out_packet + 484, in->route_policy_id.bytes, 16u);
    put_u64_be(out_packet + 500, in->route_policy_revision);
    put_u16_be(out_packet + 508, in->route_policy_digest.algorithm);
    (void)memcpy(out_packet + 510, in->route_policy_digest.bytes, 32u);
    (void)memcpy(out_packet + 542, in->selected_path_id.bytes, 16u);
    put_u64_be(out_packet + 558, in->path_selection_epoch);
    put_u32_be(out_packet + 566, in->route_flags);
    put_u16_be(out_packet + 570, (uint16_t)in->namespace_id.length);
    put_u16_be(out_packet + 572, (uint16_t)in->service_id.length);
    put_u16_be(out_packet + 574, (uint16_t)in->schema_id.length);
    put_u32_be(out_packet + 576, in->payload.length);
    put_u32_be(out_packet + 580, in->evidence.length);

    off = NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES;
    (void)memcpy(
        out_packet + off, in->namespace_id.bytes, in->namespace_id.length);
    off += in->namespace_id.length;
    (void)memcpy(
        out_packet + off, in->service_id.bytes, in->service_id.length);
    off += in->service_id.length;
    (void)memcpy(out_packet + off, in->schema_id.bytes, in->schema_id.length);
    off += in->schema_id.length;
    if (in->payload.length > 0u) {
        (void)memcpy(out_packet + off, in->payload.bytes, in->payload.length);
        off += in->payload.length;
    }
    if (in->evidence.length > 0u) {
        (void)memcpy(
            out_packet + off, in->evidence.bytes, in->evidence.length);
    }

    crc = ninlil_fabric_private_nfl1_crc32c(out_packet, total);
    put_u32_be(out_packet + 12, crc);
    *out_length = total;
    return NINLIL_FABRIC_PRIVATE_NFL1_OK;
}

ninlil_fabric_private_nfl1_status_t ninlil_fabric_private_nfl1_decode(
    const uint8_t *packet,
    uint32_t packet_length,
    ninlil_fabric_private_nfl1_workspace_t *workspace,
    ninlil_fabric_private_nfl1_envelope_t *out,
    uint32_t *out_required_workspace)
{
    uint32_t total_length;
    uint16_t version;
    uint16_t header_length;
    uint32_t stored_crc;
    uint32_t computed_crc;
    uint32_t ns_len;
    uint32_t svc_len;
    uint32_t sch_len;
    uint32_t payload_len;
    uint32_t evidence_len;
    uint32_t body_need;
    uint32_t off;
    ninlil_fabric_private_nfl1_envelope_t tmp;

    if (packet == NULL || workspace == NULL || out == NULL) {
        return NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT;
    }

    if (packet_length > NINLIL_FABRIC_PRIVATE_NFL1_CODEC_CEILING) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }
    if (packet_length < NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }
    if (packet[0] != (uint8_t)'N' || packet[1] != (uint8_t)'F'
        || packet[2] != (uint8_t)'L' || packet[3] != (uint8_t)'1') {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }

    version = get_u16_be(packet + 4);
    if (version != NINLIL_FABRIC_PRIVATE_NFL1_VERSION) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED;
    }
    header_length = get_u16_be(packet + 6);
    if (header_length != NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }
    total_length = get_u32_be(packet + 8);
    if (total_length != packet_length) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }
    if (total_length < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || total_length > NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MAX) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }

    stored_crc = get_u32_be(packet + 12);
    computed_crc = ninlil_fabric_private_nfl1_crc32c(packet, packet_length);
    if (stored_crc != computed_crc) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }

    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.api_version = NINLIL_ABI_VERSION;
    tmp.struct_size = (uint16_t)sizeof(tmp);
    tmp.message_kind = get_u32_be(packet + 16);
    tmp.message_flags = get_u32_be(packet + 20);
    (void)memcpy(tmp.transaction_id.bytes, packet + 24, 16u);
    (void)memcpy(tmp.attempt_id.bytes, packet + 40, 16u);
    (void)memcpy(tmp.event_id.bytes, packet + 56, 16u);
    (void)memcpy(tmp.source_runtime_id.bytes, packet + 72, 16u);
    (void)memcpy(tmp.source_application_id.bytes, packet + 88, 16u);
    (void)memcpy(tmp.source_device_id.bytes, packet + 104, 16u);
    (void)memcpy(tmp.source_installation_id.bytes, packet + 120, 16u);
    (void)memcpy(tmp.source_site_id.bytes, packet + 136, 16u);
    tmp.source_binding_epoch = get_u64_be(packet + 152);
    tmp.source_membership_epoch = get_u64_be(packet + 160);
    tmp.source_flags = get_u32_be(packet + 168);
    (void)memcpy(tmp.target_runtime_id.bytes, packet + 172, 16u);
    (void)memcpy(tmp.target_application_id.bytes, packet + 188, 16u);
    (void)memcpy(tmp.target_device_id.bytes, packet + 204, 16u);
    (void)memcpy(tmp.target_installation_id.bytes, packet + 220, 16u);
    (void)memcpy(tmp.target_site_id.bytes, packet + 236, 16u);
    tmp.target_binding_epoch = get_u64_be(packet + 252);
    tmp.target_membership_epoch = get_u64_be(packet + 260);
    tmp.target_flags = get_u32_be(packet + 268);
    (void)memcpy(tmp.authority_id.bytes, packet + 272, 16u);
    tmp.authority_term = get_u64_be(packet + 288);
    tmp.assignment_epoch = get_u32_be(packet + 296);
    tmp.descriptor_revision = get_u64_be(packet + 300);
    tmp.descriptor_digest.algorithm = get_u16_be(packet + 308);
    (void)memcpy(tmp.descriptor_digest.bytes, packet + 310, 32u);
    tmp.schema_major = get_u16_be(packet + 342);
    tmp.schema_minor = get_u16_be(packet + 344);
    tmp.family = get_u32_be(packet + 346);
    tmp.content_digest.algorithm = get_u16_be(packet + 350);
    (void)memcpy(tmp.content_digest.bytes, packet + 352, 32u);
    tmp.generation = get_u64_be(packet + 384);
    (void)memcpy(tmp.deadline_clock_epoch_id.bytes, packet + 392, 16u);
    tmp.absolute_effect_deadline_ms = get_u64_be(packet + 408);
    tmp.evidence_grace_ms = get_u64_be(packet + 416);
    tmp.required_evidence = get_u32_be(packet + 424);
    tmp.receipt_stage = get_u32_be(packet + 428);
    tmp.disposition = get_u32_be(packet + 432);
    tmp.effect_certainty = get_u32_be(packet + 436);
    tmp.retry_guidance = get_u32_be(packet + 440);
    tmp.cancel_kind = get_u32_be(packet + 444);
    tmp.retry_delay_ms = get_u64_be(packet + 448);
    (void)memcpy(tmp.evidence_time_clock_epoch_id.bytes, packet + 456, 16u);
    tmp.evidence_time_now_ms = get_u64_be(packet + 472);
    tmp.evidence_time_trust = get_u32_be(packet + 480);
    (void)memcpy(tmp.route_policy_id.bytes, packet + 484, 16u);
    tmp.route_policy_revision = get_u64_be(packet + 500);
    tmp.route_policy_digest.algorithm = get_u16_be(packet + 508);
    (void)memcpy(tmp.route_policy_digest.bytes, packet + 510, 32u);
    (void)memcpy(tmp.selected_path_id.bytes, packet + 542, 16u);
    tmp.path_selection_epoch = get_u64_be(packet + 558);
    tmp.route_flags = get_u32_be(packet + 566);
    ns_len = get_u16_be(packet + 570);
    svc_len = get_u16_be(packet + 572);
    sch_len = get_u16_be(packet + 574);
    payload_len = get_u32_be(packet + 576);
    evidence_len = get_u32_be(packet + 580);

    if (ns_len > NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX
        || svc_len > NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX
        || sch_len > NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX
        || payload_len > NINLIL_FABRIC_PRIVATE_NFL1_PAYLOAD_MAX
        || evidence_len > NINLIL_FABRIC_PRIVATE_NFL1_EVIDENCE_MAX) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }
    body_need = ns_len + svc_len + sch_len + payload_len + evidence_len;
    if (NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES + body_need != total_length) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }

    if (tmp.descriptor_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256
        || tmp.content_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256
        || tmp.route_policy_digest.algorithm
            != NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED;
    }
    if (!closed_catalog_decode_ok(&tmp)) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED;
    }

    tmp.namespace_id.length = ns_len;
    tmp.service_id.length = svc_len;
    tmp.schema_id.length = sch_len;
    tmp.payload.length = payload_len;
    tmp.evidence.length = evidence_len;
    /* Temporary borrow of packet only for matrix length checks. */
    tmp.namespace_id.bytes = packet + NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES;
    tmp.service_id.bytes = tmp.namespace_id.bytes + ns_len;
    tmp.schema_id.bytes = tmp.service_id.bytes + svc_len;
    tmp.payload.bytes =
        payload_len > 0u ? tmp.schema_id.bytes + sch_len : NULL;
    tmp.evidence.bytes = evidence_len > 0u
        ? (tmp.schema_id.bytes + sch_len + payload_len)
        : NULL;

    if (!kind_matrix_ok(&tmp)) {
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT;
    }

    if (body_need > sizeof(workspace->bytes)) {
        if (out_required_workspace != NULL) {
            *out_required_workspace = body_need;
        }
        ninlil_fabric_private_nfl1_clear(out);
        return NINLIL_FABRIC_PRIVATE_NFL1_BUFFER_TOO_SMALL;
    }

    off = 0u;
    if (ns_len > 0u) {
        (void)memcpy(
            workspace->bytes + off,
            packet + NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES,
            ns_len);
        tmp.namespace_id.bytes = workspace->bytes + off;
        off += ns_len;
    }
    if (svc_len > 0u) {
        (void)memcpy(
            workspace->bytes + off,
            packet + NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES + ns_len,
            svc_len);
        tmp.service_id.bytes = workspace->bytes + off;
        off += svc_len;
    }
    if (sch_len > 0u) {
        (void)memcpy(
            workspace->bytes + off,
            packet + NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES + ns_len
                + svc_len,
            sch_len);
        tmp.schema_id.bytes = workspace->bytes + off;
        off += sch_len;
    }
    if (payload_len > 0u) {
        (void)memcpy(
            workspace->bytes + off,
            packet + NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES + ns_len
                + svc_len + sch_len,
            payload_len);
        tmp.payload.bytes = workspace->bytes + off;
        off += payload_len;
    } else {
        tmp.payload.bytes = NULL;
    }
    if (evidence_len > 0u) {
        (void)memcpy(
            workspace->bytes + off,
            packet + NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES + ns_len
                + svc_len + sch_len + payload_len,
            evidence_len);
        tmp.evidence.bytes = workspace->bytes + off;
        off += evidence_len;
    } else {
        tmp.evidence.bytes = NULL;
    }

    workspace->used = off;
    *out = tmp;
    if (out_required_workspace != NULL) {
        *out_required_workspace = off;
    }
    return NINLIL_FABRIC_PRIVATE_NFL1_OK;
}

uint32_t ninlil_fabric_private_nfl1_response_slot(
    uint32_t message_kind,
    uint32_t receipt_stage,
    uint32_t disposition,
    uint32_t cancel_kind)
{
    if (message_kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        return receipt_stage;
    }
    if (message_kind == NINLIL_BEARER_MESSAGE_DISPOSITION) {
        return disposition;
    }
    if (message_kind == NINLIL_BEARER_MESSAGE_CANCEL_RESULT) {
        return cancel_kind;
    }
    return 0u;
}

void ninlil_fabric_private_nfl1_foundation_message_digest(
    const uint8_t *packet,
    uint32_t packet_length,
    uint8_t out_digest[32])
{
    static const uint8_t zeroes[86] = {0};
    const uint8_t *parts[7];
    size_t lengths[7];

    if (out_digest == NULL || packet == NULL
        || packet_length < NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES
        || packet_length > NINLIL_FABRIC_PRIVATE_NFL1_CODEC_CEILING) {
        if (out_digest != NULL) {
            ninlil_fabric_private_memzero(out_digest, 32u);
        }
        return;
    }
    parts[0] = packet;
    lengths[0] = 12u;
    parts[1] = zeroes;
    lengths[1] = 4u;
    parts[2] = packet + 16u;
    lengths[2] = 256u;
    parts[3] = zeroes;
    lengths[3] = 28u;
    parts[4] = packet + 300u;
    lengths[4] = 184u;
    parts[5] = zeroes;
    lengths[5] = 86u;
    parts[6] = packet + 570u;
    lengths[6] = (size_t)packet_length - 570u;
    ninlil_fabric_private_tagged_sha256_parts(
        "NINLIL-FABRIC-FOUNDATION-MESSAGE-V1",
        parts,
        lengths,
        7u,
        out_digest);
}

void ninlil_fabric_private_nfl1_service_identity_digest(
    const uint8_t *namespace_id,
    uint16_t namespace_len,
    const uint8_t *service_id,
    uint16_t service_len,
    const uint8_t *schema_id,
    uint16_t schema_len,
    uint64_t descriptor_revision,
    const uint8_t descriptor_digest[32],
    uint16_t schema_major,
    uint16_t schema_minor,
    uint32_t family,
    uint8_t out_digest[32])
{
    uint8_t canonical[2u + 63u + 2u + 63u + 2u + 63u + 8u + 2u + 32u + 2u
        + 2u + 4u];
    uint32_t off = 0u;

    if (out_digest == NULL || namespace_id == NULL || service_id == NULL
        || schema_id == NULL || descriptor_digest == NULL
        || namespace_len == 0u
        || namespace_len > NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX
        || service_len == 0u
        || service_len > NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX
        || schema_len == 0u
        || schema_len > NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX) {
        if (out_digest != NULL) {
            ninlil_fabric_private_memzero(out_digest, 32u);
        }
        return;
    }
    ninlil_fabric_private_put_u16_be(canonical + off, namespace_len);
    off += 2u;
    (void)memcpy(canonical + off, namespace_id, namespace_len);
    off += namespace_len;
    ninlil_fabric_private_put_u16_be(canonical + off, service_len);
    off += 2u;
    (void)memcpy(canonical + off, service_id, service_len);
    off += service_len;
    ninlil_fabric_private_put_u16_be(canonical + off, schema_len);
    off += 2u;
    (void)memcpy(canonical + off, schema_id, schema_len);
    off += schema_len;
    ninlil_fabric_private_put_u64_be(canonical + off, descriptor_revision);
    off += 8u;
    ninlil_fabric_private_put_u16_be(canonical + off, 1u);
    off += 2u;
    (void)memcpy(canonical + off, descriptor_digest, 32u);
    off += 32u;
    ninlil_fabric_private_put_u16_be(canonical + off, schema_major);
    off += 2u;
    ninlil_fabric_private_put_u16_be(canonical + off, schema_minor);
    off += 2u;
    ninlil_fabric_private_put_u32_be(canonical + off, family);
    off += 4u;
    ninlil_fabric_private_tagged_sha256(
        "NINLIL-FABRIC-SERVICE-IDENTITY-V1",
        canonical,
        off,
        out_digest);
    ninlil_fabric_private_memzero(canonical, off);
}
