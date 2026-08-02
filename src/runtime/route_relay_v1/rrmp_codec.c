#include "rrmp_codec.h"
#include "rrmp_util.h"

#include <string.h>

static int magic_eq(const uint8_t *p, const char *m4)
{
    return p[0] == (uint8_t)m4[0] && p[1] == (uint8_t)m4[1] &&
           p[2] == (uint8_t)m4[2] && p[3] == (uint8_t)m4[3];
}

static int bytes_nonzero(const uint8_t *p, size_t n)
{
    uint8_t any = 0u;
    size_t i;
    if (p == NULL) {
        return 0;
    }
    for (i = 0u; i < n; ++i) {
        any = (uint8_t)(any | p[i]);
    }
    return any != 0u;
}

static int bytes_zero(const uint8_t *p, size_t n)
{
    return bytes_nonzero(p, n) ? 0 : 1;
}

static int u64_record_id_valid(uint64_t value)
{
    return value != 0u && value != UINT64_MAX;
}

static int u32_record_id_valid(uint32_t value)
{
    return value != 0u && value != UINT32_MAX;
}

static void copy16(uint8_t *dst, const ninlil_rrmp_id16_t *src)
{
    memcpy(dst, src->bytes, 16u);
}

static void load16(ninlil_rrmp_id16_t *dst, const uint8_t *src)
{
    memcpy(dst->bytes, src, 16u);
}

static void copy32(uint8_t *dst, const ninlil_rrmp_digest32_t *src)
{
    memcpy(dst, src->bytes, 32u);
}

static void load32(ninlil_rrmp_digest32_t *dst, const uint8_t *src)
{
    memcpy(dst->bytes, src, 32u);
}

int ninlil_rrmp_encode_nrm1(
    const ninlil_rrmp_nrm1_fields_t *fields, uint8_t out[NINLIL_RRMP_NRM1_BYTES])
{
    uint8_t digest[32];
    if (fields == NULL || out == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NRM1_BYTES);
    out[0] = 'N';
    out[1] = 'R';
    out[2] = 'M';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, (uint16_t)NINLIL_RRMP_NRM1_BYTES);
    copy16(out + 8, &fields->authority_id);
    ninlil_rrmp_put_u64_be(out + 24, fields->controller_term);
    ninlil_rrmp_put_u64_be(out + 32, fields->route_revision);
    ninlil_rrmp_put_u64_be(out + 40, fields->lease_epoch);
    copy16(out + 48, &fields->authority_clock_epoch_id);
    ninlil_rrmp_put_u64_be(out + 64, fields->lease_expiry_ms);
    ninlil_rrmp_put_u32_be(out + 72, fields->ingress_hop_context_id);
    ninlil_rrmp_put_u16_be(out + 76, fields->route_handle);
    ninlil_rrmp_put_u16_be(out + 78, fields->route_generation);
    copy16(out + 80, &fields->egress_peer_id);
    ninlil_rrmp_put_u32_be(out + 96, fields->egress_hop_context_id);
    ninlil_rrmp_put_u16_be(out + 100, fields->egress_route_handle);
    ninlil_rrmp_put_u16_be(out + 102, fields->egress_route_generation);
    copy16(out + 104, &fields->grant_id);
    ninlil_rrmp_put_u16_be(out + 120, fields->queue_quota_entries);
    ninlil_rrmp_put_u16_be(out + 122, 0u);
    ninlil_rrmp_put_u32_be(out + 124, fields->queue_quota_bytes);
    out[128] = fields->max_hops;
    out[129] = fields->ack_policy;
    out[130] = fields->terminal_flag;
    out[131] = 0u;
    copy16(out + 132, &fields->path_policy_id);
    ninlil_rrmp_put_u64_be(out + 148, fields->path_policy_revision);
    ninlil_rrmp_sha256(out, 156u, digest);
    memcpy(out + 156, digest, 32u);
    ninlil_rrmp_put_u32_be(out + 188, ninlil_rrmp_crc32c(out, 188u));
    return 1;
}

int ninlil_rrmp_decode_nrm1(
    const uint8_t in[NINLIL_RRMP_NRM1_BYTES], ninlil_rrmp_nrm1_fields_t *out)
{
    uint8_t digest[32];
    uint32_t crc;
    if (in == NULL || out == NULL) {
        return 0;
    }
    if (!magic_eq(in, "NRM1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) != NINLIL_RRMP_NRM1_BYTES) {
        return 0;
    }
    ninlil_rrmp_sha256(in, 156u, digest);
    if (!ninlil_rrmp_memeq(digest, in + 156, 32u)) {
        return 0;
    }
    crc = ninlil_rrmp_crc32c(in, 188u);
    if (crc != ninlil_rrmp_get_u32_be(in + 188)) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    load16(&out->authority_id, in + 8);
    out->controller_term = ninlil_rrmp_get_u64_be(in + 24);
    out->route_revision = ninlil_rrmp_get_u64_be(in + 32);
    out->lease_epoch = ninlil_rrmp_get_u64_be(in + 40);
    load16(&out->authority_clock_epoch_id, in + 48);
    out->lease_expiry_ms = ninlil_rrmp_get_u64_be(in + 64);
    out->ingress_hop_context_id = ninlil_rrmp_get_u32_be(in + 72);
    out->route_handle = ninlil_rrmp_get_u16_be(in + 76);
    out->route_generation = ninlil_rrmp_get_u16_be(in + 78);
    load16(&out->egress_peer_id, in + 80);
    out->egress_hop_context_id = ninlil_rrmp_get_u32_be(in + 96);
    out->egress_route_handle = ninlil_rrmp_get_u16_be(in + 100);
    out->egress_route_generation = ninlil_rrmp_get_u16_be(in + 102);
    load16(&out->grant_id, in + 104);
    out->queue_quota_entries = ninlil_rrmp_get_u16_be(in + 120);
    out->queue_quota_bytes = ninlil_rrmp_get_u32_be(in + 124);
    out->max_hops = in[128];
    out->ack_policy = in[129];
    out->terminal_flag = in[130];
    load16(&out->path_policy_id, in + 132);
    out->path_policy_revision = ninlil_rrmp_get_u64_be(in + 148);
    return 1;
}

int ninlil_rrmp_materialize_exact(
    const ninlil_rrmp_nrm1_fields_t *fields,
    uint8_t out[NINLIL_RRMP_EXACT_BODY_BYTES])
{
    if (fields == NULL || out == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_EXACT_BODY_BYTES);
    copy16(out + 0, &fields->egress_peer_id);
    ninlil_rrmp_put_u32_be(out + 16, fields->egress_hop_context_id);
    ninlil_rrmp_put_u16_be(out + 20, fields->egress_route_handle);
    ninlil_rrmp_put_u16_be(out + 22, fields->egress_route_generation);
    copy16(out + 24, &fields->authority_id);
    ninlil_rrmp_put_u64_be(out + 40, fields->lease_epoch);
    ninlil_rrmp_put_u64_be(out + 48, fields->lease_expiry_ms);
    copy16(out + 56, &fields->grant_id);
    ninlil_rrmp_put_u16_be(out + 72, fields->queue_quota_entries);
    ninlil_rrmp_put_u16_be(out + 74, 0u);
    ninlil_rrmp_put_u32_be(out + 76, fields->queue_quota_bytes);
    out[80] = fields->max_hops;
    out[81] = fields->ack_policy;
    out[82] = fields->terminal_flag;
    out[83] = 0u;
    ninlil_rrmp_put_u32_be(out + 84, fields->ingress_hop_context_id);
    ninlil_rrmp_put_u16_be(out + 88, fields->route_handle);
    ninlil_rrmp_put_u16_be(out + 90, fields->route_generation);
    ninlil_rrmp_put_u32_be(out + 92, 0u);
    return 1;
}

int ninlil_rrmp_encode_slot(
    uint8_t state,
    const ninlil_rrmp_nrm1_fields_t *fields,
    uint64_t next_admission_seq,
    const ninlil_rrmp_drain_fence_t *drain_or_null,
    uint8_t out[NINLIL_RRMP_SLOT_BYTES])
{
    uint8_t mgmt[NINLIL_RRMP_NRM1_BYTES];
    uint8_t exact[NINLIL_RRMP_EXACT_BODY_BYTES];
    uint8_t digest[32];
    if (fields == NULL || out == NULL) {
        return 0;
    }
    if (!ninlil_rrmp_encode_nrm1(fields, mgmt)) {
        return 0;
    }
    if (!ninlil_rrmp_materialize_exact(fields, exact)) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_SLOT_BYTES);
    out[0] = state;
    ninlil_rrmp_put_u32_be(out + 4, fields->ingress_hop_context_id);
    ninlil_rrmp_put_u16_be(out + 8, fields->route_handle);
    ninlil_rrmp_put_u16_be(out + 10, fields->route_generation);
    memcpy(out + 12, mgmt, NINLIL_RRMP_NRM1_BYTES);
    memcpy(out + 268, exact, NINLIL_RRMP_EXACT_BODY_BYTES);
    copy16(out + 364, &fields->authority_clock_epoch_id);
    ninlil_rrmp_put_u64_be(out + 380, fields->lease_expiry_ms);
    if (drain_or_null != NULL) {
        ninlil_rrmp_put_u64_be(out + 388, drain_or_null->drain_fence);
        ninlil_rrmp_put_u64_be(out + 396, drain_or_null->route_revision);
        ninlil_rrmp_put_u64_be(out + 404, drain_or_null->drain_deadline_ms);
        ninlil_rrmp_put_u64_be(out + 412, drain_or_null->lease_deadline_ms);
    }
    ninlil_rrmp_put_u64_be(out + 420, next_admission_seq);
    ninlil_rrmp_sha256(out, 428u, digest);
    memcpy(out + 428, digest, 32u);
    ninlil_rrmp_put_u32_be(out + 460, ninlil_rrmp_crc32c(out, 460u));
    return 1;
}

int ninlil_rrmp_decode_slot_state(
    const uint8_t in[NINLIL_RRMP_SLOT_BYTES],
    uint8_t *state_out,
    ninlil_rrmp_nrm1_fields_t *fields_out,
    uint64_t *next_admission_seq_out)
{
    uint8_t digest[32];
    uint32_t crc;
    if (in == NULL) {
        return 0;
    }
    ninlil_rrmp_sha256(in, 428u, digest);
    if (!ninlil_rrmp_memeq(digest, in + 428, 32u)) {
        return 0;
    }
    crc = ninlil_rrmp_crc32c(in, 460u);
    if (crc != ninlil_rrmp_get_u32_be(in + 460)) {
        return 0;
    }
    if (state_out != NULL) {
        *state_out = in[0];
    }
    if (fields_out != NULL) {
        if (!ninlil_rrmp_decode_nrm1(in + 12, fields_out)) {
            return 0;
        }
    }
    if (next_admission_seq_out != NULL) {
        *next_admission_seq_out = ninlil_rrmp_get_u64_be(in + 420);
    }
    return 1;
}

int ninlil_rrmp_encode_nrp1(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots[NINLIL_RRMP_SLOTS_PER_PAGE],
    uint8_t out[NINLIL_RRMP_NRP1_BYTES])
{
    uint16_t bitmap = 0u;
    size_t i;
    if (out == NULL || page_index >= NINLIL_RRMP_PAGE_COUNT) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NRP1_BYTES);
    out[0] = 'N';
    out[1] = 'R';
    out[2] = 'P';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, page_index);
    ninlil_rrmp_put_u32_be(out + 8, page_generation);
    for (i = 0u; i < NINLIL_RRMP_SLOTS_PER_PAGE; ++i) {
        if (slots != NULL && slots[i] != NULL) {
            bitmap = (uint16_t)(bitmap | (uint16_t)(1u << i));
            memcpy(
                out + NINLIL_RRMP_NRP1_HEADER_BYTES + i * NINLIL_RRMP_SLOT_BYTES,
                slots[i],
                NINLIL_RRMP_SLOT_BYTES);
        }
    }
    ninlil_rrmp_put_u16_be(out + 12, bitmap);
    ninlil_rrmp_put_u16_be(out + 14, 0u);
    ninlil_rrmp_put_u32_be(out + 16, 0u);
    ninlil_rrmp_put_u32_be(out + 16, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NRP1_BYTES));
    return 1;
}

int ninlil_rrmp_validate_nrp1(const uint8_t in[NINLIL_RRMP_NRP1_BYTES])
{
    uint32_t stored;
    if (in == NULL || !magic_eq(in, "NRP1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) >= NINLIL_RRMP_PAGE_COUNT) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 16);
    return ninlil_rrmp_crc32c_zeroed_u32_be_field(
               in, NINLIL_RRMP_NRP1_BYTES, 16u) == stored
               ? 1
               : 0;
}

int ninlil_rrmp_encode_nrd1(
    uint64_t directory_generation,
    const ninlil_rrmp_id16_t *authority_id,
    uint64_t controller_term,
    const uint32_t route_page_gens[NINLIL_RRMP_PAGE_COUNT],
    const uint32_t evidence_page_gens[NINLIL_RRMP_NEP1_PAGE_COUNT],
    uint8_t out[NINLIL_RRMP_DIR_BYTES])
{
    uint16_t route_bits = 0u;
    uint16_t evi_bits = 0u;
    size_t i;
    if (out == NULL || authority_id == NULL || route_page_gens == NULL ||
        evidence_page_gens == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_DIR_BYTES);
    out[0] = 'N';
    out[1] = 'R';
    out[2] = 'D';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, (uint16_t)NINLIL_RRMP_DIR_BYTES);
    ninlil_rrmp_put_u64_be(out + 8, directory_generation);
    copy16(out + 16, authority_id);
    ninlil_rrmp_put_u64_be(out + 32, controller_term);
    for (i = 0u; i < NINLIL_RRMP_PAGE_COUNT; ++i) {
        if (route_page_gens[i] != 0u) {
            route_bits = (uint16_t)(route_bits | (uint16_t)(1u << i));
        }
        ninlil_rrmp_put_u32_be(out + 44u + i * 4u, route_page_gens[i]);
    }
    for (i = 0u; i < NINLIL_RRMP_NEP1_PAGE_COUNT; ++i) {
        if (evidence_page_gens[i] != 0u) {
            evi_bits = (uint16_t)(evi_bits | (uint16_t)(1u << i));
        }
        ninlil_rrmp_put_u32_be(out + 108u + i * 4u, evidence_page_gens[i]);
    }
    ninlil_rrmp_put_u16_be(out + 40, route_bits);
    ninlil_rrmp_put_u16_be(out + 42, evi_bits);
    ninlil_rrmp_put_u32_be(out + 252, 0u);
    ninlil_rrmp_put_u32_be(out + 252, ninlil_rrmp_crc32c(out, NINLIL_RRMP_DIR_BYTES));
    return 1;
}

int ninlil_rrmp_validate_nrd1(const uint8_t in[NINLIL_RRMP_DIR_BYTES])
{
    uint32_t stored;
    if (in == NULL || !magic_eq(in, "NRD1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) != NINLIL_RRMP_DIR_BYTES) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 252);
    return ninlil_rrmp_crc32c_zeroed_u32_be_field(
               in, NINLIL_RRMP_DIR_BYTES, 252u) == stored
               ? 1
               : 0;
}

int ninlil_rrmp_encode_nev1(
    const ninlil_rrmp_nev1_fields_t *fields, uint8_t out[NINLIL_RRMP_NEV1_BYTES])
{
    uint8_t digest[32];
    if (fields == NULL || out == NULL) {
        return 0;
    }
    if (fields->lifecycle != NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE &&
        fields->lifecycle != NINLIL_RRMP_EVIDENCE_LIFECYCLE_COMPLETED) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NEV1_BYTES);
    out[0] = 'N';
    out[1] = 'E';
    out[2] = 'V';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, (uint16_t)NINLIL_RRMP_NEV1_BYTES);
    ninlil_rrmp_put_u16_be(out + 8, fields->route_handle);
    ninlil_rrmp_put_u16_be(out + 10, fields->route_generation);
    ninlil_rrmp_put_u64_be(out + 12, fields->admission_seq);
    copy32(out + 20, &fields->e2e_header_digest);
    ninlil_rrmp_put_u64_be(out + 52, fields->outer_rx_counter);
    ninlil_rrmp_put_u64_be(out + 60, fields->outer_tx_counter);
    copy16(out + 68, &fields->local_runtime_id);
    out[84] = fields->hop_remaining_in;
    out[85] = fields->hop_remaining_out;
    out[86] = fields->lifecycle;
    out[87] = 0u;
    ninlil_rrmp_put_u32_be(out + 88, fields->result_status);
    ninlil_rrmp_sha256(out, 92u, digest);
    memcpy(out + 92, digest, 32u);
    ninlil_rrmp_put_u32_be(out + 124, ninlil_rrmp_crc32c(out, 124u));
    return 1;
}

int ninlil_rrmp_decode_nev1(
    const uint8_t in[NINLIL_RRMP_NEV1_BYTES], ninlil_rrmp_nev1_fields_t *out)
{
    if (!ninlil_rrmp_validate_nev1(in) || out == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->route_handle = ninlil_rrmp_get_u16_be(in + 8);
    out->route_generation = ninlil_rrmp_get_u16_be(in + 10);
    out->admission_seq = ninlil_rrmp_get_u64_be(in + 12);
    load32(&out->e2e_header_digest, in + 20);
    out->outer_rx_counter = ninlil_rrmp_get_u64_be(in + 52);
    out->outer_tx_counter = ninlil_rrmp_get_u64_be(in + 60);
    load16(&out->local_runtime_id, in + 68);
    out->hop_remaining_in = in[84];
    out->hop_remaining_out = in[85];
    out->lifecycle = in[86];
    out->result_status = ninlil_rrmp_get_u32_be(in + 88);
    return 1;
}

int ninlil_rrmp_validate_nev1(const uint8_t in[NINLIL_RRMP_NEV1_BYTES])
{
    uint8_t digest[32];
    if (in == NULL || !magic_eq(in, "NEV1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) != NINLIL_RRMP_NEV1_BYTES) {
        return 0;
    }
    if (in[86] != NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE &&
        in[86] != NINLIL_RRMP_EVIDENCE_LIFECYCLE_COMPLETED) {
        return 0;
    }
    ninlil_rrmp_sha256(in, 92u, digest);
    if (!ninlil_rrmp_memeq(digest, in + 92, 32u)) {
        return 0;
    }
    return ninlil_rrmp_crc32c(in, 124u) == ninlil_rrmp_get_u32_be(in + 124) ? 1
                                                                            : 0;
}

int ninlil_rrmp_encode_nep1(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots,
    size_t slot_count,
    uint8_t out[NINLIL_RRMP_NEP1_BYTES])
{
    size_t i;
    if (out == NULL || page_index >= NINLIL_RRMP_NEP1_PAGE_COUNT ||
        slot_count > NINLIL_RRMP_NEP1_SLOTS) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NEP1_BYTES);
    out[0] = 'N';
    out[1] = 'E';
    out[2] = 'P';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, page_index);
    ninlil_rrmp_put_u32_be(out + 8, page_generation);
    ninlil_rrmp_put_u32_be(out + 12, (uint32_t)slot_count);
    for (i = 0u; i < slot_count; ++i) {
        if (slots == NULL) {
            return 0;
        }
        memcpy(
            out + NINLIL_RRMP_NEP1_HEADER_BYTES + i * NINLIL_RRMP_NEV1_BYTES,
            slots + i * NINLIL_RRMP_NEV1_BYTES,
            NINLIL_RRMP_NEV1_BYTES);
    }
    ninlil_rrmp_put_u32_be(out + 20, 0u);
    ninlil_rrmp_put_u32_be(out + 20, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NEP1_BYTES));
    return 1;
}

int ninlil_rrmp_validate_nep1(const uint8_t in[NINLIL_RRMP_NEP1_BYTES])
{
    uint32_t stored;
    uint32_t count;
    if (in == NULL || !magic_eq(in, "NEP1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) >= NINLIL_RRMP_NEP1_PAGE_COUNT) {
        return 0;
    }
    count = ninlil_rrmp_get_u32_be(in + 12);
    if (count > NINLIL_RRMP_NEP1_SLOTS) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 20);
    return ninlil_rrmp_crc32c_zeroed_u32_be_field(
               in, NINLIL_RRMP_NEP1_BYTES, 20u) == stored
               ? 1
               : 0;
}

int ninlil_rrmp_parent_set_digest(
    const ninlil_rrmp_id16_t *parent_ids,
    uint8_t count,
    ninlil_rrmp_digest32_t *out)
{
    uint8_t material[NINLIL_RRMP_PARENT_MAX * 16u];
    size_t i;
    if (parent_ids == NULL || out == NULL || count < 1u ||
        count > NINLIL_RRMP_PARENT_MAX) {
        return 0;
    }
    for (i = 0u; i < count; ++i) {
        memcpy(material + i * 16u, parent_ids[i].bytes, 16u);
    }
    ninlil_rrmp_sha256(material, (size_t)count * 16u, out->bytes);
    return 1;
}

int ninlil_rrmp_encode_nps1(
    const ninlil_rrmp_nps1_fields_t *fields, uint8_t out[NINLIL_RRMP_NPS1_BYTES])
{
    ninlil_rrmp_digest32_t dig;
    uint8_t body_digest[32];
    size_t i;
    if (fields == NULL || out == NULL) {
        return 0;
    }
    if (!bytes_nonzero(fields->owner_scope_id.bytes, 16u) ||
        !bytes_nonzero(fields->parent_set_id.bytes, 16u) ||
        !u64_record_id_valid(fields->parent_set_revision) ||
        fields->parent_count < 1u ||
        fields->parent_count > NINLIL_RRMP_PARENT_MAX) {
        return 0;
    }
    for (i = 0u; i < fields->parent_count; ++i) {
        if (!bytes_nonzero(fields->parent_ids[i].bytes, 16u)) {
            return 0;
        }
    }
    if (!ninlil_rrmp_parent_set_digest(
            fields->parent_ids, fields->parent_count, &dig)) {
        return 0;
    }
    if (!ninlil_rrmp_memeq(
            fields->parent_set_digest.bytes, dig.bytes, sizeof(dig.bytes))) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NPS1_BYTES);
    out[0] = 'N';
    out[1] = 'P';
    out[2] = 'S';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, (uint16_t)NINLIL_RRMP_NPS1_BYTES);
    copy16(out + 8, &fields->owner_scope_id);
    copy16(out + 24, &fields->parent_set_id);
    ninlil_rrmp_put_u64_be(out + 40, fields->parent_set_revision);
    out[48] = fields->parent_count;
    memcpy(out + 52, dig.bytes, 32u);
    for (i = 0u; i < fields->parent_count; ++i) {
        copy16(out + 84u + i * 16u, &fields->parent_ids[i]);
    }
    ninlil_rrmp_sha256(out, 212u, body_digest);
    memcpy(out + 212, body_digest, 32u);
    ninlil_rrmp_put_u32_be(out + 244, 0u);
    ninlil_rrmp_put_u32_be(out + 244, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NPS1_BYTES));
    return 1;
}

int ninlil_rrmp_decode_nps1(
    const uint8_t in[NINLIL_RRMP_NPS1_BYTES], ninlil_rrmp_nps1_fields_t *out)
{
    size_t i;
    if (!ninlil_rrmp_validate_nps1(in) || out == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    load16(&out->owner_scope_id, in + 8);
    load16(&out->parent_set_id, in + 24);
    out->parent_set_revision = ninlil_rrmp_get_u64_be(in + 40);
    out->parent_count = in[48];
    load32(&out->parent_set_digest, in + 52);
    for (i = 0u; i < out->parent_count && i < NINLIL_RRMP_PARENT_MAX; ++i) {
        load16(&out->parent_ids[i], in + 84u + i * 16u);
    }
    return 1;
}

int ninlil_rrmp_validate_nps1(const uint8_t in[NINLIL_RRMP_NPS1_BYTES])
{
    uint8_t dig[32];
    uint32_t stored;
    uint8_t count;
    ninlil_rrmp_id16_t ids[NINLIL_RRMP_PARENT_MAX];
    ninlil_rrmp_digest32_t expected;
    size_t i;
    if (in == NULL || !magic_eq(in, "NPS1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) != NINLIL_RRMP_NPS1_BYTES) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 244);
    if (ninlil_rrmp_crc32c_zeroed_u32_be_field(
            in, NINLIL_RRMP_NPS1_BYTES, 244u) != stored) {
        return 0;
    }
    ninlil_rrmp_sha256(in, 212u, dig);
    if (!ninlil_rrmp_memeq(dig, in + 212, 32u)) {
        return 0;
    }
    if (!bytes_zero(in + 49u, 3u) ||
        !bytes_zero(in + 248u, 8u)) {
        return 0;
    }
    if (!bytes_nonzero(in + 8u, 16u) ||
        !bytes_nonzero(in + 24u, 16u) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 40u))) {
        return 0;
    }
    count = in[48];
    if (count < 1u || count > NINLIL_RRMP_PARENT_MAX) {
        return 0;
    }
    for (i = 0u; i < count; ++i) {
        if (!bytes_nonzero(in + 84u + i * 16u, 16u)) {
            return 0;
        }
        load16(&ids[i], in + 84u + i * 16u);
    }
    if (!bytes_zero(
            in + 84u + (size_t)count * 16u,
            ((size_t)NINLIL_RRMP_PARENT_MAX - count) * 16u)) {
        return 0;
    }
    if (!ninlil_rrmp_parent_set_digest(ids, count, &expected)) {
        return 0;
    }
    if (!ninlil_rrmp_memeq(expected.bytes, in + 52, 32u)) {
        return 0;
    }
    return 1;
}

int ninlil_rrmp_encode_npp1(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots[NINLIL_RRMP_NPP1_SLOTS],
    uint8_t out[NINLIL_RRMP_NPP1_BYTES])
{
    size_t i;
    if (out == NULL || page_index >= NINLIL_RRMP_NPP1_PAGE_COUNT ||
        page_generation == 0u || page_generation == UINT32_MAX) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NPP1_BYTES);
    out[0] = 'N';
    out[1] = 'P';
    out[2] = 'P';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, page_index);
    ninlil_rrmp_put_u32_be(out + 8, page_generation);
    for (i = 0u; i < NINLIL_RRMP_NPP1_SLOTS; ++i) {
        if (slots != NULL && slots[i] != NULL) {
            if (!ninlil_rrmp_validate_nps1(slots[i])) {
                return 0;
            }
            memcpy(
                out + NINLIL_RRMP_NPP1_HEADER_BYTES + i * NINLIL_RRMP_NPS1_BYTES,
                slots[i],
                NINLIL_RRMP_NPS1_BYTES);
        }
    }
    ninlil_rrmp_put_u32_be(out + 12, 0u);
    ninlil_rrmp_put_u32_be(out + 12, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NPP1_BYTES));
    return 1;
}

int ninlil_rrmp_validate_npp1(const uint8_t in[NINLIL_RRMP_NPP1_BYTES])
{
    uint32_t stored;
    size_t i;
    if (in == NULL || !magic_eq(in, "NPP1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 12);
    if (ninlil_rrmp_crc32c_zeroed_u32_be_field(
            in, NINLIL_RRMP_NPP1_BYTES, 12u) != stored) {
        return 0;
    }
    if (!bytes_zero(
            in + NINLIL_RRMP_NPP1_HEADER_BYTES +
                NINLIL_RRMP_NPP1_SLOTS * NINLIL_RRMP_NPS1_BYTES,
            NINLIL_RRMP_NPP1_PAD_BYTES)) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) >= NINLIL_RRMP_NPP1_PAGE_COUNT ||
        !u32_record_id_valid(ninlil_rrmp_get_u32_be(in + 8u))) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_NPP1_SLOTS; ++i) {
        const uint8_t *slot =
            in + NINLIL_RRMP_NPP1_HEADER_BYTES +
            i * NINLIL_RRMP_NPS1_BYTES;
        if (!bytes_zero(slot, NINLIL_RRMP_NPS1_BYTES) &&
            !ninlil_rrmp_validate_nps1(slot)) {
            return 0;
        }
    }
    return 1;
}

int ninlil_rrmp_encode_noa1(
    const ninlil_rrmp_noa1_fields_t *fields, uint8_t out[NINLIL_RRMP_NOA1_BYTES])
{
    uint8_t dig[32];
    if (fields == NULL || out == NULL ||
        !bytes_nonzero(fields->owner_scope_id.bytes, 16u) ||
        !bytes_nonzero(fields->authority_id.bytes, 16u) ||
        !u64_record_id_valid(fields->controller_term) ||
        !u64_record_id_valid(fields->assignment_epoch) ||
        !u64_record_id_valid(fields->assignment_revision) ||
        !bytes_nonzero(fields->owner_controller_id.bytes, 16u) ||
        !bytes_nonzero(fields->owner_cell_id.bytes, 16u) ||
        fields->direction > 1u ||
        !u32_record_id_valid(fields->e2e_context_id) ||
        !u64_record_id_valid(fields->key_generation) ||
        !bytes_nonzero(fields->e2e_security_id.bytes, 16u) ||
        !u64_record_id_valid(fields->e2e_security_epoch) ||
        !bytes_nonzero(fields->e2e_binding_digest.bytes, 32u) ||
        !bytes_nonzero(fields->authority_clock_epoch_id.bytes, 16u) ||
        !u64_record_id_valid(fields->lease_not_after_authority_ms) ||
        !bytes_nonzero(fields->handoff_token_digest.bytes, 32u) ||
        !bytes_nonzero(fields->parent_set_digest.bytes, 32u) ||
        fields->parent_set_count < 1u ||
        fields->parent_set_count > NINLIL_RRMP_PARENT_MAX ||
        !bytes_nonzero(fields->parent_set_id.bytes, 16u)) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NOA1_BYTES);
    out[0] = 'N';
    out[1] = 'O';
    out[2] = 'A';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, (uint16_t)NINLIL_RRMP_NOA1_BYTES);
    copy16(out + 8, &fields->owner_scope_id);
    copy16(out + 24, &fields->authority_id);
    ninlil_rrmp_put_u64_be(out + 40, fields->controller_term);
    ninlil_rrmp_put_u64_be(out + 48, fields->assignment_epoch);
    ninlil_rrmp_put_u64_be(out + 56, fields->assignment_revision);
    copy16(out + 64, &fields->owner_controller_id);
    copy16(out + 80, &fields->owner_cell_id);
    out[96] = fields->direction;
    ninlil_rrmp_put_u32_be(out + 100, fields->e2e_context_id);
    ninlil_rrmp_put_u64_be(out + 104, fields->key_generation);
    copy16(out + 112, &fields->e2e_security_id);
    ninlil_rrmp_put_u64_be(out + 128, fields->e2e_security_epoch);
    copy32(out + 136, &fields->e2e_binding_digest);
    copy16(out + 168, &fields->authority_clock_epoch_id);
    ninlil_rrmp_put_u64_be(out + 184, fields->lease_not_after_authority_ms);
    copy32(out + 192, &fields->handoff_token_digest);
    ninlil_rrmp_sha256(out, 224u, dig);
    memcpy(out + 224, dig, 32u);
    copy32(out + 260, &fields->parent_set_digest);
    out[292] = fields->parent_set_count;
    copy16(out + 296, &fields->parent_set_id);
    ninlil_rrmp_put_u32_be(out + 256, 0u);
    ninlil_rrmp_put_u32_be(out + 256, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NOA1_BYTES));
    return 1;
}

int ninlil_rrmp_decode_noa1(
    const uint8_t in[NINLIL_RRMP_NOA1_BYTES], ninlil_rrmp_noa1_fields_t *out)
{
    if (!ninlil_rrmp_validate_noa1(in) || out == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    load16(&out->owner_scope_id, in + 8);
    load16(&out->authority_id, in + 24);
    out->controller_term = ninlil_rrmp_get_u64_be(in + 40);
    out->assignment_epoch = ninlil_rrmp_get_u64_be(in + 48);
    out->assignment_revision = ninlil_rrmp_get_u64_be(in + 56);
    load16(&out->owner_controller_id, in + 64);
    load16(&out->owner_cell_id, in + 80);
    out->direction = in[96];
    out->e2e_context_id = ninlil_rrmp_get_u32_be(in + 100);
    out->key_generation = ninlil_rrmp_get_u64_be(in + 104);
    load16(&out->e2e_security_id, in + 112);
    out->e2e_security_epoch = ninlil_rrmp_get_u64_be(in + 128);
    load32(&out->e2e_binding_digest, in + 136);
    load16(&out->authority_clock_epoch_id, in + 168);
    out->lease_not_after_authority_ms = ninlil_rrmp_get_u64_be(in + 184);
    load32(&out->handoff_token_digest, in + 192);
    load32(&out->parent_set_digest, in + 260);
    out->parent_set_count = in[292];
    load16(&out->parent_set_id, in + 296);
    return 1;
}

int ninlil_rrmp_validate_noa1(const uint8_t in[NINLIL_RRMP_NOA1_BYTES])
{
    uint8_t dig[32];
    uint32_t stored;
    if (in == NULL || !magic_eq(in, "NOA1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) != NINLIL_RRMP_NOA1_BYTES) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 256);
    if (ninlil_rrmp_crc32c_zeroed_u32_be_field(
            in, NINLIL_RRMP_NOA1_BYTES, 256u) != stored) {
        return 0;
    }
    ninlil_rrmp_sha256(in, 224u, dig);
    if (!ninlil_rrmp_memeq(dig, in + 224, 32u)) {
        return 0;
    }
    if (!bytes_zero(in + 97u, 3u) ||
        !bytes_zero(in + 293u, 3u) ||
        !bytes_zero(in + 312u, 88u)) {
        return 0;
    }
    if (!bytes_nonzero(in + 8u, 16u) ||
        !bytes_nonzero(in + 24u, 16u) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 40u)) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 48u)) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 56u)) ||
        !bytes_nonzero(in + 64u, 16u) ||
        !bytes_nonzero(in + 80u, 16u) ||
        in[96u] > 1u ||
        !u32_record_id_valid(ninlil_rrmp_get_u32_be(in + 100u)) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 104u)) ||
        !bytes_nonzero(in + 112u, 16u) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 128u)) ||
        !bytes_nonzero(in + 136u, 32u) ||
        !bytes_nonzero(in + 168u, 16u) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 184u)) ||
        !bytes_nonzero(in + 192u, 32u) ||
        !bytes_nonzero(in + 260u, 32u) ||
        in[292u] < 1u || in[292u] > NINLIL_RRMP_PARENT_MAX ||
        !bytes_nonzero(in + 296u, 16u)) {
        return 0;
    }
    return 1;
}

int ninlil_rrmp_authority_commit_digest(
    const uint8_t noa1_body_digest[32],
    const uint8_t nps1_record_digest[32],
    const uint8_t handoff_token_digest[32],
    uint64_t controller_term,
    uint64_t assignment_revision,
    ninlil_rrmp_digest32_t *out)
{
    /* domain(22) + noa1(32) + nps1(32) + token(32) + term(8) + rev(8) = 134 */
    uint8_t pre[134];
    static const char domain[] = "NINLIL-PARENT-COMMIT-V1";
    if (noa1_body_digest == NULL || nps1_record_digest == NULL ||
        handoff_token_digest == NULL || out == NULL) {
        return 0;
    }
    memcpy(pre, domain, 22u);
    memcpy(pre + 22, noa1_body_digest, 32u);
    memcpy(pre + 54, nps1_record_digest, 32u);
    memcpy(pre + 86, handoff_token_digest, 32u);
    ninlil_rrmp_put_u64_be(pre + 118, controller_term);
    ninlil_rrmp_put_u64_be(pre + 126, assignment_revision);
    ninlil_rrmp_sha256(pre, 134u, out->bytes);
    return 1;
}

int ninlil_rrmp_encode_nph1(
    const ninlil_rrmp_nph1_fields_t *fields, uint8_t out[NINLIL_RRMP_NPH1_BYTES])
{
    uint8_t dig[32];
    if (fields == NULL || out == NULL) {
        return 0;
    }
    if (!bytes_nonzero(fields->authority_id.bytes, 16u) ||
        !bytes_nonzero(fields->writer_controller_id.bytes, 16u) ||
        fields->controller_term == 0u ||
        fields->controller_term == UINT64_MAX ||
        fields->writer_epoch == 0u ||
        fields->writer_epoch == UINT64_MAX ||
        fields->lease_not_after_ms == 0u ||
        fields->lease_not_after_ms == UINT64_MAX ||
        !bytes_nonzero(fields->authority_clock_epoch_id.bytes, 16u) ||
        !bytes_nonzero(fields->writer_proof_digest.bytes, 32u) ||
        !bytes_nonzero(fields->authority_commit_digest.bytes, 32u) ||
        fields->header_generation == 0u ||
        fields->header_generation == UINT64_MAX ||
        (fields->assignment_page_bitmap & 0xff00u) != 0u ||
        (fields->token_page_bitmap & 0xff00u) != 0u) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NPH1_BYTES);
    out[0] = 'N';
    out[1] = 'P';
    out[2] = 'H';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, (uint16_t)NINLIL_RRMP_NPH1_BYTES);
    copy16(out + 8, &fields->authority_id);
    copy16(out + 24, &fields->writer_controller_id);
    ninlil_rrmp_put_u64_be(out + 40, fields->controller_term);
    ninlil_rrmp_put_u64_be(out + 48, fields->writer_epoch);
    ninlil_rrmp_put_u64_be(out + 56, fields->lease_not_after_ms);
    copy16(out + 64, &fields->authority_clock_epoch_id);
    copy32(out + 80, &fields->writer_proof_digest);
    ninlil_rrmp_put_u64_be(out + 112, fields->header_generation);
    ninlil_rrmp_put_u16_be(out + 120, fields->assignment_page_bitmap);
    ninlil_rrmp_put_u16_be(out + 122, fields->token_page_bitmap);
    copy32(out + 128, &fields->authority_commit_digest);
    ninlil_rrmp_sha256(out, 160u, dig);
    memcpy(out + 160, dig, 32u);
    ninlil_rrmp_put_u32_be(out + 192, 0u);
    ninlil_rrmp_put_u32_be(out + 192, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NPH1_BYTES));
    return 1;
}

int ninlil_rrmp_validate_nph1(const uint8_t in[NINLIL_RRMP_NPH1_BYTES])
{
    uint8_t dig[32];
    uint32_t stored;
    if (in == NULL || !magic_eq(in, "NPH1")) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6) != NINLIL_RRMP_NPH1_BYTES) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 192);
    if (ninlil_rrmp_crc32c_zeroed_u32_be_field(
            in, NINLIL_RRMP_NPH1_BYTES, 192u) != stored) {
        return 0;
    }
    ninlil_rrmp_sha256(in, 160u, dig);
    if (!ninlil_rrmp_memeq(dig, in + 160, 32u)) {
        return 0;
    }
    if (ninlil_rrmp_get_u32_be(in + 124u) != 0u ||
        !bytes_zero(in + 196u, 60u)) {
        return 0;
    }
    if (!bytes_nonzero(in + 8u, 16u) ||
        !bytes_nonzero(in + 24u, 16u) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 40u)) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 48u)) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 56u)) ||
        !bytes_nonzero(in + 64u, 16u) ||
        !bytes_nonzero(in + 80u, 32u) ||
        !bytes_nonzero(in + 128u, 32u) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(in + 112u)) ||
        (ninlil_rrmp_get_u16_be(in + 120u) & 0xff00u) != 0u ||
        (ninlil_rrmp_get_u16_be(in + 122u) & 0xff00u) != 0u) {
        return 0;
    }
    return 1;
}

int ninlil_rrmp_derive_owner_scope_id(
    const uint8_t endpoint_runtime_id[16],
    uint8_t direction,
    const uint8_t *namespace_bytes,
    uint16_t namespace_len,
    const uint8_t *service_bytes,
    uint16_t service_len,
    uint16_t traffic_class,
    const uint8_t path_policy_id[16],
    uint8_t owner_scope_id_out[16])
{
    /*
     * domain(21) + endpoint(16) + direction(1) + ns_len(2) + ns(<=63) +
     * svc_len(2) + svc(<=63) + traffic(2) + path_policy(16) <= 186
     */
    uint8_t pre[192];
    uint8_t dig[32];
    size_t off = 0u;
    static const char domain[] = "NINLIL-OWNER-SCOPE-V1";
    size_t dlen = sizeof(domain) - 1u;
    size_t i;
    size_t z = 0u;
    if (endpoint_runtime_id == NULL || path_policy_id == NULL ||
        owner_scope_id_out == NULL) {
        return 0;
    }
    if (namespace_len < 1u || namespace_len > 63u || service_len < 1u ||
        service_len > 63u) {
        return 0;
    }
    if (namespace_bytes == NULL || service_bytes == NULL) {
        return 0;
    }
    /* Closed direction enum: 0 = downlink-ish, 1 = uplink-ish; reject reserved. */
    if (direction > 1u) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        z |= endpoint_runtime_id[i];
        z |= path_policy_id[i];
    }
    if (z == 0u) {
        return 0;
    }
    memcpy(pre + off, domain, dlen);
    off += dlen;
    memcpy(pre + off, endpoint_runtime_id, 16u);
    off += 16u;
    pre[off++] = direction;
    ninlil_rrmp_put_u16_be(pre + off, namespace_len);
    off += 2u;
    memcpy(pre + off, namespace_bytes, namespace_len);
    off += namespace_len;
    ninlil_rrmp_put_u16_be(pre + off, service_len);
    off += 2u;
    memcpy(pre + off, service_bytes, service_len);
    off += service_len;
    ninlil_rrmp_put_u16_be(pre + off, traffic_class);
    off += 2u;
    memcpy(pre + off, path_policy_id, 16u);
    off += 16u;
    ninlil_rrmp_sha256(pre, off, dig);
    memcpy(owner_scope_id_out, dig, 16u);
    return 1;
}

void ninlil_rrmp_loop_key(
    const uint8_t e2e_header_digest32[32],
    uint16_t route_handle,
    uint16_t route_generation,
    const uint8_t local_runtime_id16[16],
    ninlil_rrmp_digest32_t *out)
{
    /* domain <= 32 + e2e32 + handle2 + gen2 + runtime16 */
    uint8_t pre[32 + 32 + 2 + 2 + 16];
    static const char domain[] = "NINLIL-ROUTE-LOOP-V1";
    size_t dlen = sizeof(domain) - 1u;
    memcpy(pre, domain, dlen);
    memcpy(pre + dlen, e2e_header_digest32, 32u);
    ninlil_rrmp_put_u16_be(pre + dlen + 32u, route_handle);
    ninlil_rrmp_put_u16_be(pre + dlen + 34u, route_generation);
    memcpy(pre + dlen + 36u, local_runtime_id16, 16u);
    ninlil_rrmp_sha256(pre, dlen + 52u, out->bytes);
}

void ninlil_rrmp_dedup_key(
    const uint8_t e2e_header_digest32[32],
    uint32_t ingress_hop_context_id,
    uint16_t route_handle,
    uint16_t route_generation,
    ninlil_rrmp_digest32_t *out)
{
    /* domain <= 32 + e2e32 + hop4 + handle2 + gen2 */
    uint8_t pre[32 + 32 + 4 + 2 + 2];
    static const char domain[] = "NINLIL-ROUTE-DEDUP-V1";
    size_t dlen = sizeof(domain) - 1u;
    memcpy(pre, domain, dlen);
    memcpy(pre + dlen, e2e_header_digest32, 32u);
    ninlil_rrmp_put_u32_be(pre + dlen + 32u, ingress_hop_context_id);
    ninlil_rrmp_put_u16_be(pre + dlen + 36u, route_handle);
    ninlil_rrmp_put_u16_be(pre + dlen + 38u, route_generation);
    ninlil_rrmp_sha256(pre, dlen + 40u, out->bytes);
}

void ninlil_rrmp_evidence_key(
    const uint8_t e2e_header_digest32[32],
    uint16_t route_handle,
    uint16_t route_generation,
    uint64_t admission_seq,
    ninlil_rrmp_digest32_t *out)
{
    /* domain <= 32 + e2e32 + handle2 + gen2 + seq8 */
    uint8_t pre[32 + 32 + 2 + 2 + 8];
    static const char domain[] = "NINLIL-ROUTE-EVIDENCE-KEY-V1";
    size_t dlen = sizeof(domain) - 1u;
    memcpy(pre, domain, dlen);
    memcpy(pre + dlen, e2e_header_digest32, 32u);
    ninlil_rrmp_put_u16_be(pre + dlen + 32u, route_handle);
    ninlil_rrmp_put_u16_be(pre + dlen + 34u, route_generation);
    ninlil_rrmp_put_u64_be(pre + dlen + 36u, admission_seq);
    ninlil_rrmp_sha256(pre, dlen + 44u, out->bytes);
}

static int assignment_slot_valid(
    const uint8_t slot[NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES])
{
    uint8_t state;
    int proof_present;
    int receipt_present;
    uint32_t stored;
    if (slot == NULL) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(slot + 468u);
    if (ninlil_rrmp_crc32c(slot, 468u) != stored) {
        return 0;
    }
    if (!ninlil_rrmp_validate_noa1(slot)) {
        return 0;
    }
    if (!bytes_zero(slot + 401u, 3u)) {
        return 0;
    }
    state = slot[400u];
    if (state < NINLIL_RRMP_HANDOFF_PREPARED_NEW ||
        state > NINLIL_RRMP_HANDOFF_OLD_RETIRED) {
        return 0;
    }
    proof_present = bytes_nonzero(slot + 404u, 32u);
    receipt_present = bytes_nonzero(slot + 436u, 32u);
    if (state == NINLIL_RRMP_HANDOFF_PREPARED_NEW) {
        return !proof_present && !receipt_present &&
            bytes_zero(slot + 404u, 64u);
    }
    if (state == NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF) {
        return proof_present && !receipt_present &&
            bytes_zero(slot + 436u, 32u);
    }
    return proof_present && receipt_present;
}

int ninlil_rrmp_encode_assignment_slot(
    const uint8_t noa1[NINLIL_RRMP_NOA1_BYTES],
    uint8_t local_state,
    const uint8_t proof_digest[32],
    const uint8_t receipt_digest[32],
    uint8_t out[NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES])
{
    if (noa1 == NULL || out == NULL ||
        !ninlil_rrmp_validate_noa1(noa1) ||
        local_state < NINLIL_RRMP_HANDOFF_PREPARED_NEW ||
        local_state > NINLIL_RRMP_HANDOFF_OLD_RETIRED) {
        return 0;
    }
    if ((local_state == NINLIL_RRMP_HANDOFF_PREPARED_NEW &&
            (proof_digest != NULL || receipt_digest != NULL)) ||
        (local_state == NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF &&
            (proof_digest == NULL || receipt_digest != NULL)) ||
        (local_state >= NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED &&
            (proof_digest == NULL || receipt_digest == NULL)) ||
        (proof_digest != NULL && !bytes_nonzero(proof_digest, 32u)) ||
        (receipt_digest != NULL && !bytes_nonzero(receipt_digest, 32u))) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES);
    memcpy(out, noa1, NINLIL_RRMP_NOA1_BYTES);
    out[400] = local_state;
    if (proof_digest != NULL) {
        memcpy(out + 404, proof_digest, 32u);
    }
    if (receipt_digest != NULL) {
        memcpy(out + 436, receipt_digest, 32u);
    }
    ninlil_rrmp_put_u32_be(out + 468, 0u);
    ninlil_rrmp_put_u32_be(out + 468, ninlil_rrmp_crc32c(out, 468u));
    return assignment_slot_valid(out);
}

int ninlil_rrmp_encode_npa1_page(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots[NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE],
    uint8_t out[NINLIL_RRMP_NPA1_BYTES])
{
    size_t i;
    if (out == NULL || page_index >= NINLIL_RRMP_NPA1_PAGE_COUNT ||
        page_generation == 0u || page_generation == UINT32_MAX) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NPA1_BYTES);
    out[0] = 'N';
    out[1] = 'P';
    out[2] = 'A';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, page_index);
    ninlil_rrmp_put_u32_be(out + 8, page_generation);
    for (i = 0u; i < NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE; ++i) {
        if (slots != NULL && slots[i] != NULL) {
            const uint8_t *slot = slots[i];
            if (!assignment_slot_valid(slot)) {
                return 0;
            }
            memcpy(
                out + NINLIL_RRMP_NPA1_HEADER_BYTES +
                    i * NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES,
                slots[i],
                NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES);
        }
    }
    ninlil_rrmp_put_u32_be(out + 12, 0u);
    ninlil_rrmp_put_u32_be(out + 12, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NPA1_BYTES));
    return 1;
}

int ninlil_rrmp_validate_npa1(const uint8_t in[NINLIL_RRMP_NPA1_BYTES])
{
    uint32_t stored;
    size_t i;
    if (in == NULL || in[0] != 'N' || in[1] != 'P' || in[2] != 'A' || in[3] != '1') {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 12);
    if (ninlil_rrmp_crc32c_zeroed_u32_be_field(
            in, NINLIL_RRMP_NPA1_BYTES, 12u) != stored) {
        return 0;
    }
    if (!bytes_zero(
            in + NINLIL_RRMP_NPA1_HEADER_BYTES +
                NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE *
                    NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES,
            NINLIL_RRMP_NPA1_PAD_BYTES)) {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 6u) >= NINLIL_RRMP_NPA1_PAGE_COUNT ||
        !u32_record_id_valid(ninlil_rrmp_get_u32_be(in + 8u))) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE; ++i) {
        const uint8_t *slot =
            in + NINLIL_RRMP_NPA1_HEADER_BYTES +
            i * NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES;
        if (bytes_zero(slot, NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES)) {
            continue;
        }
        if (!assignment_slot_valid(slot)) {
            return 0;
        }
    }
    return 1;
}

int ninlil_rrmp_encode_npt1_slot(
    const uint8_t digest32[32],
    uint8_t kind,
    uint64_t created_ms,
    uint8_t out[NINLIL_RRMP_NPT1_SLOT_BYTES])
{
    if (out == NULL || digest32 == NULL ||
        !bytes_nonzero(digest32, 32u) ||
        (kind != NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE &&
         kind != NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED) ||
        !u64_record_id_valid(created_ms)) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NPT1_SLOT_BYTES);
    memcpy(out, digest32, 32u);
    out[32] = kind;
    ninlil_rrmp_put_u64_be(out + 36, created_ms);
    ninlil_rrmp_put_u32_be(out + 44, 0u);
    ninlil_rrmp_put_u32_be(out + 44, ninlil_rrmp_crc32c(out, 44u));
    return 1;
}

static int token_slot_valid(
    const uint8_t slot[NINLIL_RRMP_NPT1_SLOT_BYTES])
{
    uint32_t stored;
    if (slot == NULL) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(slot + 44u);
    if (ninlil_rrmp_crc32c(slot, 44u) != stored) {
        return 0;
    }
    if (!bytes_zero(slot + 33u, 3u)) {
        return 0;
    }
    if (!bytes_nonzero(slot, 32u) ||
        (slot[32u] != NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE &&
         slot[32u] != NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED) ||
        !u64_record_id_valid(ninlil_rrmp_get_u64_be(slot + 36u))) {
        return 0;
    }
    return 1;
}

int ninlil_rrmp_encode_npt1_page(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *slots_packed,
    uint32_t slot_count,
    uint8_t out[NINLIL_RRMP_NPT1_BYTES])
{
    size_t i;
    if (out == NULL || page_index >= NINLIL_RRMP_NPT1_PAGE_COUNT ||
        page_generation == 0u || page_generation == UINT32_MAX ||
        slot_count > NINLIL_RRMP_NPT1_SLOTS_PER_PAGE) {
        return 0;
    }
    ninlil_rrmp_memzero(out, NINLIL_RRMP_NPT1_BYTES);
    out[0] = 'N';
    out[1] = 'P';
    out[2] = 'T';
    out[3] = '1';
    ninlil_rrmp_put_u16_be(out + 4, 1u);
    ninlil_rrmp_put_u16_be(out + 6, page_index);
    ninlil_rrmp_put_u32_be(out + 8, page_generation);
    ninlil_rrmp_put_u32_be(out + 12, slot_count);
    for (i = 0u; i < slot_count; ++i) {
        if (slots_packed == NULL) {
            return 0;
        }
        {
            const uint8_t *slot =
                slots_packed + i * NINLIL_RRMP_NPT1_SLOT_BYTES;
            if (!token_slot_valid(slot)) {
                return 0;
            }
        }
        memcpy(
            out + NINLIL_RRMP_NPT1_HEADER_BYTES + i * NINLIL_RRMP_NPT1_SLOT_BYTES,
            slots_packed + i * NINLIL_RRMP_NPT1_SLOT_BYTES,
            NINLIL_RRMP_NPT1_SLOT_BYTES);
    }
    ninlil_rrmp_put_u32_be(out + 20, 0u);
    ninlil_rrmp_put_u32_be(out + 20, ninlil_rrmp_crc32c(out, NINLIL_RRMP_NPT1_BYTES));
    return 1;
}

int ninlil_rrmp_validate_npt1(const uint8_t in[NINLIL_RRMP_NPT1_BYTES])
{
    uint32_t stored;
    uint32_t count;
    size_t i;
    if (in == NULL || in[0] != 'N' || in[1] != 'P' || in[2] != 'T' || in[3] != '1') {
        return 0;
    }
    if (ninlil_rrmp_get_u16_be(in + 4) != 1u) {
        return 0;
    }
    stored = ninlil_rrmp_get_u32_be(in + 20);
    if (ninlil_rrmp_crc32c_zeroed_u32_be_field(
            in, NINLIL_RRMP_NPT1_BYTES, 20u) != stored) {
        return 0;
    }
    if (ninlil_rrmp_get_u32_be(in + 16u) != 0u ||
        !bytes_zero(
            in + NINLIL_RRMP_NPT1_HEADER_BYTES +
                NINLIL_RRMP_NPT1_SLOTS_PER_PAGE *
                    NINLIL_RRMP_NPT1_SLOT_BYTES,
            NINLIL_RRMP_NPT1_PAD_BYTES)) {
        return 0;
    }
    count = ninlil_rrmp_get_u32_be(in + 12u);
    if (ninlil_rrmp_get_u16_be(in + 6u) >= NINLIL_RRMP_NPT1_PAGE_COUNT ||
        !u32_record_id_valid(ninlil_rrmp_get_u32_be(in + 8u)) ||
        count > NINLIL_RRMP_NPT1_SLOTS_PER_PAGE) {
        return 0;
    }
    for (i = 0u; i < count; ++i) {
        const uint8_t *slot =
            in + NINLIL_RRMP_NPT1_HEADER_BYTES +
            i * NINLIL_RRMP_NPT1_SLOT_BYTES;
        if (!token_slot_valid(slot)) {
            return 0;
        }
    }
    if (!bytes_zero(
            in + NINLIL_RRMP_NPT1_HEADER_BYTES +
                (size_t)count * NINLIL_RRMP_NPT1_SLOT_BYTES,
            ((size_t)NINLIL_RRMP_NPT1_SLOTS_PER_PAGE - count) *
                NINLIL_RRMP_NPT1_SLOT_BYTES)) {
        return 0;
    }
    return 1;
}
