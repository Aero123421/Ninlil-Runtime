/* SPDX-License-Identifier: Apache-2.0
 * ADR-0021 exact wire encode/decode (BIND52 + OPEN/PAGE/CHUNK/responses).
 * Independent of lab FSM; used by engine and KAT tests.
 */
#include "mfdt_v1.h"

#include <string.h>

#define MFDT_IDENTITY_FLAGS_KNOWN ((uint32_t)0x07u)

static int bytes_zero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0u;
    size_t i;
    if (bytes == NULL) {
        return 1;
    }
    for (i = 0u; i < len; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any == 0u;
}

static int text_id_ok(const uint8_t *bytes, uint16_t len, int namespace_id)
{
    uint16_t i;
    if (bytes == NULL || len == 0u || len > 63u ||
        !((bytes[0] >= (uint8_t)'a' && bytes[0] <= (uint8_t)'z') ||
          (bytes[0] >= (uint8_t)'0' && bytes[0] <= (uint8_t)'9'))) {
        return 0;
    }
    for (i = 0u; i < len; ++i) {
        const uint8_t c = bytes[i];
        if ((c >= (uint8_t)'a' && c <= (uint8_t)'z') ||
            (c >= (uint8_t)'0' && c <= (uint8_t)'9') ||
            c == (uint8_t)'.' || c == (uint8_t)'-' ||
            (!namespace_id && c == (uint8_t)'_')) {
            continue;
        }
        return 0;
    }
    return 1;
}

static int identity_shape_ok(const uint8_t *device,
                             const uint8_t *installation,
                             const uint8_t *site,
                             uint64_t binding_epoch,
                             uint64_t membership_epoch,
                             uint32_t flags,
                             uint32_t reserved)
{
    const int has_device = (flags & 1u) != 0u;
    const int has_installation = (flags & 2u) != 0u;
    const int has_site = (flags & 4u) != 0u;
    return reserved == 0u && (flags & ~MFDT_IDENTITY_FLAGS_KNOWN) == 0u &&
           (bytes_zero(device, 16u) == !has_device) &&
           (bytes_zero(installation, 16u) == !has_installation) &&
           (bytes_zero(site, 16u) == !has_site) &&
           ((binding_epoch != 0ull) == (has_device || has_installation)) &&
           ((membership_epoch != 0ull) == has_site);
}

static int family_shape_ok(const uint8_t *origin_event,
                           uint32_t family,
                           uint64_t generation,
                           const uint8_t *deadline_epoch,
                           uint64_t deadline_ms,
                           uint64_t evidence_grace_ms)
{
    const int downlink = family == 2u || family == 5u || family == 6u;
    const int uplink = family == 1u || family == 3u || family == 4u;
    if (!downlink && !uplink) {
        return 0;
    }
    if (family == 1u) {
        if (bytes_zero(origin_event, 16u) || generation != 0ull) {
            return 0;
        }
    } else if (!bytes_zero(origin_event, 16u) || generation == 0ull) {
        return 0;
    }
    if (downlink) {
        return !bytes_zero(deadline_epoch, 16u) && deadline_ms != 0ull &&
               deadline_ms != UINT64_MAX;
    }
    return bytes_zero(deadline_epoch, 16u) && deadline_ms == UINT64_MAX &&
           evidence_grace_ms == 0ull;
}

void ninlil_mfdt_v1_bind52(const uint8_t transfer_id[16], uint32_t revision,
                           const uint8_t manifest_digest[32], uint8_t out[52])
{
    (void)memcpy(out + 0, transfer_id, 16u);
    ninlil_mfdt_v1_put_u32(out + 16, revision);
    (void)memcpy(out + 20, manifest_digest, 32u);
}

int ninlil_mfdt_v1_encode_open(
    const uint8_t transfer_id[16], uint32_t total_length, const uint8_t *content,
    const ninlil_mfdt_v1_open_metadata_t *metadata,
    uint8_t *open_out, uint16_t *open_len_out,
    uint8_t *entries_out, uint16_t *entry_bytes_out, uint8_t manifest_out[32],
    uint8_t whole_out[32])
{
    ninlil_mfdt_v1_geometry_t geo;
    uint16_t i;
    uint16_t text_len;
    int rc;
    if (open_out == NULL || open_len_out == NULL || transfer_id == NULL ||
        metadata == NULL || entry_bytes_out == NULL || manifest_out == NULL ||
        whole_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!text_id_ok(metadata->namespace_bytes, metadata->namespace_length, 1) ||
        !text_id_ok(metadata->service_bytes, metadata->service_length, 0) ||
        !text_id_ok(metadata->schema_bytes, metadata->schema_length, 0)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    text_len = (uint16_t)(metadata->namespace_length +
                          metadata->service_length + metadata->schema_length);
    rc = ninlil_mfdt_v1_geometry(total_length, &geo);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if ((total_length > 0u && (content == NULL || entries_out == NULL)) ||
        bytes_zero(transfer_id, 16u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_sha256(content != NULL ? content : (const uint8_t *)"",
                          total_length, whole_out);
    for (i = 0; i < geo.chunk_count; ++i) {
        uint32_t off = (uint32_t)i * NINLIL_MFDT_V1_CHUNK_SIZE;
        uint16_t clen =
            (i + 1u == geo.chunk_count) ? geo.final_chunk_length
                                        : NINLIL_MFDT_V1_CHUNK_SIZE;
        ninlil_mfdt_v1_chunk_entry(content + off, clen, off, i,
                                   entries_out + (size_t)i * 40u);
    }
    *entry_bytes_out = (uint16_t)(geo.chunk_count * 40u);
    ninlil_mfdt_v1_memzero(open_out, NINLIL_MFDT_V1_OPEN_TEXT_OFFSET);
    (void)memcpy(open_out + 0, transfer_id, 16u);
    ninlil_mfdt_v1_put_u32(open_out + 16, 1u);
    ninlil_mfdt_v1_put_u32(open_out + 20, total_length);
    ninlil_mfdt_v1_put_u16(open_out + 24, NINLIL_MFDT_V1_CHUNK_SIZE);
    ninlil_mfdt_v1_put_u16(open_out + 26, geo.chunk_count);
    ninlil_mfdt_v1_put_u16(open_out + 28, geo.page_count);
    ninlil_mfdt_v1_put_u16(open_out + 30, NINLIL_MFDT_V1_ENTRIES_PER_PAGE);
    (void)memcpy(open_out + 32, whole_out, 32u);
    (void)memcpy(open_out + 64, metadata->origin_transaction_id, 16u);
    (void)memcpy(open_out + 80, metadata->origin_event_id, 16u);
    (void)memcpy(open_out + 96, metadata->source_runtime_id, 16u);
    (void)memcpy(open_out + 112, metadata->target_runtime_id, 16u);
    ninlil_mfdt_v1_put_u64(open_out + 128,
                           metadata->service_descriptor_revision);
    ninlil_mfdt_v1_put_u16(open_out + 136, 1u);
    (void)memcpy(open_out + 138, metadata->service_descriptor_digest, 32u);
    ninlil_mfdt_v1_put_u16(open_out + 170, metadata->namespace_length);
    ninlil_mfdt_v1_put_u16(open_out + 172, metadata->service_length);
    ninlil_mfdt_v1_put_u16(open_out + 174, metadata->schema_length);
    ninlil_mfdt_v1_put_u16(open_out + 176, 0u);
    (void)memcpy(open_out + 178, metadata->deadline_clock_epoch_id, 16u);
    ninlil_mfdt_v1_put_u64(open_out + 194,
                           metadata->absolute_effect_deadline_ms);
    (void)memcpy(open_out + 234, metadata->original_attempt_id, 16u);
    ninlil_mfdt_v1_put_u32(open_out + 250, metadata->target_ordinal);
    (void)memcpy(open_out + 254,
                 metadata->source_application_instance_id, 16u);
    (void)memcpy(open_out + 270, metadata->source_device_id, 16u);
    (void)memcpy(open_out + 286, metadata->source_installation_id, 16u);
    (void)memcpy(open_out + 302, metadata->source_site_id, 16u);
    ninlil_mfdt_v1_put_u64(open_out + 318, metadata->source_binding_epoch);
    ninlil_mfdt_v1_put_u64(open_out + 326, metadata->source_membership_epoch);
    ninlil_mfdt_v1_put_u32(open_out + 334, metadata->source_identity_flags);
    ninlil_mfdt_v1_put_u32(open_out + 338, metadata->source_reserved);
    (void)memcpy(open_out + 342,
                 metadata->target_application_instance_id, 16u);
    (void)memcpy(open_out + 358, metadata->target_device_id, 16u);
    (void)memcpy(open_out + 374, metadata->target_installation_id, 16u);
    (void)memcpy(open_out + 390, metadata->target_site_id, 16u);
    ninlil_mfdt_v1_put_u64(open_out + 406, metadata->target_binding_epoch);
    ninlil_mfdt_v1_put_u64(open_out + 414, metadata->target_membership_epoch);
    ninlil_mfdt_v1_put_u32(open_out + 422, metadata->target_identity_flags);
    ninlil_mfdt_v1_put_u32(open_out + 426, metadata->target_reserved);
    ninlil_mfdt_v1_put_u16(open_out + 430, metadata->service_schema_major);
    ninlil_mfdt_v1_put_u16(open_out + 432, metadata->service_schema_minor);
    ninlil_mfdt_v1_put_u32(open_out + 434, metadata->service_family);
    ninlil_mfdt_v1_put_u64(open_out + 438, metadata->application_generation);
    ninlil_mfdt_v1_put_u64(open_out + 446, metadata->evidence_grace_ms);
    ninlil_mfdt_v1_put_u32(open_out + 454, metadata->required_evidence);
    ninlil_mfdt_v1_put_u32(open_out + 458,
                           metadata->application_binding_flags);
    (void)memcpy(open_out + 462, metadata->namespace_bytes,
                 metadata->namespace_length);
    (void)memcpy(open_out + 462 + metadata->namespace_length,
                 metadata->service_bytes, metadata->service_length);
    (void)memcpy(open_out + 462 + metadata->namespace_length +
                     metadata->service_length,
                 metadata->schema_bytes, metadata->schema_length);
    ninlil_mfdt_v1_manifest_digest(open_out, open_out + 234,
                                   open_out + 462, text_len, entries_out,
                                   geo.chunk_count, manifest_out);
    (void)memcpy(open_out + 202, manifest_out, 32u);
    *open_len_out = (uint16_t)(NINLIL_MFDT_V1_OPEN_TEXT_OFFSET + text_len);
    return ninlil_mfdt_v1_validate_open(
        open_out, *open_len_out, entries_out, *entry_bytes_out, content,
        total_length, 1u);
}

int ninlil_mfdt_v1_validate_open(const uint8_t *open, uint16_t open_len,
                                 const uint8_t *entries,
                                 uint16_t entry_bytes,
                                 const uint8_t *content,
                                 uint32_t content_len,
                                 uint8_t require_manifest)
{
    ninlil_mfdt_v1_geometry_t geo;
    uint16_t ns_len;
    uint16_t service_len;
    uint16_t schema_len;
    uint16_t i;
    uint8_t digest[32];
    if (open == NULL || open_len < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        open_len > NINLIL_MFDT_V1_OPEN_BODY_MAX ||
        require_manifest > 1u) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    ns_len = ninlil_mfdt_v1_get_u16(open + 170);
    service_len = ninlil_mfdt_v1_get_u16(open + 172);
    schema_len = ninlil_mfdt_v1_get_u16(open + 174);
    if ((uint32_t)NINLIL_MFDT_V1_OPEN_TEXT_OFFSET + ns_len + service_len +
            schema_len != open_len ||
        bytes_zero(open + 0, 16u) ||
        ninlil_mfdt_v1_get_u32(open + 16) < 1u ||
        ninlil_mfdt_v1_get_u32(open + 20) != content_len ||
        ninlil_mfdt_v1_get_u16(open + 24) != NINLIL_MFDT_V1_CHUNK_SIZE ||
        bytes_zero(open + 32, 32u) || bytes_zero(open + 64, 16u) ||
        bytes_zero(open + 96, 16u) || bytes_zero(open + 112, 16u) ||
        ninlil_mfdt_v1_get_u64(open + 128) == 0ull ||
        ninlil_mfdt_v1_get_u16(open + 136) != 1u ||
        bytes_zero(open + 138, 32u) ||
        ninlil_mfdt_v1_get_u16(open + 176) != 0u ||
        bytes_zero(open + 202, 32u) || bytes_zero(open + 234, 16u) ||
        ninlil_mfdt_v1_get_u32(open + 250) >= 4u ||
        bytes_zero(open + 254, 16u) || bytes_zero(open + 342, 16u) ||
        !identity_shape_ok(open + 270, open + 286, open + 302,
                           ninlil_mfdt_v1_get_u64(open + 318),
                           ninlil_mfdt_v1_get_u64(open + 326),
                           ninlil_mfdt_v1_get_u32(open + 334),
                           ninlil_mfdt_v1_get_u32(open + 338)) ||
        !identity_shape_ok(open + 358, open + 374, open + 390,
                           ninlil_mfdt_v1_get_u64(open + 406),
                           ninlil_mfdt_v1_get_u64(open + 414),
                           ninlil_mfdt_v1_get_u32(open + 422),
                           ninlil_mfdt_v1_get_u32(open + 426)) ||
        ninlil_mfdt_v1_get_u16(open + 430) == 0u ||
        !family_shape_ok(open + 80, ninlil_mfdt_v1_get_u32(open + 434),
                         ninlil_mfdt_v1_get_u64(open + 438), open + 178,
                         ninlil_mfdt_v1_get_u64(open + 194),
                         ninlil_mfdt_v1_get_u64(open + 446)) ||
        ninlil_mfdt_v1_get_u32(open + 454) < 1u ||
        ninlil_mfdt_v1_get_u32(open + 454) > 4u ||
        ninlil_mfdt_v1_get_u32(open + 458) != 0u ||
        !text_id_ok(open + 462, ns_len, 1) ||
        !text_id_ok(open + 462 + ns_len, service_len, 0) ||
        !text_id_ok(open + 462 + ns_len + service_len, schema_len, 0)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (ninlil_mfdt_v1_geometry(content_len, &geo) != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_get_u16(open + 26) != geo.chunk_count ||
        ninlil_mfdt_v1_get_u16(open + 28) != geo.page_count ||
        ninlil_mfdt_v1_get_u16(open + 30) !=
            NINLIL_MFDT_V1_ENTRIES_PER_PAGE ||
        entry_bytes != (uint16_t)(geo.chunk_count *
                                  NINLIL_MFDT_V1_ENTRY_BYTES)) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (geo.chunk_count > 0u && entries == NULL && require_manifest != 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (entries != NULL) {
        for (i = 0u; i < geo.chunk_count; ++i) {
            const uint8_t *entry = entries + (size_t)i * 40u;
            const uint32_t offset =
                (uint32_t)i * NINLIL_MFDT_V1_CHUNK_SIZE;
            const uint16_t length =
                i + 1u == geo.chunk_count ? geo.final_chunk_length
                                          : NINLIL_MFDT_V1_CHUNK_SIZE;
            if (ninlil_mfdt_v1_get_u16(entry + 0) != i ||
                ninlil_mfdt_v1_get_u16(entry + 2) != length ||
                ninlil_mfdt_v1_get_u32(entry + 4) != offset ||
                bytes_zero(entry + 8, 32u)) {
                return NINLIL_MFDT_V1_ERR_LAYOUT;
            }
        }
    }
    if (require_manifest != 0u) {
        ninlil_mfdt_v1_manifest_digest(
            open, open + 234, open + 462,
            (uint16_t)(open_len - NINLIL_MFDT_V1_OPEN_TEXT_OFFSET), entries,
            geo.chunk_count, digest);
        if (!ninlil_mfdt_v1_memeq(digest, open + 202, 32u)) {
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
    }
    if (content != NULL || content_len == 0u) {
        ninlil_mfdt_v1_sha256(content != NULL ? content : (const uint8_t *)"",
                              content_len, digest);
        if (!ninlil_mfdt_v1_memeq(digest, open + 32, 32u)) {
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_encode_page(const uint8_t transfer_id[16], uint32_t revision,
                               const uint8_t manifest_digest[32],
                               uint16_t page_index, uint16_t page_count,
                               uint16_t first_chunk_index, uint16_t entry_count,
                               const uint8_t *entries, uint8_t *page_out,
                               uint16_t *page_len_out)
{
    uint8_t dig[32];
    /* domain(11)+tid(16)+rev(4)+md(32)+4*u16(8)+entries(22*40)=951; BSS not stack. */
    static uint8_t tmp[11u + 16u + 4u + 32u + 8u + 22u * 40u];
    size_t n = 0u;
    if (page_out == NULL || page_len_out == NULL || entry_count == 0u ||
        entry_count > NINLIL_MFDT_V1_ENTRIES_PER_PAGE || entries == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, page_out);
    ninlil_mfdt_v1_put_u16(page_out + 52, page_index);
    ninlil_mfdt_v1_put_u16(page_out + 54, page_count);
    ninlil_mfdt_v1_put_u16(page_out + 56, first_chunk_index);
    ninlil_mfdt_v1_put_u16(page_out + 58, entry_count);
    /* page_digest */
    (void)memcpy(tmp + n, "NM3-PAGE-V1", 11u);
    n = 11u;
    (void)memcpy(tmp + n, transfer_id, 16u);
    n += 16u;
    ninlil_mfdt_v1_put_u32(tmp + n, revision);
    n += 4u;
    (void)memcpy(tmp + n, manifest_digest, 32u);
    n += 32u;
    ninlil_mfdt_v1_put_u16(tmp + n, page_index);
    n += 2u;
    ninlil_mfdt_v1_put_u16(tmp + n, page_count);
    n += 2u;
    ninlil_mfdt_v1_put_u16(tmp + n, first_chunk_index);
    n += 2u;
    ninlil_mfdt_v1_put_u16(tmp + n, entry_count);
    n += 2u;
    (void)memcpy(tmp + n, entries, (size_t)entry_count * 40u);
    n += (size_t)entry_count * 40u;
    ninlil_mfdt_v1_sha256(tmp, n, dig);
    (void)memcpy(page_out + 60, dig, 32u);
    (void)memcpy(page_out + 92, entries, (size_t)entry_count * 40u);
    *page_len_out = (uint16_t)(92u + entry_count * 40u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_encode_chunk_offer(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      uint16_t chunk_index, uint16_t chunk_count,
                                      uint32_t chunk_offset, uint16_t chunk_len,
                                      const uint8_t *chunk_bytes, uint8_t *out,
                                      uint16_t *out_len)
{
    uint8_t dig[32];
    if (out == NULL || out_len == NULL || (chunk_len > 0u && chunk_bytes == NULL)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_sha256(chunk_bytes != NULL ? chunk_bytes : (const uint8_t *)"",
                          chunk_len, dig);
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, out);
    ninlil_mfdt_v1_put_u16(out + 52, chunk_index);
    ninlil_mfdt_v1_put_u16(out + 54, chunk_count);
    ninlil_mfdt_v1_put_u32(out + 56, chunk_offset);
    ninlil_mfdt_v1_put_u16(out + 60, chunk_len);
    ninlil_mfdt_v1_put_u16(out + 62, 0u);
    (void)memcpy(out + 64, dig, 32u);
    if (chunk_len > 0u) {
        (void)memcpy(out + 96, chunk_bytes, chunk_len);
    }
    *out_len = (uint16_t)(96u + chunk_len);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_encode_open_accept(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      const uint8_t reservation_id[16],
                                      uint32_t reserved_total,
                                      const uint8_t res_epoch[16],
                                      uint64_t not_after_ms,
                                      uint8_t manifest_complete, uint8_t *out,
                                      uint16_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, out);
    (void)memcpy(out + 52, reservation_id, 16u);
    ninlil_mfdt_v1_put_u32(out + 68, reserved_total);
    (void)memcpy(out + 72, res_epoch, 16u);
    ninlil_mfdt_v1_put_u64(out + 88, not_after_ms);
    out[96] = manifest_complete;
    out[97] = 0u;
    out[98] = 0u;
    out[99] = 0u;
    *out_len = 100u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_encode_page_accept(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      uint16_t page_index,
                                      uint16_t received_page_count,
                                      const uint8_t page_digest[32],
                                      const uint8_t reservation_id[16],
                                      uint8_t manifest_complete, uint8_t *out,
                                      uint16_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, out);
    ninlil_mfdt_v1_put_u16(out + 52, page_index);
    ninlil_mfdt_v1_put_u16(out + 54, received_page_count);
    (void)memcpy(out + 56, page_digest, 32u);
    (void)memcpy(out + 88, reservation_id, 16u);
    out[104] = manifest_complete;
    out[105] = 0u;
    out[106] = 0u;
    out[107] = 0u;
    *out_len = 108u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_encode_chunk_accept(const uint8_t transfer_id[16],
                                       uint32_t revision,
                                       const uint8_t manifest_digest[32],
                                       uint16_t chunk_index,
                                       const uint8_t chunk_sha[32], uint8_t *out,
                                       uint16_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, out);
    ninlil_mfdt_v1_put_u16(out + 52, chunk_index);
    ninlil_mfdt_v1_put_u16(out + 54, 0u);
    (void)memcpy(out + 56, chunk_sha, 32u);
    *out_len = 88u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_encode_finalize(const uint8_t transfer_id[16],
                                   uint32_t revision,
                                   const uint8_t manifest_digest[32],
                                   const uint8_t whole[32], uint32_t total_len,
                                   uint8_t *out, uint16_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, out);
    (void)memcpy(out + 52, whole, 32u);
    ninlil_mfdt_v1_put_u32(out + 84, total_len);
    ninlil_mfdt_v1_put_u32(out + 88, 0u);
    *out_len = 92u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_encode_transfer_accept(
    const uint8_t transfer_id[16], uint32_t revision,
    const uint8_t manifest_digest[32], const uint8_t whole[32],
    uint32_t total_len, const uint8_t evidence[16], uint64_t acc_gen,
    const uint8_t reservation_id[16], const uint8_t acc_digest[32], uint8_t *out,
    uint16_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, out);
    (void)memcpy(out + 52, whole, 32u);
    ninlil_mfdt_v1_put_u32(out + 84, total_len);
    (void)memcpy(out + 88, evidence, 16u);
    ninlil_mfdt_v1_put_u64(out + 104, acc_gen);
    (void)memcpy(out + 112, reservation_id, 16u);
    (void)memcpy(out + 128, acc_digest, 32u);
    *out_len = 160u;
    return NINLIL_MFDT_V1_OK;
}
