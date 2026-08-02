/* SPDX-License-Identifier: Apache-2.0
 * Durable NM3S/NM3R record pack/unpack (ADR-0021 308-byte header + body + CRC).
 */
#include "mfdt_v1.h"

#include <string.h>

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

static int active_state_ok(uint8_t owner, uint8_t state)
{
    if (owner == 1u) {
        return state == NINLIL_MFDT_V1_S_OPEN_PENDING ||
               state == NINLIL_MFDT_V1_S_OPEN_ACCEPTED ||
               state == NINLIL_MFDT_V1_S_MANIFEST_ACCEPTED ||
               state == NINLIL_MFDT_V1_S_CHUNKS_PARTIAL ||
               state == NINLIL_MFDT_V1_S_FINAL_WAIT ||
               state == NINLIL_MFDT_V1_S_ACCEPT_RX ||
               state == NINLIL_MFDT_V1_S_ABORT_PENDING ||
               state == NINLIL_MFDT_V1_S_COMMIT_UNKNOWN;
    }
    if (owner == 2u) {
        return state == NINLIL_MFDT_V1_R_RESERVED_OPEN ||
               state == NINLIL_MFDT_V1_R_MANIFEST_PARTIAL ||
               state == NINLIL_MFDT_V1_R_MANIFEST_ACCEPTED ||
               state == NINLIL_MFDT_V1_R_CHUNKS_PARTIAL ||
               state == NINLIL_MFDT_V1_R_CONTENT_VERIFIED ||
               state == NINLIL_MFDT_V1_R_ACCEPT_NOTIFIED ||
               state == NINLIL_MFDT_V1_R_HANDED_OFF ||
               state == NINLIL_MFDT_V1_R_COMMIT_UNKNOWN ||
               state == NINLIL_MFDT_V1_R_ABORT_PENDING;
    }
    return 0;
}

static int active_record_semantic_ok(const uint8_t *rec, uint32_t rec_len)
{
    const uint8_t owner = rec[12];
    const uint8_t state = rec[13];
    const uint16_t open_len = ninlil_mfdt_v1_get_u16(rec + 84);
    const uint16_t entry_bytes = ninlil_mfdt_v1_get_u16(rec + 86);
    const uint32_t content_len = ninlil_mfdt_v1_get_u32(rec + 88);
    const uint16_t chunk_count = ninlil_mfdt_v1_get_u16(rec + 92);
    const uint16_t page_count = ninlil_mfdt_v1_get_u16(rec + 94);
    const uint64_t chunk_bitmap = ninlil_mfdt_v1_get_u64(rec + 96);
    const uint8_t page_bitmap = rec[104];
    const uint8_t publication_state = rec[107];
    const uint8_t handoff_state = rec[108];
    const uint8_t accept_notified = rec[109];
    const uint8_t *open = rec + 308u;
    const uint8_t *entries = open + open_len;
    const uint8_t *content = entries + entry_bytes;
    ninlil_mfdt_v1_geometry_t geometry;
    uint16_t i;
    uint64_t chunk_mask;
    uint8_t page_mask;
    int reservation_zero;
    int evidence_zero;
    int acceptance_zero;
    int token_zero;
    int publication_evidence_zero;

    if (!active_state_ok(owner, state) ||
        ((owner == 1u &&
          !ninlil_mfdt_v1_memeq(rec, "NM3S", 4u)) ||
         (owner == 2u &&
          !ninlil_mfdt_v1_memeq(rec, "NM3R", 4u))) ||
        ninlil_mfdt_v1_get_u16(rec + 14) != 0u ||
        bytes_zero(rec + 16, 16u) ||
        ninlil_mfdt_v1_get_u32(rec + 32) == 0u ||
        bytes_zero(rec + 36, 32u) ||
        ninlil_mfdt_v1_get_u64(rec + 68) == 0ull ||
        rec[105] > NINLIL_MFDT_V1_RETRY_BUDGET_MAX ||
        rec[106] > 2u || publication_state > 2u || handoff_state > 1u ||
        accept_notified > 1u || ninlil_mfdt_v1_get_u16(rec + 110) != 0u ||
        bytes_zero(rec + 200, 16u) ||
        ninlil_mfdt_v1_get_u16(rec + 230) != 0u ||
        ninlil_mfdt_v1_get_u32(rec + 296) > NINLIL_MFDT_V1_RESUME_MAX ||
        ninlil_mfdt_v1_get_u32(rec + 300) == 0u ||
        open_len < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        open_len > NINLIL_MFDT_V1_OPEN_BODY_MAX ||
        rec_len != 308u + (uint32_t)open_len + (uint32_t)entry_bytes +
                       content_len + 4u) {
        return 0;
    }
    if (ninlil_mfdt_v1_geometry(content_len, &geometry) !=
            NINLIL_MFDT_V1_OK ||
        geometry.chunk_count != chunk_count ||
        geometry.page_count != page_count ||
        entry_bytes != (uint16_t)(chunk_count *
                                  NINLIL_MFDT_V1_ENTRY_BYTES) ||
        !ninlil_mfdt_v1_memeq(open, rec + 16, 16u) ||
        ninlil_mfdt_v1_get_u32(open + 16) !=
            ninlil_mfdt_v1_get_u32(rec + 32) ||
        ninlil_mfdt_v1_get_u32(open + 20) != content_len ||
        ninlil_mfdt_v1_get_u16(open + 24) != NINLIL_MFDT_V1_CHUNK_SIZE ||
        ninlil_mfdt_v1_get_u16(open + 26) != chunk_count ||
        ninlil_mfdt_v1_get_u16(open + 28) != page_count ||
        ninlil_mfdt_v1_get_u16(open + 30) !=
            NINLIL_MFDT_V1_ENTRIES_PER_PAGE ||
        ninlil_mfdt_v1_validate_open(open, open_len, NULL, entry_bytes, NULL,
                                    content_len, 0u) !=
            NINLIL_MFDT_V1_OK ||
        !ninlil_mfdt_v1_memeq(open + 202, rec + 36, 32u)) {
        return 0;
    }
    chunk_mask = chunk_count == 0u ? 0ull : ((1ull << chunk_count) - 1ull);
    page_mask = page_count == 0u
                    ? 0u
                    : (uint8_t)((1u << page_count) - 1u);
    if ((chunk_bitmap & ~chunk_mask) != 0ull ||
        (page_bitmap & (uint8_t)~page_mask) != 0u) {
        return 0;
    }
    for (i = 0u; i < chunk_count; ++i) {
        const uint8_t *entry = entries + (size_t)i * 40u;
        const uint16_t page = (uint16_t)(
            i / NINLIL_MFDT_V1_ENTRIES_PER_PAGE);
        const int entry_present =
            owner == 1u || ((page_bitmap & (uint8_t)(1u << page)) != 0u);
        const uint32_t offset =
            (uint32_t)i * NINLIL_MFDT_V1_CHUNK_SIZE;
        const uint16_t length =
            i + 1u == chunk_count
                ? geometry.final_chunk_length
                : NINLIL_MFDT_V1_CHUNK_SIZE;
        if (!entry_present) {
            if (!bytes_zero(entry, 40u)) {
                return 0;
            }
            continue;
        }
        if (ninlil_mfdt_v1_get_u16(entry + 0) != i ||
            ninlil_mfdt_v1_get_u16(entry + 2) != length ||
            ninlil_mfdt_v1_get_u32(entry + 4) != offset ||
            bytes_zero(entry + 8, 32u)) {
            return 0;
        }
        if (owner == 1u ||
            (chunk_bitmap & (1ull << i)) != 0ull) {
            uint8_t digest[32];
            ninlil_mfdt_v1_sha256(content + offset, length, digest);
            if (!ninlil_mfdt_v1_memeq(digest, entry + 8, 32u)) {
                return 0;
            }
        } else if (!bytes_zero(content + offset, length)) {
            return 0;
        }
    }
    if (owner == 1u || page_bitmap == page_mask) {
        uint8_t digest[32];
        ninlil_mfdt_v1_manifest_digest(
            open, open + 234, open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET,
            (uint16_t)(open_len - NINLIL_MFDT_V1_OPEN_TEXT_OFFSET),
            entries, chunk_count, digest);
        if (!ninlil_mfdt_v1_memeq(digest, rec + 36, 32u)) {
            return 0;
        }
    }
    if (owner == 1u || chunk_bitmap == chunk_mask) {
        uint8_t digest[32];
        ninlil_mfdt_v1_sha256(content, content_len, digest);
        if (!ninlil_mfdt_v1_memeq(digest, open + 32, 32u)) {
            return 0;
        }
    }
    reservation_zero = bytes_zero(rec + 112, 16u);
    if (reservation_zero != bytes_zero(rec + 128, 16u) ||
        reservation_zero !=
            (ninlil_mfdt_v1_get_u64(rec + 144) == 0ull) ||
        /*
         * A receiver creates the reservation from its own trusted local
         * monotonic clock, so NM3R must bind both epochs.  NM3S persists the
         * peer receiver's reservation epoch alongside the sender's own local
         * epoch; those are independent clock domains and may differ.
         */
        (!reservation_zero && owner == 2u &&
         !ninlil_mfdt_v1_memeq(rec + 128, rec + 200, 16u))) {
        return 0;
    }
    evidence_zero = bytes_zero(rec + 152, 16u);
    acceptance_zero = bytes_zero(rec + 168, 32u);
    if (evidence_zero != acceptance_zero ||
        evidence_zero !=
            (ninlil_mfdt_v1_get_u64(rec + 76) == 0ull)) {
        return 0;
    }
    token_zero = bytes_zero(rec + 248, 16u);
    publication_evidence_zero = bytes_zero(rec + 264, 32u);
    if ((publication_state == 0u &&
         (!token_zero || !publication_evidence_zero ||
          handoff_state != 0u)) ||
        (publication_state == 1u &&
         (token_zero || !publication_evidence_zero ||
          handoff_state != 0u)) ||
        (publication_state == 2u &&
         (token_zero || publication_evidence_zero ||
          handoff_state != 1u))) {
        return 0;
    }
    if ((ninlil_mfdt_v1_get_u32(rec + 224) == 0u) !=
            (ninlil_mfdt_v1_get_u16(rec + 228) == 0u &&
             bytes_zero(rec + 232, 16u)) ||
        ninlil_mfdt_v1_get_u32(rec + 224) >
            NINLIL_MFDT_V1_ABORT_GEN_MAX) {
        return 0;
    }
    if ((owner == 2u && reservation_zero) ||
        (owner == 1u && state != NINLIL_MFDT_V1_S_OPEN_PENDING &&
         reservation_zero) ||
        (state == NINLIL_MFDT_V1_S_ACCEPT_RX && evidence_zero) ||
        (owner == 2u && state >= NINLIL_MFDT_V1_R_CONTENT_VERIFIED &&
         (evidence_zero || publication_state == 0u)) ||
        (state == NINLIL_MFDT_V1_R_HANDED_OFF &&
         (publication_state != 2u || handoff_state != 1u))) {
        return 0;
    }
    return 1;
}

int ninlil_mfdt_v1_record_pack(
    uint8_t owner_side, uint8_t state_code, const uint8_t transfer_id[16],
    uint32_t revision, const uint8_t manifest_digest[32],
    const uint8_t *open_body, uint16_t open_len, const uint8_t *entries,
    uint16_t entry_bytes, const uint8_t *content, uint32_t content_len,
    uint64_t record_generation, uint8_t page_bitmap, uint64_t chunk_bitmap,
    uint8_t retry_budget, uint8_t publication_state, uint8_t handoff_state,
    const uint8_t reservation_id[16], const uint8_t res_epoch[16],
    uint64_t not_after, const uint8_t publication_token[16],
    uint32_t session_generation, uint8_t *out, uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_mfdt_v1_geometry_t geometry;
    uint32_t fixed_total;
    uint32_t total;
    uint32_t off;
    uint32_t hdr_crc;
    uint32_t rec_crc;
    int rc;
    if (out == NULL || out_len == NULL || transfer_id == NULL ||
        manifest_digest == NULL || open_body == NULL ||
        session_generation == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (open_len < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        open_len > NINLIL_MFDT_V1_OPEN_BODY_MAX) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    rc = ninlil_mfdt_v1_geometry(content_len, &geometry);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if ((owner_side != 1u && owner_side != 2u) ||
        !active_state_ok(owner_side, state_code) ||
        entry_bytes !=
            (uint16_t)(geometry.chunk_count * NINLIL_MFDT_V1_ENTRY_BYTES) ||
        ninlil_mfdt_v1_get_u32(open_body + 20u) != content_len ||
        ninlil_mfdt_v1_get_u16(open_body + 26u) != geometry.chunk_count ||
        ninlil_mfdt_v1_get_u16(open_body + 28u) != geometry.page_count) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    if (entry_bytes != 0u && entries == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (content_len != 0u && content == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    fixed_total = 308u + (uint32_t)open_len + (uint32_t)entry_bytes + 4u;
    if (fixed_total > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX ||
        fixed_total > out_cap ||
        content_len > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX - fixed_total ||
        content_len > out_cap - fixed_total) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    total = fixed_total + content_len;
    ninlil_mfdt_v1_memzero(out, 308u);
    if (owner_side == 1u) {
        (void)memcpy(out + 0, "NM3S", 4u);
    } else {
        (void)memcpy(out + 0, "NM3R", 4u);
    }
    ninlil_mfdt_v1_put_u16(out + 4, NINLIL_MFDT_V1_ACTIVE_SCHEMA);
    ninlil_mfdt_v1_put_u16(out + 6, 308u);
    ninlil_mfdt_v1_put_u32(out + 8, total);
    out[12] = owner_side;
    out[13] = state_code;
    ninlil_mfdt_v1_put_u16(out + 14, 0u);
    (void)memcpy(out + 16, transfer_id, 16u);
    ninlil_mfdt_v1_put_u32(out + 32, revision);
    (void)memcpy(out + 36, manifest_digest, 32u);
    ninlil_mfdt_v1_put_u64(out + 68, record_generation);
    ninlil_mfdt_v1_put_u16(out + 84, open_len);
    ninlil_mfdt_v1_put_u16(out + 86, entry_bytes);
    ninlil_mfdt_v1_put_u32(out + 88, content_len);
    ninlil_mfdt_v1_put_u16(out + 92, ninlil_mfdt_v1_get_u16(open_body + 26));
    ninlil_mfdt_v1_put_u16(out + 94, ninlil_mfdt_v1_get_u16(open_body + 28));
    ninlil_mfdt_v1_put_u64(out + 96, chunk_bitmap);
    out[104] = page_bitmap;
    out[105] = retry_budget;
    out[106] = 0u; /* release_policy IMMEDIATE */
    out[107] = publication_state;
    out[108] = handoff_state;
    out[109] = 0u; /* accept_notified set by caller via flags later */
    if (reservation_id != NULL) {
        (void)memcpy(out + 112, reservation_id, 16u);
    }
    if (res_epoch != NULL) {
        (void)memcpy(out + 128, res_epoch, 16u);
    }
    ninlil_mfdt_v1_put_u64(out + 144, not_after);
    if (publication_token != NULL) {
        (void)memcpy(out + 248, publication_token, 16u);
    }
    ninlil_mfdt_v1_put_u32(out + 300, session_generation);
    hdr_crc = ninlil_mfdt_v1_crc32c(out, 304u);
    ninlil_mfdt_v1_put_u32(out + 304, hdr_crc);
    off = 308u;
    (void)memcpy(out + off, open_body, open_len);
    off += open_len;
    if (entry_bytes > 0u) {
        (void)memcpy(out + off, entries, entry_bytes);
        off += entry_bytes;
    }
    if (content_len > 0u) {
        (void)memcpy(out + off, content, content_len);
        off += content_len;
    }
    rec_crc = ninlil_mfdt_v1_crc32c(out, off);
    ninlil_mfdt_v1_put_u32(out + off, rec_crc);
    *out_len = off + 4u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_record_unpack(
    const uint8_t *rec, uint32_t rec_len, uint8_t *owner_side,
    uint8_t *state_code, uint8_t transfer_id[16], uint32_t *revision,
    uint8_t manifest_digest[32], const uint8_t **open_body, uint16_t *open_len,
    const uint8_t **entries, uint16_t *entry_bytes, const uint8_t **content,
    uint32_t *content_len, uint64_t *record_generation, uint8_t *page_bitmap,
    uint64_t *chunk_bitmap, uint8_t *retry_budget, uint8_t *publication_state,
    uint8_t *handoff_state)
{
    ninlil_mfdt_v1_geometry_t geometry;
    uint16_t hl;
    uint32_t total;
    uint16_t ol;
    uint16_t el;
    uint32_t cl;
    uint32_t hdr_crc;
    uint32_t rec_crc;
    uint32_t body;
    uint32_t body_bytes;
    if (rec == NULL || rec_len < 312u) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (!(ninlil_mfdt_v1_memeq(rec, "NM3S", 4u) ||
          ninlil_mfdt_v1_memeq(rec, "NM3R", 4u))) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (ninlil_mfdt_v1_get_u16(rec + 4) !=
        NINLIL_MFDT_V1_ACTIVE_SCHEMA) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    hl = ninlil_mfdt_v1_get_u16(rec + 6);
    if (hl != 308u) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    total = ninlil_mfdt_v1_get_u32(rec + 8);
    if (total != rec_len || total < 312u ||
        total > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    hdr_crc = ninlil_mfdt_v1_get_u32(rec + 304);
    if (hdr_crc != ninlil_mfdt_v1_crc32c(rec, 304u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    ol = ninlil_mfdt_v1_get_u16(rec + 84);
    el = ninlil_mfdt_v1_get_u16(rec + 86);
    cl = ninlil_mfdt_v1_get_u32(rec + 88);
    body_bytes = rec_len - 312u;
    if (ol < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        ol > NINLIL_MFDT_V1_OPEN_BODY_MAX ||
        (uint32_t)ol > body_bytes ||
        (uint32_t)el > body_bytes - (uint32_t)ol ||
        cl != body_bytes - (uint32_t)ol - (uint32_t)el ||
        ninlil_mfdt_v1_geometry(cl, &geometry) != NINLIL_MFDT_V1_OK ||
        el != (uint16_t)(geometry.chunk_count *
                         NINLIL_MFDT_V1_ENTRY_BYTES)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    body = rec_len - 4u;
    rec_crc = ninlil_mfdt_v1_get_u32(rec + body);
    if (rec_crc != ninlil_mfdt_v1_crc32c(rec, body)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (!active_record_semantic_ok(rec, rec_len)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (owner_side != NULL) {
        *owner_side = rec[12];
    }
    if (state_code != NULL) {
        *state_code = rec[13];
    }
    if (transfer_id != NULL) {
        (void)memcpy(transfer_id, rec + 16, 16u);
    }
    if (revision != NULL) {
        *revision = ninlil_mfdt_v1_get_u32(rec + 32);
    }
    if (manifest_digest != NULL) {
        (void)memcpy(manifest_digest, rec + 36, 32u);
    }
    if (record_generation != NULL) {
        *record_generation = ninlil_mfdt_v1_get_u64(rec + 68);
    }
    if (chunk_bitmap != NULL) {
        *chunk_bitmap = ninlil_mfdt_v1_get_u64(rec + 96);
    }
    if (page_bitmap != NULL) {
        *page_bitmap = rec[104];
    }
    if (retry_budget != NULL) {
        *retry_budget = rec[105];
    }
    if (publication_state != NULL) {
        *publication_state = rec[107];
    }
    if (handoff_state != NULL) {
        *handoff_state = rec[108];
    }
    if (open_body != NULL) {
        *open_body = rec + 308u;
    }
    if (open_len != NULL) {
        *open_len = ol;
    }
    if (entries != NULL) {
        *entries = rec + 308u + ol;
    }
    if (entry_bytes != NULL) {
        *entry_bytes = el;
    }
    if (content != NULL) {
        *content = rec + 308u + ol + el;
    }
    if (content_len != NULL) {
        *content_len = cl;
    }
    return NINLIL_MFDT_V1_OK;
}
