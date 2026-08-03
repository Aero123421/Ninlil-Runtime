/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1.h"

#include <string.h>

void ninlil_mfdt_v1_put_u16(uint8_t *o, uint16_t v)
{
    o[0] = (uint8_t)((v >> 8) & 0xffu);
    o[1] = (uint8_t)(v & 0xffu);
}

void ninlil_mfdt_v1_put_u32(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)((v >> 24) & 0xffu);
    o[1] = (uint8_t)((v >> 16) & 0xffu);
    o[2] = (uint8_t)((v >> 8) & 0xffu);
    o[3] = (uint8_t)(v & 0xffu);
}

void ninlil_mfdt_v1_put_u64(uint8_t *o, uint64_t v)
{
    o[0] = (uint8_t)((v >> 56) & 0xffu);
    o[1] = (uint8_t)((v >> 48) & 0xffu);
    o[2] = (uint8_t)((v >> 40) & 0xffu);
    o[3] = (uint8_t)((v >> 32) & 0xffu);
    o[4] = (uint8_t)((v >> 24) & 0xffu);
    o[5] = (uint8_t)((v >> 16) & 0xffu);
    o[6] = (uint8_t)((v >> 8) & 0xffu);
    o[7] = (uint8_t)(v & 0xffu);
}

uint16_t ninlil_mfdt_v1_get_u16(const uint8_t *i)
{
    return (uint16_t)(((uint16_t)i[0] << 8) | (uint16_t)i[1]);
}

uint32_t ninlil_mfdt_v1_get_u32(const uint8_t *i)
{
    return ((uint32_t)i[0] << 24) | ((uint32_t)i[1] << 16) |
           ((uint32_t)i[2] << 8) | (uint32_t)i[3];
}

uint64_t ninlil_mfdt_v1_get_u64(const uint8_t *i)
{
    return ((uint64_t)i[0] << 56) | ((uint64_t)i[1] << 48) |
           ((uint64_t)i[2] << 40) | ((uint64_t)i[3] << 32) |
           ((uint64_t)i[4] << 24) | ((uint64_t)i[5] << 16) |
           ((uint64_t)i[6] << 8) | (uint64_t)i[7];
}

void ninlil_mfdt_v1_memzero(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    size_t i;
    if (p == NULL) {
        return;
    }
    for (i = 0; i < n; ++i) {
        q[i] = 0u;
    }
}

int ninlil_mfdt_v1_memeq(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t d = 0u;
    size_t i;
    if (a == NULL || b == NULL) {
        return a == b ? 1 : 0;
    }
    for (i = 0; i < n; ++i) {
        d = (uint8_t)(d | (x[i] ^ y[i]));
    }
    return d == 0u ? 1 : 0;
}

uint32_t ninlil_mfdt_v1_crc32c(const uint8_t *in, size_t len)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    if (in == NULL && len != 0u) {
        return 0u;
    }
    for (i = 0; i < len; ++i) {
        uint32_t b;
        crc ^= in[i];
        for (b = 0; b < 8u; ++b) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1u) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

static uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

void ninlil_mfdt_v1_sha256(const uint8_t *message, size_t length, uint8_t out[32])
{
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
        0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
        0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
        0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
        0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
        0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
        0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
        0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    uint8_t block[64];
    uint64_t bit_len = (uint64_t)length * 8u;
    size_t offset = 0u;
    size_t remain = length;
    int done = 0;
    int wrote_one = 0;
    const uint8_t *msg = message != NULL ? message : (const uint8_t *)"";

    while (!done) {
        size_t i;
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, hh;
        size_t take = remain > 64u ? 64u : remain;
        (void)memset(block, 0, sizeof(block));
        if (take > 0u) {
            (void)memcpy(block, msg + offset, take);
            offset += take;
            remain -= take;
        }
        if (take < 64u) {
            if (!wrote_one) {
                block[take] = 0x80u;
                wrote_one = 1;
            }
            if (take < 56u) {
                for (i = 0u; i < 8u; ++i) {
                    block[63u - i] = (uint8_t)(bit_len >> (8u * i));
                }
                done = 1;
            }
        }
        for (i = 0u; i < 16u; ++i) {
            w[i] = ((uint32_t)block[i * 4u] << 24) |
                   ((uint32_t)block[i * 4u + 1u] << 16) |
                   ((uint32_t)block[i * 4u + 2u] << 8) |
                   (uint32_t)block[i * 4u + 3u];
        }
        for (i = 16u; i < 64u; ++i) {
            uint32_t s0 = rotr32(w[i - 15u], 7u) ^ rotr32(w[i - 15u], 18u) ^
                          (w[i - 15u] >> 3);
            uint32_t s1 = rotr32(w[i - 2u], 17u) ^ rotr32(w[i - 2u], 19u) ^
                          (w[i - 2u] >> 10);
            w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
        }
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];
        f = h[5];
        g = h[6];
        hh = h[7];
        for (i = 0u; i < 64u; ++i) {
            uint32_t S1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
    {
        size_t i;
        for (i = 0u; i < 8u; ++i) {
            out[i * 4u] = (uint8_t)((h[i] >> 24) & 0xffu);
            out[i * 4u + 1u] = (uint8_t)((h[i] >> 16) & 0xffu);
            out[i * 4u + 2u] = (uint8_t)((h[i] >> 8) & 0xffu);
            out[i * 4u + 3u] = (uint8_t)(h[i] & 0xffu);
        }
    }
}

int ninlil_mfdt_v1_geometry(uint32_t total_length, ninlil_mfdt_v1_geometry_t *out)
{
    uint32_t chunks;
    uint32_t pages;
    if (out == NULL || total_length > NINLIL_MFDT_V1_MAX_CONTENT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ninlil_mfdt_v1_memzero(out, sizeof(*out));
    out->total_length = total_length;
    out->chunk_size = NINLIL_MFDT_V1_CHUNK_SIZE;
    if (total_length == 0u) {
        out->chunk_count = 0u;
        out->page_count = 0u;
        out->final_chunk_length = 0u;
        return NINLIL_MFDT_V1_OK;
    }
    chunks = (total_length + NINLIL_MFDT_V1_CHUNK_SIZE - 1u) / NINLIL_MFDT_V1_CHUNK_SIZE;
    if (chunks > NINLIL_MFDT_V1_MAX_CHUNKS) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    pages = (chunks + NINLIL_MFDT_V1_ENTRIES_PER_PAGE - 1u) /
            NINLIL_MFDT_V1_ENTRIES_PER_PAGE;
    if (pages > NINLIL_MFDT_V1_MAX_PAGES) {
        return NINLIL_MFDT_V1_ERR_LAYOUT;
    }
    out->chunk_count = (uint16_t)chunks;
    out->page_count = (uint16_t)pages;
    out->final_chunk_length =
        (uint16_t)(total_length - NINLIL_MFDT_V1_CHUNK_SIZE * (chunks - 1u));
    return NINLIL_MFDT_V1_OK;
}

void ninlil_mfdt_v1_request_body_digest(uint8_t message_type, const uint8_t *body,
                                        uint16_t body_len, uint8_t out[32])
{
    uint8_t pre[3 + 2048];
    if (body_len > 2048u) {
        /* oversized: digest empty domain to fail closed callers */
        ninlil_mfdt_v1_sha256((const uint8_t *)"MFDT-OVERSIZE", 13u, out);
        return;
    }
    pre[0] = message_type;
    ninlil_mfdt_v1_put_u16(pre + 1, body_len);
    if (body_len > 0u && body != NULL) {
        (void)memcpy(pre + 3, body, body_len);
    }
    ninlil_mfdt_v1_sha256(pre, (size_t)3u + (size_t)body_len, out);
}

void ninlil_mfdt_v1_chunk_entry(const uint8_t *chunk, uint16_t chunk_len,
                                uint32_t offset, uint16_t chunk_index,
                                uint8_t entry_out[40])
{
    uint8_t dig[32];
    if (chunk_index >= NINLIL_MFDT_V1_MAX_CHUNKS) {
        ninlil_mfdt_v1_memzero(entry_out, 40u);
        return;
    }
    ninlil_mfdt_v1_sha256(chunk != NULL ? chunk : (const uint8_t *)"", chunk_len,
                          dig);
    /* ADR: chunk_index_u16 | chunk_length_u16 | chunk_offset_u32 | digest[32] */
    ninlil_mfdt_v1_put_u16(entry_out + 0, chunk_index);
    ninlil_mfdt_v1_put_u16(entry_out + 2, chunk_len);
    ninlil_mfdt_v1_put_u32(entry_out + 4, offset);
    (void)memcpy(entry_out + 8, dig, 32u);
}

void ninlil_mfdt_v1_manifest_digest(const uint8_t *open_head202,
                                    const uint8_t *open_binding228,
                                    const uint8_t *open_text, uint16_t text_len,
                                    const uint8_t *entries, uint16_t chunk_count,
                                    uint8_t out[32])
{
    /* domain || open[0,202) || open[234,462) || text || entries */
    static const char dom[15] = {'N', 'M', '3', '-', 'M', 'A', 'N', 'I',
                                 'F', 'E', 'S', 'T', '-', 'V', '1'};
    uint8_t buf[15u + 202u + 228u + 189u + 37u * 40u];
    size_t n = 0u;
    if (chunk_count > NINLIL_MFDT_V1_MAX_CHUNKS) {
        ninlil_mfdt_v1_sha256((const uint8_t *)"MFDT-MANIFEST-OVERFLOW", 21u, out);
        return;
    }
    (void)memcpy(buf + n, dom, 15u);
    n += 15u;
    if (open_head202 != NULL) {
        (void)memcpy(buf + n, open_head202, 202u);
        n += 202u;
    } else {
        ninlil_mfdt_v1_memzero(buf + n, 202u);
        n += 202u;
    }
    if (open_binding228 != NULL) {
        (void)memcpy(buf + n, open_binding228, 228u);
    } else {
        ninlil_mfdt_v1_memzero(buf + n, 228u);
    }
    n += 228u;
    if (text_len > 0u && open_text != NULL) {
        if (text_len > 189u) {
            ninlil_mfdt_v1_sha256((const uint8_t *)"MFDT-MANIFEST-OVERFLOW",
                                  21u, out);
            return;
        }
        (void)memcpy(buf + n, open_text, text_len);
        n += text_len;
    }
    if (chunk_count > 0u && entries != NULL) {
        size_t elen = (size_t)chunk_count * NINLIL_MFDT_V1_ENTRY_BYTES;
        (void)memcpy(buf + n, entries, elen);
        n += elen;
    }
    ninlil_mfdt_v1_sha256(buf, n, out);
}

ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_classify_cu(
    int has_old, int has_new, int partial, int extra, int third, int both,
    int absent)
{
    if (absent) {
        return NINLIL_MFDT_V1_CU_ABSENT;
    }
    if (both) {
        return NINLIL_MFDT_V1_CU_BOTH;
    }
    if (third) {
        return NINLIL_MFDT_V1_CU_THIRD;
    }
    if (extra) {
        return NINLIL_MFDT_V1_CU_EXTRA;
    }
    if (partial) {
        return NINLIL_MFDT_V1_CU_PARTIAL;
    }
    if (has_new && !has_old) {
        return NINLIL_MFDT_V1_CU_NEW;
    }
    if (has_old && !has_new) {
        return NINLIL_MFDT_V1_CU_OLD;
    }
    return NINLIL_MFDT_V1_CU_THIRD;
}

ninlil_mfdt_v1_cu_class_t ninlil_mfdt_v1_classify_cu_bytes(
    const uint8_t *observed, uint32_t observed_len, int observed_present,
    const uint8_t *old_bytes, uint32_t old_len, int has_old_intent,
    const uint8_t *new_bytes, uint32_t new_len, int has_new_intent)
{
    int match_old = 0;
    int match_new = 0;
    if (!observed_present) {
        return ninlil_mfdt_v1_classify_cu(0, 0, 0, 0, 0, 0, 1);
    }
    if (observed == NULL) {
        return NINLIL_MFDT_V1_CU_PARTIAL;
    }
    if (has_old_intent && old_bytes != NULL && observed_len == old_len &&
        ninlil_mfdt_v1_memeq(observed, old_bytes, old_len)) {
        match_old = 1;
    }
    if (has_new_intent && new_bytes != NULL && observed_len == new_len &&
        ninlil_mfdt_v1_memeq(observed, new_bytes, new_len)) {
        match_new = 1;
    }
    if (match_old && match_new) {
        /* identical old/new intent — treat as NEW adopted */
        return NINLIL_MFDT_V1_CU_NEW;
    }
    if (match_new) {
        return NINLIL_MFDT_V1_CU_NEW;
    }
    if (match_old) {
        return NINLIL_MFDT_V1_CU_OLD;
    }
    if (has_new_intent && new_bytes != NULL && observed_len != new_len &&
        observed_len > 0u && observed_len < new_len) {
        return NINLIL_MFDT_V1_CU_PARTIAL;
    }
    return NINLIL_MFDT_V1_CU_THIRD;
}

void ninlil_mfdt_v1_publication_token(const uint8_t transfer_id[16],
                                      uint32_t revision,
                                      const uint8_t manifest_digest[32],
                                      const uint8_t whole[32],
                                      uint32_t total_length,
                                      const uint8_t evidence_id[16],
                                      uint8_t token_out[16])
{
    /* "NM3-PUBLISH-V1" = 14 bytes, no NUL */
    uint8_t pre[14u + 52u + 32u + 4u + 16u];
    uint8_t dig[32];
    size_t n = 0u;
    static const char dom[14] = {'N', 'M', '3', '-', 'P', 'U', 'B', 'L',
                                 'I', 'S', 'H', '-', 'V', '1'};
    (void)memcpy(pre + n, dom, 14u);
    n += 14u;
    ninlil_mfdt_v1_bind52(transfer_id, revision, manifest_digest, pre + n);
    n += 52u;
    (void)memcpy(pre + n, whole, 32u);
    n += 32u;
    ninlil_mfdt_v1_put_u32(pre + n, total_length);
    n += 4u;
    (void)memcpy(pre + n, evidence_id, 16u);
    n += 16u;
    ninlil_mfdt_v1_sha256(pre, n, dig);
    (void)memcpy(token_out, dig, 16u);
}

uint16_t ninlil_mfdt_v1_receiver_fulls_max(void)
{
    return NINLIL_MFDT_V1_RECEIVER_FULLS_MAX;
}

uint16_t ninlil_mfdt_v1_sender_fulls_max(void)
{
    return NINLIL_MFDT_V1_SENDER_FULLS_MAX;
}
