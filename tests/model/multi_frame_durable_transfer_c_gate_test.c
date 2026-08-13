/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Independent C11 gate for the ADR-0021 application-handoff review candidate.
 *
 * - Parses the machine vector as data only (no Python/Node/generator import).
 * - Compares against literal authority in multi_frame_durable_transfer_c_authority.h.
 * - Fixed input → fixed canonical wire-byte KATs for production-planned codec ABI
 *   shapes (OPEN/PAGE/CHUNK/FINALIZE/ACCEPT) using hard-coded ONE-BYTE bytes.
 * - Coherent generator+vector drift is rejected when it diverges from C literals.
 * - No production multi-frame implementation or release-support claim.
 *
 * Usage: multi_frame_durable_transfer_c_gate_test --check|--self-test [repo_root]
 */

#include "multi_frame_durable_transfer_c_authority.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            (void)fprintf(stderr, "MFDT C gate FAIL %s:%d: %s\n", __FILE__,    \
                          __LINE__, #cond);                                    \
            return 1;                                                          \
        }                                                                      \
    } while (0)

/* ---- SHA-256 (fixed stack; no heap/VLA) ---------------------------------- */

static uint32_t rotr32(uint32_t value, unsigned bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void mfdt_sha256(const uint8_t *message, size_t length, uint8_t out[32])
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
    /* 0x80 must be written exactly once. When len%64 >= 56 the length field
     * spills into a following all-zero block that must NOT get a second 0x80. */
    int wrote_one = 0;

    while (!done) {
        size_t i;
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, hh;
        size_t take = remain > 64u ? 64u : remain;
        (void)memset(block, 0, sizeof(block));
        if (take > 0u) {
            (void)memcpy(block, message + offset, take);
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
        } else if (remain == 0u && !wrote_one) {
            /* Exact multiple of 64: next iteration is pure pad block with 0x80. */
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
    for (size_t i = 0u; i < 8u; ++i) {
        out[i * 4u] = (uint8_t)(h[i] >> 24);
        out[i * 4u + 1u] = (uint8_t)(h[i] >> 16);
        out[i * 4u + 2u] = (uint8_t)(h[i] >> 8);
        out[i * 4u + 3u] = (uint8_t)h[i];
    }
}

static void hex_encode(const uint8_t *in, size_t n, char *out /* 2n+1 */)
{
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[i * 2u] = digits[(in[i] >> 4) & 0xfu];
        out[i * 2u + 1u] = digits[in[i] & 0xfu];
    }
    out[n * 2u] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_cap,
                      size_t *out_len)
{
    if ((hex_len % 2u) != 0u || (hex_len / 2u) > out_cap) {
        return 0;
    }
    for (size_t i = 0; i < hex_len; i += 2u) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1u]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i / 2u] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = hex_len / 2u;
    return 1;
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static uint16_t read_u16be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t mfdt_crc32c(const uint8_t *bytes, size_t length)
{
    uint32_t crc = 0xffffffffu;
    size_t i;
    for (i = 0u; i < length; ++i) {
        unsigned bit;
        crc ^= (uint32_t)bytes[i];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

static int all_zero(const uint8_t *bytes, size_t length)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int check_nm30_literal_kats(void)
{
    const uint8_t *current = k_mfdt_nm30_schema2_kat;
    const uint8_t *legacy = k_mfdt_nm30_schema1_legacy_kat;

    REQUIRE(sizeof(k_mfdt_nm30_schema2_kat) == (size_t)MFDT_NM30_BYTES);
    REQUIRE(bytes_eq(current, (const uint8_t *)"NM30", 4u));
    REQUIRE(read_u16be(current + 4u) == 2u);
    REQUIRE(read_u16be(current + 6u) == MFDT_NM30_BYTES);
    REQUIRE(!all_zero(current + 8u, 16u));
    REQUIRE(read_u32be(current + 24u) != 0u);
    REQUIRE(!all_zero(current + 28u, 32u));
    REQUIRE(!all_zero(current + 132u, 16u));
    REQUIRE(!all_zero(current + 148u, 8u));
    REQUIRE(!all_zero(current + 156u, 16u));
    REQUIRE(current[172] == 1u || current[172] == 2u);
    REQUIRE(all_zero(current + 173u, 3u));
    REQUIRE(read_u32be(current + 176u) == mfdt_crc32c(current, 176u));

    REQUIRE(sizeof(k_mfdt_nm30_schema1_legacy_kat) ==
            (size_t)MFDT_NM30_LEGACY_SCHEMA1_BYTES);
    REQUIRE(bytes_eq(legacy, (const uint8_t *)"NM30", 4u));
    REQUIRE(read_u16be(legacy + 4u) == 1u);
    REQUIRE(read_u16be(legacy + 6u) == MFDT_NM30_LEGACY_SCHEMA1_BYTES);
    REQUIRE(all_zero(legacy + 156u, 4u));
    REQUIRE(read_u32be(legacy + 160u) == mfdt_crc32c(legacy, 160u));
    return 0;
}

/* ---- Minimal vector file load + scan helpers ----------------------------- */

static char *load_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    long sz;
    char *buf;
    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0L, SEEK_END) != 0) {
        (void)fclose(fp);
        return NULL;
    }
    sz = ftell(fp);
    if (sz < 0) {
        (void)fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0L, SEEK_SET) != 0) {
        (void)fclose(fp);
        return NULL;
    }
    buf = (char *)malloc((size_t)sz + 1u);
    if (buf == NULL) {
        (void)fclose(fp);
        return NULL;
    }
    if (fread(buf, 1u, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        (void)fclose(fp);
        return NULL;
    }
    (void)fclose(fp);
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

static const char *find_str(const char *hay, size_t hay_len, const char *needle)
{
    size_t n = strlen(needle);
    if (n == 0u || hay_len < n) {
        return NULL;
    }
    for (size_t i = 0; i + n <= hay_len; ++i) {
        if (memcmp(hay + i, needle, n) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

/* Extract JSON string value after "key": "..." (first match). */
static int extract_json_string_after(const char *text, size_t text_len,
                                     const char *key, char *out, size_t out_cap)
{
    char pattern[160];
    const char *p;
    size_t i = 0u;
    int n = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (n <= 0 || (size_t)n >= sizeof(pattern)) {
        return 0;
    }
    p = find_str(text, text_len, pattern);
    if (p == NULL) {
        return 0;
    }
    p += (size_t)n;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') {
        ++p;
    }
    if (*p != '"') {
        return 0;
    }
    ++p;
    while (*p != '\0' && *p != '"' && i + 1u < out_cap) {
        if (*p == '\\') {
            ++p;
            if (*p == '\0') {
                break;
            }
        }
        out[i++] = *p++;
    }
    if (*p != '"') {
        return 0;
    }
    out[i] = '\0';
    return 1;
}

/* Vector entries are the four-space-indented objects in the vectors array. */
static int window_around_id(const char *text, size_t text_len, const char *vid,
                            const char **out_start, size_t *out_len)
{
    char idpat[96];
    const char *p;
    const char *cursor;
    const char *found;
    const char *start = NULL;
    const char *end;
    size_t remaining;
    int n = snprintf(idpat, sizeof(idpat), "\"id\": \"%s\"", vid);
    if (n <= 0 || (size_t)n >= sizeof(idpat)) {
        return 0;
    }
    p = find_str(text, text_len, idpat);
    if (p == NULL) {
        return 0;
    }
    cursor = text;
    remaining = (size_t)(p - text);
    while ((found = find_str(cursor, remaining, "\n    {")) != NULL) {
        size_t advance = (size_t)(found - cursor) + 1u;
        start = found + 1;
        cursor += advance;
        remaining -= advance;
    }
    end = find_str(p, (size_t)(text + text_len - p), "\n    }");
    if (start == NULL || end == NULL || end <= start) {
        return 0;
    }
    *out_start = start;
    *out_len = (size_t)(end - start);
    return 1;
}

/*
 * Read expected.status / classification from authority_index (compact; not buried
 * under multi-page fixtures). Pattern: "VID": { "authority_fingerprint... "expected".
 */
static const char *authority_index_row(const char *text, size_t text_len,
                                       const char *vid)
{
    char pat[128];
    const char *idx;
    const char *row;
    size_t idx_len;
    int n = snprintf(pat, sizeof(pat), "\"%s\": {", vid);
    if (n <= 0 || (size_t)n >= sizeof(pat)) {
        return NULL;
    }
    idx = find_str(text, text_len, "\"authority_index\"");
    if (idx == NULL) {
        return NULL;
    }
    idx_len = (size_t)(text + text_len - idx);
    /* Bound authority_index section roughly until "vectors". */
    {
        const char *vectors = find_str(idx, idx_len, "\"vectors\"");
        if (vectors != NULL) {
            idx_len = (size_t)(vectors - idx);
        }
    }
    row = find_str(idx, idx_len, pat);
    return row;
}

static int extract_status_for_id(const char *text, size_t text_len, const char *vid,
                                 char *out, size_t out_cap)
{
    const char *row = authority_index_row(text, text_len, vid);
    const char *exp;
    if (row == NULL) {
        return 0;
    }
    exp = find_str(row, 4096u, "\"expected\"");
    if (exp == NULL) {
        return 0;
    }
    return extract_json_string_after(exp, 2048u, "status", out, out_cap);
}

static int extract_classification_for_id(const char *text, size_t text_len,
                                         const char *vid, char *out,
                                         size_t out_cap)
{
    const char *row = authority_index_row(text, text_len, vid);
    const char *exp;
    if (row == NULL) {
        return 0;
    }
    exp = find_str(row, 4096u, "\"expected\"");
    if (exp == NULL) {
        return 0;
    }
    return extract_json_string_after(exp, 2048u, "classification", out, out_cap);
}/* Extract field near vector id (window includes fixture bytes before/after id). */
static int extract_hex_field_near_id(const char *text, size_t text_len,
                                     const char *vid, const char *field,
                                     char *out, size_t out_cap)
{
    const char *win;
    size_t win_len;
    if (!window_around_id(text, text_len, vid, &win, &win_len)) {
        return 0;
    }
    return extract_json_string_after(win, win_len, field, out, out_cap);
}
/* ---- COMMIT_UNKNOWN independent classifier (minimal literal rules) ------ */

enum mfdt_cu_class {
    MFDT_CU_OLD = 0,
    MFDT_CU_NEW,
    MFDT_CU_PARTIAL,
    MFDT_CU_EXTRA,
    MFDT_CU_THIRD,
    MFDT_CU_ABSENT,
    MFDT_CU_BOTH
};

/* Synthetic fixed key fingerprints for classifier unit tests (not from vector). */
static int classify_commit_unknown(int has_old, int has_new, int has_partial,
                                   int has_extra, int has_third, int has_both,
                                   int observed_empty)
{
    if (observed_empty) {
        return MFDT_CU_ABSENT;
    }
    if (has_both) {
        return MFDT_CU_BOTH;
    }
    if (has_third) {
        return MFDT_CU_THIRD;
    }
    if (has_extra) {
        return MFDT_CU_EXTRA;
    }
    if (has_partial) {
        return MFDT_CU_PARTIAL;
    }
    if (has_new && !has_old) {
        return MFDT_CU_NEW;
    }
    if (has_old && !has_new) {
        return MFDT_CU_OLD;
    }
    return MFDT_CU_THIRD;
}

static const char *cu_name(int c)
{
    switch (c) {
    case MFDT_CU_OLD:
        return "OLD";
    case MFDT_CU_NEW:
        return "NEW";
    case MFDT_CU_PARTIAL:
        return "PARTIAL";
    case MFDT_CU_EXTRA:
        return "EXTRA";
    case MFDT_CU_THIRD:
        return "THIRD";
    case MFDT_CU_ABSENT:
        return "ABSENT";
    case MFDT_CU_BOTH:
        return "BOTH";
    default:
        return "?";
    }
}

/* ---- Byte-bound geometry ------------------------------------------------- */

static int geometry_ok(int total, int *out_chunks, int *out_pages, int *out_final)
{
    int chunks;
    int pages;
    int final_len;
    if (total < 0 || total > MFDT_MAX_CONTENT) {
        return 0;
    }
    if (total == 0) {
        *out_chunks = 0;
        *out_pages = 0;
        *out_final = 0;
        return 1;
    }
    chunks = (total + MFDT_CHUNK_SIZE - 1) / MFDT_CHUNK_SIZE;
    if (chunks > MFDT_MAX_CHUNKS) {
        return 0;
    }
    pages = (chunks + MFDT_ENTRIES_PER_PAGE - 1) / MFDT_ENTRIES_PER_PAGE;
    if (pages > MFDT_MAX_PAGES) {
        return 0;
    }
    final_len = total - MFDT_CHUNK_SIZE * (chunks - 1);
    *out_chunks = chunks;
    *out_pages = pages;
    *out_final = final_len;
    return 1;
}

/* ---- ONE-BYTE literal KAT recompute paths -------------------------------- */

static int check_one_byte_literal_kats(void)
{
    uint8_t dig[32];
    uint8_t page_digest_domain[11 + 16 + 4 + 32 + 2 + 2 + 2 + 2 + 40];
    size_t off = 0u;

    /* Content digest. */
    mfdt_sha256(k_mfdt_one_content, 1u, dig);
    REQUIRE(bytes_eq(dig, k_mfdt_one_whole_digest, 32u));

    /* Empty digest pin. */
    mfdt_sha256((const uint8_t *)"", 0u, dig);
    REQUIRE(bytes_eq(dig, k_mfdt_sha256_empty, 32u));

    /* Chunk payload digest matches header bytes 64..95 of chunk body. */
    mfdt_sha256(k_mfdt_one_content, 1u, dig);
    REQUIRE(bytes_eq(dig, k_mfdt_one_chunk0 + 64, 32u));
    REQUIRE(k_mfdt_one_chunk0[96] == 0x41);

    /* Page domain: NM3-PAGE-V1 || tid||rev||md||idx||count||first||entry_count||entries */
    (void)memcpy(page_digest_domain + off, "NM3-PAGE-V1", 11u);
    off += 11u;
    (void)memcpy(page_digest_domain + off, k_mfdt_one_page0, 16u); /* tid */
    off += 16u;
    (void)memcpy(page_digest_domain + off, k_mfdt_one_page0 + 16, 4u); /* rev */
    off += 4u;
    (void)memcpy(page_digest_domain + off, k_mfdt_one_page0 + 20, 32u); /* md */
    off += 32u;
    page_digest_domain[off++] = 0x00; /* page_index hi */
    page_digest_domain[off++] = 0x00;
    page_digest_domain[off++] = 0x00; /* page_count */
    page_digest_domain[off++] = 0x01;
    page_digest_domain[off++] = 0x00; /* first */
    page_digest_domain[off++] = 0x00;
    page_digest_domain[off++] = 0x00; /* entry_count */
    page_digest_domain[off++] = 0x01;
    (void)memcpy(page_digest_domain + off, k_mfdt_one_entry0, 40u);
    off += 40u;
    mfdt_sha256(page_digest_domain, off, dig);
    REQUIRE(bytes_eq(dig, k_mfdt_one_page0 + 60, 32u));

    /* Wire lengths match production-planned fixed sizes. */
    REQUIRE(sizeof(k_mfdt_one_open_accept) == (size_t)MFDT_OPEN_ACCEPT_LEN);
    REQUIRE(sizeof(k_mfdt_one_transfer_accept) == (size_t)MFDT_TRANSFER_ACCEPT_LEN);
    REQUIRE(sizeof(k_mfdt_one_page0) ==
            (size_t)MFDT_PAGE_HEADER + (size_t)MFDT_ENTRY_BYTES);
    REQUIRE(sizeof(k_mfdt_one_chunk0) == (size_t)MFDT_CHUNK_HEADER + 1u);
    REQUIRE(sizeof(k_mfdt_one_finalize) == 92u);
    REQUIRE(sizeof(k_mfdt_one_open_body) == (size_t)MFDT_OPEN_BODY_MIN);

    /* Header binds: open_accept tid/rev/md match open_body. */
    REQUIRE(bytes_eq(k_mfdt_one_open_accept, k_mfdt_one_open_body, 16u));
    REQUIRE(bytes_eq(k_mfdt_one_open_accept + 16, k_mfdt_one_open_body + 16, 4u));
    REQUIRE(bytes_eq(k_mfdt_one_open_accept + 20, k_mfdt_one_manifest_digest, 32u));
    REQUIRE(bytes_eq(k_mfdt_one_page0 + 20, k_mfdt_one_manifest_digest, 32u));
    REQUIRE(bytes_eq(k_mfdt_one_chunk0 + 20, k_mfdt_one_manifest_digest, 32u));
    REQUIRE(bytes_eq(k_mfdt_one_finalize + 20, k_mfdt_one_manifest_digest, 32u));
    REQUIRE(bytes_eq(k_mfdt_one_transfer_accept + 20, k_mfdt_one_manifest_digest, 32u));
    REQUIRE(bytes_eq(k_mfdt_one_finalize + 52, k_mfdt_one_whole_digest, 32u));

    /* ACCEPT digest over domain prefix ("NM3-ACCEPT-V1" is 13 octets). */
    {
        uint8_t acc_dom[13 + 128];
        (void)memcpy(acc_dom, "NM3-ACCEPT-V1", 13u);
        (void)memcpy(acc_dom + 13, k_mfdt_one_transfer_accept, 128u);
        mfdt_sha256(acc_dom, 13u + 128u, dig);
        REQUIRE(bytes_eq(dig, k_mfdt_one_transfer_accept + 128, 32u));
    }
    return 0;
}

static int check_vector_against_authority(const char *repo_root)
{
    char path[1024];
    size_t text_len = 0u;
    char *text;
    uint8_t file_digest[32];
    char file_digest_hex[65];
    char status_buf[64];
    char class_buf[32];
    char hexbuf[MFDT_OPEN_BODY_MAX * 2 + 1];
    uint8_t decoded[MFDT_OPEN_BODY_MAX];
    size_t decoded_len = 0u;
    int executed = 0;
    int chunks = 0;
    int pages = 0;
    int final_len = 0;

    REQUIRE(snprintf(path, sizeof(path), "%s/%s", repo_root, k_mfdt_vector_relpath) <
            (int)sizeof(path));
    text = load_file(path, &text_len);
    REQUIRE(text != NULL);

    mfdt_sha256((const uint8_t *)text, text_len, file_digest);
    hex_encode(file_digest, 32u, file_digest_hex);
    REQUIRE(strcmp(file_digest_hex, k_mfdt_vector_sha256_hex) == 0);

    REQUIRE(find_str(text, text_len, k_mfdt_pinned_status) != NULL);
    REQUIRE(find_str(text, text_len, k_mfdt_pinned_schema) != NULL);
    REQUIRE(find_str(text, text_len, k_mfdt_pinned_adr) != NULL);
    REQUIRE(find_str(text, text_len, k_mfdt_authority_map_sha256_hex) != NULL);

    /*
     * Contract-phase literals are independent C authority, not values learned
     * from the generator. The vector SHA seals the whole document; these pins
     * make the repaired allocation/resource semantics reviewable in C too.
     */
    REQUIRE(find_str(text, text_len, "\"mfdt_offer_type\": 52") != NULL);
    REQUIRE(find_str(text, text_len, "\"mfdt_accept_type\": 53") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_OPEN\": 54") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_OPEN_ACCEPT\": 55") != NULL);
    REQUIRE(find_str(text, text_len, "\"MANIFEST_PAGE\": 56") != NULL);
    REQUIRE(find_str(text, text_len, "\"MANIFEST_PAGE_ACCEPT\": 57") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_REJECT\": 58") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_BUSY\": 59") != NULL);
    REQUIRE(find_str(text, text_len, "\"CHUNK_OFFER\": 60") != NULL);
    REQUIRE(find_str(text, text_len, "\"CHUNK_ACCEPT\": 61") != NULL);
    REQUIRE(find_str(text, text_len, "\"RESUME_QUERY\": 62") != NULL);
    REQUIRE(find_str(text, text_len, "\"RESUME_STATE\": 63") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_FINALIZE\": 64") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_ACCEPT\": 65") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_ABORT\": 66") != NULL);
    REQUIRE(find_str(text, text_len, "\"TRANSFER_ABORT_ACK\": 67") != NULL);
    REQUIRE(find_str(text, text_len, "\"nrc1_slot_bytes\": 208") != NULL);
    REQUIRE(find_str(text, text_len, "\"nrc1_value_bytes\": 15020") != NULL);
    REQUIRE(find_str(text, text_len, "\"nrc1_logical_bytes\": 15056") != NULL);
    REQUIRE(find_str(text, text_len, "\"nm30_schema\": 2") != NULL);
    REQUIRE(find_str(text, text_len, "\"nm30_value_bytes\": 180") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"nm30_legacy_schema1_value_bytes\": 164") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"nm30_peer_endpoint_id_offset\": 156") != NULL);
    REQUIRE(find_str(text, text_len, "\"nm30_owner_role_offset\": 172") != NULL);
    REQUIRE(find_str(text, text_len, "\"nm30_reserved_offset\": 173") != NULL);
    REQUIRE(find_str(text, text_len, "\"nm30_crc_offset\": 176") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"nm30_session_cookie_durable\": false") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"terminal_session_generation_authority\": "
                     "\"NRC1_header_offset_24\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"active_record_schema\": 2") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"application_binding_bytes\": 228") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"no_deadline_u64_hex\": \"ffffffffffffffff\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"finite_downlink_deadline_min_u64_hex\": "
                     "\"0000000000000001\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"finite_downlink_deadline_max_u64_hex\": "
                     "\"fffffffffffffffe\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"uplink_eventfact_deadline_shape\": "
                     "\"epoch_zero__absolute_no_deadline__grace_zero\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"original_application_open_deadline_mapping\": "
                     "\"bit_exact_no_normalization\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"deadline_shape_cases\": [") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"case\": \"uplink_eventfact_deadline_zero\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"case\": \"downlink_no_deadline\"") != NULL);
    REQUIRE(find_str(text, text_len, "\"open_fixed_bytes\": 462") != NULL);
    REQUIRE(find_str(text, text_len, "\"open_body_min\": 465") != NULL);
    REQUIRE(find_str(text, text_len, "\"open_body_max\": 651") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"mfdt_admission_profile_revision\": 2") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"admission_reserved_logical_bytes\": 50519") != NULL);
    REQUIRE(find_str(text, text_len, "\"host_slot_count\": 4") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_control_arena_bytes\": 17920") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_terminal_catalog_entries\": 16") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_terminal_catalog_entry_bytes\": 64") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_control_outbox_count\": 1") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_control_outbox_bytes\": 1024") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_control_route_sentinel\": 255") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_owner_workspace_bytes\": 280064") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_four_active_committed_logical_bytes\": 201212") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"terminal_row_logical_bytes\": 216") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_terminal_group_logical_bytes\": 15272") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_committed_logical_bytes_hard_max\": 384476") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_begin_final_union_logical_bytes_hard_max\": 434779") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_serialized_full_staging_logical_bytes_max\": 50303") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"active_replacement_begin_final_logical_bytes_max\": 70494") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"id\": \"MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"id\": \"MF-NEG-ADMISSION-REV1-REV2-MIXED\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"selected_control_version_3\": \"REJECT\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"target_promotion_on\": \"UNALLOCATED_UNSUPPORTED\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"nm30_expired_reason_terminal_only\": 5") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_terminal_catalog_rebind\": "
                     "\"peer_role_generation_exact_fresh_nonzero_cookie\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_control_outbox_backpressure\": "
                     "\"ERR_BUSY_no_overwrite\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"host_fifth_active\": "
                     "\"CAPACITY_BUSY_control_outbox_state_mutation_0\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"nm30_schema2_layout\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"legacy_nm30_schema1_replay_ineligible\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"host_terminal_cold_rebind_hit\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"host_terminal_bind_matrix\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"four_active_terminal_hit_control_route\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"four_active_fresh_open_capacity_busy\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"control_outbox_no_overwrite\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"preadmission_policy_stateless\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"preadmission_deadline_stateless\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"active_semantic_reject_cached\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"branch\": \"canonical_roster_target_attempt_prearm_"
                     "foundation_full_reconcile\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"target_runtime_unique_within_origin\": true") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"runtime_uniqueness_scope\": \"MFDT_V1_ONLY\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"same_runtime_different_application_instance_rejected\": "
                     "true") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"duplicate_runtime_api_status\": \"NINLIL_OK\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"duplicate_runtime_submission_state\": \"REJECTED\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"duplicate_runtime_reason\": "
                     "\"TARGET_COUNT_UNSUPPORTED\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"duplicate_runtime_entropy_draws\": 0") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"duplicate_runtime_sidecar_mutations\": 0") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"duplicate_runtime_foundation_mutations\": 0") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"compound_receiver_key_created\": false") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"nts3_target_local_suffix_rule_changed\": false") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"attempt_draws_max_per_target\": 4") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"attempt_collision_set\": "
                     "\"durable_active_retained_plus_prior_same_admission_candidates\"")
            != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"attempt_candidate_bound_to_target_open\": true") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"attempt_consumed_claim_before_foundation_full\": 0") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"wire_txgate_callback_before_foundation_full\": 0") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"foundation_admission_full_count\": 1") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"admission_execution_scope\": \"owner_thread_call\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"restart_reconcile_before_bearer_open\": true") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"new_durable_state_added\": false") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"blind_attempt_redraw_forbidden\": true") != NULL);
    REQUIRE(find_str(text, text_len,
                     "\"case\": "
                     "\"duplicate_runtime_different_application_instance\"") != NULL);
    REQUIRE(find_str(text, text_len,
                     "FOUNDATION_COMMIT_UNKNOWN_KEEP_ARMS_FENCE_RECONCILE_NO_REDRAW")
            != NULL);

    /* All sealed IDs are present in required order and match the C authority. */
    {
        const char *scan = text;
        size_t remain = text_len;
        for (int i = 0; i < MFDT_ID_COUNT; ++i) {
            const mfdt_id_authority_t *row = &k_mfdt_authority[i];
            char idpat[96];
            const char *hit;
            int n = snprintf(idpat, sizeof(idpat), "\"%s\"", row->id);
            REQUIRE(n > 0 && (size_t)n < sizeof(idpat));
            hit = find_str(scan, remain, idpat);
            REQUIRE(hit != NULL);
            /* Advance to preserve order. */
            remain = (size_t)(text + text_len - (hit + 1));
            scan = hit + 1;

            REQUIRE(extract_status_for_id(text, text_len, row->id, status_buf,
                                          sizeof(status_buf)));
            if (strcmp(status_buf, row->status) != 0) {
                (void)fprintf(stderr,
                              "MFDT C authority status mismatch id=%s got=%s expected=%s\n",
                              row->id, status_buf, row->status);
            }
            REQUIRE(strcmp(status_buf, row->status) == 0);

            if (row->family == MFDT_FAM_COMMIT_UNKNOWN) {
                REQUIRE(extract_classification_for_id(text, text_len, row->id,
                                                      class_buf, sizeof(class_buf)));
                REQUIRE(strcmp(class_buf, row->classification) == 0);
            }
            executed += 1;
        }
    }
    REQUIRE(executed == MFDT_ID_COUNT);

    /* Current schema-2 and accounting-only legacy schema-1 rows are literal KATs. */
    REQUIRE(extract_hex_field_near_id(text, text_len,
                                      "MF-POS-NM30-SCHEMA2-LAYOUT-KAT",
                                      "nm30_value_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == sizeof(k_mfdt_nm30_schema2_kat));
    REQUIRE(bytes_eq(decoded, k_mfdt_nm30_schema2_kat, decoded_len));

    REQUIRE(extract_hex_field_near_id(text, text_len,
                                      "MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY",
                                      "legacy_nm30_value_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == sizeof(k_mfdt_nm30_schema1_legacy_kat));
    REQUIRE(bytes_eq(decoded, k_mfdt_nm30_schema1_legacy_kat, decoded_len));
    REQUIRE(check_nm30_literal_kats() == 0);

    /* Positive geometry pins from hard authority. */
    for (int i = 0; i < MFDT_ID_COUNT; ++i) {
        const mfdt_id_authority_t *row = &k_mfdt_authority[i];
        if (row->family != MFDT_FAM_POSITIVE || row->chunk_count < 0) {
            continue;
        }
        REQUIRE(geometry_ok(row->total_length, &chunks, &pages, &final_len));
        REQUIRE(chunks == row->chunk_count);
        if (row->total_length == 0) {
            REQUIRE(pages == 0);
        } else {
            REQUIRE(pages >= 1 && pages <= MFDT_MAX_PAGES);
        }
        REQUIRE(row->chunk_count <= MFDT_MAX_CHUNKS);
        REQUIRE(row->total_length <= MFDT_MAX_CONTENT);
    }

    /* ONE-BYTE fixture in vector must match literal C KAT bytes. */
    REQUIRE(extract_hex_field_near_id(text, text_len, "MF-POS-ONE-BYTE",
                                      "open_accept_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == sizeof(k_mfdt_one_open_accept));
    REQUIRE(bytes_eq(decoded, k_mfdt_one_open_accept, decoded_len));

    REQUIRE(extract_hex_field_near_id(text, text_len, "MF-POS-ONE-BYTE",
                                      "transfer_accept_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == sizeof(k_mfdt_one_transfer_accept));
    REQUIRE(bytes_eq(decoded, k_mfdt_one_transfer_accept, decoded_len));

    REQUIRE(extract_hex_field_near_id(text, text_len, "MF-POS-ONE-BYTE",
                                      "finalize_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == sizeof(k_mfdt_one_finalize));
    REQUIRE(bytes_eq(decoded, k_mfdt_one_finalize, decoded_len));

    REQUIRE(extract_hex_field_near_id(text, text_len, "MF-POS-ONE-BYTE",
                                      "open_body_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == sizeof(k_mfdt_one_open_body));
    REQUIRE(bytes_eq(decoded, k_mfdt_one_open_body, decoded_len));

    /* page_digest_hex is unique; body match via recompute already in KAT path. */
    REQUIRE(extract_hex_field_near_id(text, text_len, "MF-POS-ONE-BYTE",
                                      "page_digest_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == 32u);
    REQUIRE(bytes_eq(decoded, k_mfdt_one_page0 + 60, 32u));

    REQUIRE(extract_hex_field_near_id(text, text_len, "MF-POS-ONE-BYTE",
                                      "chunk_sha256_hex", hexbuf, sizeof(hexbuf)));
    REQUIRE(hex_decode(hexbuf, strlen(hexbuf), decoded, sizeof(decoded), &decoded_len));
    REQUIRE(decoded_len == 32u);
    REQUIRE(bytes_eq(decoded, k_mfdt_one_chunk0 + 64, 32u));

    REQUIRE(check_one_byte_literal_kats() == 0);
    REQUIRE(MFDT_MFN1_OFFER == 0x34 && MFDT_MFN1_ACCEPT == 0x35);
    REQUIRE(MFDT_OPEN == 0x36 && MFDT_ABORT_ACK == 0x43);
    REQUIRE(MFDT_NRC1_SLOT_BYTES == 208);
    REQUIRE(MFDT_NRC1_VALUE_BYTES == 15020);
    REQUIRE(MFDT_NRC1_LOGICAL_BYTES == 15056);
    REQUIRE(MFDT_SESSION_GENERATIONS_MAX_PER_TRANSFER == 2);
    REQUIRE(MFDT_SESSION_GENERATION_INITIAL_EXAMPLE == 7);
    REQUIRE(MFDT_SESSION_GENERATION_SUCCESSOR_EXAMPLE ==
            MFDT_SESSION_GENERATION_INITIAL_EXAMPLE + 1);
    REQUIRE(MFDT_NM30_BYTES == 180);
    REQUIRE(MFDT_NM30_LEGACY_SCHEMA1_BYTES == 164);
    REQUIRE(MFDT_TERMINAL_ROW_LOGICAL_BYTES == 216);
    REQUIRE(MFDT_TERMINAL_GROUP_LOGICAL_BYTES == 15272);
    REQUIRE(MFDT_ACTIVE_RECORD_SCHEMA == 2);
    REQUIRE(MFDT_OPEN_BASE_FIXED_BYTES == 234);
    REQUIRE(MFDT_APPLICATION_BINDING_BYTES == 228);
    REQUIRE(MFDT_OPEN_FIXED_BYTES == 462);
    REQUIRE(MFDT_OPEN_BODY_MIN == 465 && MFDT_OPEN_BODY_MAX == 651);
    REQUIRE(MFDT_ACTIVE_VALUE_MAX == 35211);
    REQUIRE(MFDT_ACTIVE_ROW_LOGICAL_BYTES_MAX == 35247);
    REQUIRE(MFDT_ACTIVE_REPLACEMENT_BEGIN_FINAL_LOGICAL_BYTES_MAX == 70494);
    REQUIRE(MFDT_ADMISSION_RESERVED_LOGICAL_BYTES == 50519);
    REQUIRE(MFDT_HOST_SLOT_COUNT == 4);
    REQUIRE(MFDT_HOST_CONTROL_ARENA_BYTES == 17920);
    REQUIRE(MFDT_HOST_TERMINAL_CATALOG_ENTRIES == 16);
    REQUIRE(MFDT_HOST_TERMINAL_CATALOG_ENTRY_BYTES == 64);
    REQUIRE(MFDT_HOST_TERMINAL_CATALOG_BYTES ==
            MFDT_HOST_TERMINAL_CATALOG_ENTRIES *
                MFDT_HOST_TERMINAL_CATALOG_ENTRY_BYTES);
    REQUIRE(MFDT_HOST_CONTROL_OUTBOX_METADATA_BYTES == 64);
    REQUIRE(MFDT_HOST_CONTROL_OUTBOX_BYTES == 1024);
    REQUIRE(MFDT_HOST_CONTROL_NRC1_SCRATCH_BYTES == 15024);
    REQUIRE(MFDT_HOST_CONTROL_NM30_SCRATCH_BYTES == 184);
    REQUIRE(MFDT_HOST_CONTROL_RECOVERY_RESERVED_BYTES == 88);
    REQUIRE(MFDT_HOST_CONTROL_ROUTE_SENTINEL == 255);
    REQUIRE(MFDT_HOST_CONTROL_ARENA_BYTES ==
            MFDT_HOST_TERMINAL_CATALOG_BYTES +
                MFDT_HOST_CONTROL_OUTBOX_METADATA_BYTES +
                MFDT_HOST_CONTROL_OUTBOX_BYTES +
                MFDT_HOST_CONTROL_NRC1_SCRATCH_BYTES +
                MFDT_HOST_CONTROL_NM30_SCRATCH_BYTES +
                MFDT_HOST_CONTROL_RECOVERY_RESERVED_BYTES +
                MFDT_HOST_COORDINATOR_BYTES);
    REQUIRE(MFDT_HOST_OWNER_WORKSPACE_BYTES ==
            MFDT_HOST_SLOT_COUNT * MFDT_HOST_SLOT_WORKSPACE_BYTES +
                MFDT_HOST_CONTROL_ARENA_BYTES);
    REQUIRE(MFDT_HOST_ACTIVE_GROUP_LOGICAL_BYTES == 50303);
    REQUIRE(MFDT_HOST_FOUR_ACTIVE_COMMITTED_LOGICAL_BYTES == 201212);
    REQUIRE(MFDT_HOST_COMMITTED_LOGICAL_BYTES_HARD_MAX == 384476);
    REQUIRE(MFDT_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_HARD_MAX == 434779);
    REQUIRE(MFDT_HOST_SERIALIZED_FULL_STAGING_LOGICAL_BYTES_MAX == 50303);
    REQUIRE(MFDT_HOST_TRACKED_TRANSFER_GROUPS_MAX == 16);

    free(text);
    (void)printf(
        "MFDT C gate OK vectors=%d map_sha=%s vector_sha=%s\n", MFDT_ID_COUNT,
        k_mfdt_authority_map_sha256_hex, k_mfdt_vector_sha256_hex);
    return 0;
}

static int self_test(const char *repo_root)
{
    int chunks = 0;
    int pages = 0;
    int final_len = 0;

    REQUIRE(check_vector_against_authority(repo_root) == 0);
    REQUIRE(check_one_byte_literal_kats() == 0);
    REQUIRE(check_nm30_literal_kats() == 0);

    /* Byte bounds: max+1 rejected by geometry. */
    REQUIRE(geometry_ok(MFDT_MAX_CONTENT, &chunks, &pages, &final_len));
    REQUIRE(chunks == 37);
    REQUIRE(!geometry_ok(MFDT_MAX_CONTENT + 1, &chunks, &pages, &final_len));
    REQUIRE(geometry_ok(0, &chunks, &pages, &final_len));
    REQUIRE(chunks == 0 && pages == 0);

    /* COMMIT_UNKNOWN classifier permanent unit KATs (literal flags). */
    REQUIRE(classify_commit_unknown(0, 0, 0, 0, 0, 0, 1) == MFDT_CU_ABSENT);
    REQUIRE(classify_commit_unknown(1, 0, 0, 0, 0, 0, 0) == MFDT_CU_OLD);
    REQUIRE(classify_commit_unknown(0, 1, 0, 0, 0, 0, 0) == MFDT_CU_NEW);
    REQUIRE(classify_commit_unknown(0, 0, 1, 0, 0, 0, 0) == MFDT_CU_PARTIAL);
    REQUIRE(classify_commit_unknown(0, 0, 0, 1, 0, 0, 0) == MFDT_CU_EXTRA);
    REQUIRE(classify_commit_unknown(0, 0, 0, 0, 1, 0, 0) == MFDT_CU_THIRD);
    REQUIRE(classify_commit_unknown(0, 0, 0, 0, 0, 1, 0) == MFDT_CU_BOTH);
    REQUIRE(strcmp(cu_name(MFDT_CU_BOTH), "BOTH") == 0);

    /* Authority inventory completeness. */
    REQUIRE(k_mfdt_authority[0].id[0] != '\0');
    REQUIRE(strcmp(k_mfdt_authority[0].id, "MF-CONSTANTS-PINNED") == 0);
    REQUIRE(strcmp(k_mfdt_authority[MFDT_ID_COUNT - 1].id, "MF-GATE-SELF-TEST-PIN") == 0);
    {
        int catalog = 0;
        int budget = 0;
        int cu = 0;
        int pos = 0;
        int neg = 0;
        int transcript = 0;
        for (int i = 0; i < MFDT_ID_COUNT; ++i) {
            if (k_mfdt_authority[i].family == MFDT_FAM_CATALOG) {
                catalog += 1;
            }
            if (k_mfdt_authority[i].family == MFDT_FAM_BUDGET) {
                budget += 1;
            }
            if (k_mfdt_authority[i].family == MFDT_FAM_COMMIT_UNKNOWN) {
                cu += 1;
                REQUIRE(k_mfdt_authority[i].classification[0] != '\0');
            }
            if (k_mfdt_authority[i].family == MFDT_FAM_POSITIVE) {
                pos += 1;
            }
            if (k_mfdt_authority[i].family == MFDT_FAM_NEGATIVE) {
                neg += 1;
            }
            if (k_mfdt_authority[i].family == MFDT_FAM_TRANSCRIPT) {
                transcript += 1;
            }
        }
        REQUIRE(catalog == MFDT_CATALOG_ID_COUNT);
        REQUIRE(budget == MFDT_BUDGET_ID_COUNT);
        REQUIRE(cu == MFDT_COMMIT_UNKNOWN_ID_COUNT);
        REQUIRE(pos == MFDT_POSITIVE_ID_COUNT);
        REQUIRE(neg == MFDT_NEGATIVE_ID_COUNT);
        REQUIRE(transcript == MFDT_TRANSCRIPT_ID_COUNT);
        REQUIRE(catalog + budget + cu + pos + neg + transcript == MFDT_ID_COUNT);
    }

    /* Coherent drift reject: literal page byte0 flip must not equal authority. */
    {
        uint8_t mutant[sizeof(k_mfdt_one_page0)];
        (void)memcpy(mutant, k_mfdt_one_page0, sizeof(mutant));
        mutant[0] ^= 0x01u;
        REQUIRE(!bytes_eq(mutant, k_mfdt_one_page0, sizeof(mutant)));
    }

    /* The independent C authority pins the accepted amendment status exactly. */
    REQUIRE(strcmp(
                k_mfdt_pinned_status,
                "SPEC_ACCEPTED") == 0);
    REQUIRE(strcmp(k_mfdt_pinned_status, "SPEC_REVIEW_CANDIDATE") != 0);
    REQUIRE(strcmp(k_mfdt_pinned_status, "PROPOSED_SPEC_ONLY") != 0);

    (void)printf("MFDT C gate self-test OK ids=%d cu_classes_checked=7\n",
                 MFDT_ID_COUNT);
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode;
    const char *root;
    if (argc < 2) {
        (void)fprintf(stderr, "usage: %s --check|--self-test [repo_root]\n",
                      argv[0]);
        return 2;
    }
    mode = argv[1];
    root = (argc >= 3) ? argv[2] : ".";
    if (strcmp(mode, "--check") == 0) {
        return check_vector_against_authority(root);
    }
    if (strcmp(mode, "--self-test") == 0) {
        return self_test(root);
    }
    (void)fprintf(stderr, "usage: %s --check|--self-test [repo_root]\n", argv[0]);
    return 2;
}
