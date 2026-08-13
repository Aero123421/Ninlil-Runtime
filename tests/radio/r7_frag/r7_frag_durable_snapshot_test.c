/* SPDX-License-Identifier: Apache-2.0 */
/*
 * P0 durable snapshot decoder fail-closed tests (docs/30 lab simulator).
 * Bounds: klen 47/48/49/255, truncation all offsets, dup/out-of-order,
 * oversize count, reserved nonzero, bad CRC/schema, trailing bytes,
 * property mutator under ASan/UBSan. Output state unchanged on failure.
 */

#include "r7_frag_durable.h"

#include <stdio.h>
#include <string.h>

static int g_fail;
static int g_n;

static void expect_i(const char *n, int32_t g, int32_t w)
{
    g_n++;
    if (g != w) {
        fprintf(stderr, "FAIL %s got=%d want=%d\n", n, (int)g, (int)w);
        g_fail++;
    }
}

static void expect_t(const char *n, int c)
{
    g_n++;
    if (!c) {
        fprintf(stderr, "FAIL %s\n", n);
        g_fail++;
    }
}

static void paint_store(ninlil_r7_frag_dur_store *st, uint8_t tag)
{
    size_t i;
    memset(st, 0xA5, sizeof(*st));
    st->cu_ws = NULL;
    st->inject = 0u;
    st->fenced = 0u;
    st->pending_count = 0u;
    st->commit_count = tag;
    st->cu_count = (uint32_t)(0x100u + tag);
    for (i = 0u; i < NINLIL_R7_FRAG_DUR_MAX_KEYS; i++) {
        st->rows[i].in_use = 0u;
    }
}

static int store_tag_unchanged(const ninlil_r7_frag_dur_store *st, uint8_t tag)
{
    return st->commit_count == tag && st->cu_count == (uint32_t)(0x100u + tag)
        && st->rows[0].in_use == 0u;
}

static void put_one(
    ninlil_r7_frag_dur_store *st,
    const uint8_t *key,
    size_t klen,
    const uint8_t *val,
    size_t vlen)
{
    ninlil_r7_frag_dur_begin(st);
    expect_i("put", ninlil_r7_frag_dur_put(st, key, klen, val, vlen),
        NINLIL_R7_FRAG_DUR_OK);
    expect_i("commit", ninlil_r7_frag_dur_commit(st), NINLIL_R7_FRAG_DUR_OK);
}

static void test_roundtrip_ok(void)
{
    ninlil_r7_frag_dur_store a;
    ninlil_r7_frag_dur_store b;
    uint8_t snap[2048];
    size_t slen = 0u;
    uint8_t k1[16];
    uint8_t k2[48];
    uint8_t k47[47];
    uint8_t v1[8];
    uint8_t v2[68];
    uint8_t out[80];
    size_t olen = 0u;
    size_t i;

    memset(&a, 0, sizeof(a));
    ninlil_r7_frag_dur_init(&a);
    memset(k1, 0x11, sizeof(k1));
    memset(k2, 0x22, sizeof(k2));
    k2[0] = 0x33u; /* sort after k1 if k1 all 0x11 */
    memset(k47, 0x12, sizeof(k47));
    memset(v1, 0xAA, sizeof(v1));
    for (i = 0u; i < sizeof(v2); i++) {
        v2[i] = (uint8_t)i;
    }
    put_one(&a, k2, 48u, v2, 68u); /* max key/val */
    put_one(&a, k1, 16u, v1, 8u);
    put_one(&a, k47, 47u, v1, 1u); /* klen 47 */

    expect_i("enc", ninlil_r7_frag_dur_snapshot_encode(&a, snap, sizeof(snap),
                       &slen),
        NINLIL_R7_FRAG_DUR_OK);
    expect_t("slen>=12", slen >= 12u);

    memset(&b, 0, sizeof(b));
    paint_store(&b, 7u);
    expect_i("dec", ninlil_r7_frag_dur_snapshot_decode(&b, snap, slen),
        NINLIL_R7_FRAG_DUR_OK);
    expect_i("get k1-16",
        ninlil_r7_frag_dur_get(&b, k1, 16u, out, sizeof(out), &olen),
        NINLIL_R7_FRAG_DUR_OK);
    expect_t("v1", olen == 8u && memcmp(out, v1, 8u) == 0);
    expect_i("get k2-48",
        ninlil_r7_frag_dur_get(&b, k2, 48u, out, sizeof(out), &olen),
        NINLIL_R7_FRAG_DUR_OK);
    expect_t("v2", olen == 68u && memcmp(out, v2, 68u) == 0);
    expect_i("get k47",
        ninlil_r7_frag_dur_get(&b, k47, 47u, out, sizeof(out), &olen),
        NINLIL_R7_FRAG_DUR_OK);
}

/* Build minimal valid 0-record snapshot via encode. */
static size_t make_empty_snap(uint8_t *out, size_t cap)
{
    ninlil_r7_frag_dur_store st;
    size_t slen = 0u;
    memset(&st, 0, sizeof(st));
    ninlil_r7_frag_dur_init(&st);
    expect_i("empty enc",
        ninlil_r7_frag_dur_snapshot_encode(&st, out, cap, &slen),
        NINLIL_R7_FRAG_DUR_OK);
    return slen;
}

/* One-record valid snapshot with controlled klen/vlen (via encode path). */
static size_t make_one_record_snap(
    uint8_t *out,
    size_t cap,
    size_t klen,
    size_t vlen)
{
    ninlil_r7_frag_dur_store st;
    uint8_t key[NINLIL_R7_FRAG_DUR_KEY_MAX];
    uint8_t val[NINLIL_R7_FRAG_DUR_VAL_MAX];
    size_t slen = 0u;
    size_t i;

    memset(&st, 0, sizeof(st));
    ninlil_r7_frag_dur_init(&st);
    for (i = 0u; i < klen; i++) {
        key[i] = (uint8_t)(0x40u + i);
    }
    for (i = 0u; i < vlen; i++) {
        val[i] = (uint8_t)(0x80u + i);
    }
    put_one(&st, key, klen, val, vlen);
    expect_i("one enc",
        ninlil_r7_frag_dur_snapshot_encode(&st, out, cap, &slen),
        NINLIL_R7_FRAG_DUR_OK);
    return slen;
}

static void test_klen_bounds(void)
{
    uint8_t snap[1024];
    size_t slen;
    ninlil_r7_frag_dur_store st;
    size_t off_klen;

    /* klen 47 / 48 ok via put+encode path */
    slen = make_one_record_snap(snap, sizeof(snap), 47u, 0u);
    paint_store(&st, 1u);
    expect_i("dec klen47", ninlil_r7_frag_dur_snapshot_decode(&st, snap, slen),
        NINLIL_R7_FRAG_DUR_OK);

    slen = make_one_record_snap(snap, sizeof(snap), 48u, 0u);
    paint_store(&st, 2u);
    expect_i("dec klen48", ninlil_r7_frag_dur_snapshot_decode(&st, snap, slen),
        NINLIL_R7_FRAG_DUR_OK);

    /* Forge klen=49 and klen=255 into a one-record body (header+record+crc). */
    slen = make_one_record_snap(snap, sizeof(snap), 1u, 0u);
    /* layout: 8 hdr | k_res | klen | key[1] | v_res | vlen | crc4 */
    off_klen = 8u + 1u;
    {
        uint8_t bad49[1024];
        uint8_t bad255[1024];
        size_t n = slen;
        memcpy(bad49, snap, n);
        bad49[off_klen] = 49u;
        /* expand fake key bytes so length parsing continues then fails capacity */
        paint_store(&st, 3u);
        expect_i("dec klen49",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad49, n),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("unchanged klen49", store_tag_unchanged(&st, 3u));

        memcpy(bad255, snap, n);
        bad255[off_klen] = 255u;
        paint_store(&st, 4u);
        expect_i("dec klen255",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad255, n),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("unchanged klen255", store_tag_unchanged(&st, 4u));
        /* P0 repro class: 1 record / klen=255 / vlen=0 must not accept. */
        expect_t("no row after 255", st.rows[0].in_use == 0u);
        expect_t("key_len not 255", st.rows[0].key_len != 255u);
    }
}

static void test_truncation_all_offsets(void)
{
    uint8_t snap[1024];
    size_t slen;
    size_t cut;
    ninlil_r7_frag_dur_store st;

    slen = make_one_record_snap(snap, sizeof(snap), 8u, 4u);
    for (cut = 0u; cut < slen; cut++) {
        paint_store(&st, 5u);
        expect_i("trunc",
            ninlil_r7_frag_dur_snapshot_decode(&st, snap, cut),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("trunc unchanged", store_tag_unchanged(&st, 5u));
    }
    /* exact length OK */
    paint_store(&st, 6u);
    expect_i("full len", ninlil_r7_frag_dur_snapshot_decode(&st, snap, slen),
        NINLIL_R7_FRAG_DUR_OK);
}

static void test_dup_and_out_of_order(void)
{
    uint8_t snap[1024];
    size_t slen;
    ninlil_r7_frag_dur_store st;
    ninlil_r7_frag_dur_store src;
    uint8_t ka[4] = { 0x01u, 0x02u, 0x03u, 0x04u };
    uint8_t kb[4] = { 0x05u, 0x06u, 0x07u, 0x08u };
    uint8_t v[2] = { 0xAAu, 0xBBu };
    size_t i;

    memset(&src, 0, sizeof(src));
    ninlil_r7_frag_dur_init(&src);
    put_one(&src, ka, 4u, v, 2u);
    put_one(&src, kb, 4u, v, 2u);
    expect_i("enc2",
        ninlil_r7_frag_dur_snapshot_encode(&src, snap, sizeof(snap), &slen),
        NINLIL_R7_FRAG_DUR_OK);

    /* Swap two key first bytes in payload to force out-of-order (break sort). */
    {
        uint8_t bad[1024];
        size_t k0 = 8u + 2u; /* first key after k_res/klen */
        size_t rec0_len = 2u + 4u + 2u + 2u;
        size_t k1 = 8u + rec0_len + 2u;
        memcpy(bad, snap, slen);
        /* swap keys: write kb then ka order by patching key bytes */
        for (i = 0u; i < 4u; i++) {
            bad[k0 + i] = kb[i];
            bad[k1 + i] = ka[i];
        }
        /* CRC no longer matches → CORRUPT (either order or CRC). */
        paint_store(&st, 8u);
        expect_i("ooo/crc",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad, slen),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("ooo unchanged", store_tag_unchanged(&st, 8u));
    }

    /* Duplicate keys with valid CRC: rebuild body manually then re-CRC. */
    {
        uint8_t body[256];
        size_t off = 0u;
        uint32_t crc;
        /* header */
        body[off++] = 0x52u;
        body[off++] = 0x37u;
        body[off++] = 0x44u;
        body[off++] = 0x52u;
        body[off++] = 0u;
        body[off++] = 2u; /* count=2 */
        body[off++] = 0u;
        body[off++] = 1u; /* schema */
        /* rec0 ka */
        body[off++] = 0u;
        body[off++] = 4u;
        memcpy(body + off, ka, 4u);
        off += 4u;
        body[off++] = 0u;
        body[off++] = 2u;
        body[off++] = 0xAAu;
        body[off++] = 0xBBu;
        /* rec1 ka again (dup) */
        body[off++] = 0u;
        body[off++] = 4u;
        memcpy(body + off, ka, 4u);
        off += 4u;
        body[off++] = 0u;
        body[off++] = 2u;
        body[off++] = 0xAAu;
        body[off++] = 0xBBu;
        /* CRC */
        crc = 0xffffffffu;
        {
            size_t b;
            size_t j;
            for (j = 0u; j < off; j++) {
                crc ^= body[j];
                for (b = 0u; b < 8u; b++) {
                    uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
                    crc = (crc >> 1) ^ (0xEDB88320u & mask);
                }
            }
            crc = ~crc;
        }
        body[off++] = (uint8_t)((crc >> 24) & 0xffu);
        body[off++] = (uint8_t)((crc >> 16) & 0xffu);
        body[off++] = (uint8_t)((crc >> 8) & 0xffu);
        body[off++] = (uint8_t)(crc & 0xffu);
        paint_store(&st, 9u);
        expect_i("dup keys",
            ninlil_r7_frag_dur_snapshot_decode(&st, body, off),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("dup unchanged", store_tag_unchanged(&st, 9u));
    }
}

static void test_oversize_and_schema(void)
{
    uint8_t snap[64];
    size_t slen;
    ninlil_r7_frag_dur_store st;

    slen = make_empty_snap(snap, sizeof(snap));
    /* count = 33 > MAX_KEYS=32 */
    {
        uint8_t bad[64];
        memcpy(bad, snap, slen);
        bad[4] = 0u;
        bad[5] = 33u;
        paint_store(&st, 10u);
        expect_i("count33",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad, slen),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("count unchanged", store_tag_unchanged(&st, 10u));
    }
    /* bad schema */
    {
        uint8_t bad[64];
        memcpy(bad, snap, slen);
        bad[7] = 0u;
        paint_store(&st, 11u);
        expect_i("schema0",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad, slen),
            NINLIL_R7_FRAG_DUR_CORRUPT);
    }
    /* fenced > 1 */
    {
        uint8_t bad[64];
        memcpy(bad, snap, slen);
        bad[6] = 2u;
        paint_store(&st, 12u);
        expect_i("fenced2",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad, slen),
            NINLIL_R7_FRAG_DUR_CORRUPT);
    }
    /* bad magic */
    {
        uint8_t bad[64];
        memcpy(bad, snap, slen);
        bad[0] ^= 0xffu;
        paint_store(&st, 13u);
        expect_i("bad magic",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad, slen),
            NINLIL_R7_FRAG_DUR_CORRUPT);
    }
    /* trailing byte after CRC: length+1 with garbage */
    {
        uint8_t bad[128];
        memcpy(bad, snap, slen);
        bad[slen] = 0xFFu;
        paint_store(&st, 14u);
        expect_i("trailing",
            ninlil_r7_frag_dur_snapshot_decode(&st, bad, slen + 1u),
            NINLIL_R7_FRAG_DUR_CORRUPT);
    }
    /* reserved key header nonzero */
    {
        uint8_t one[256];
        size_t n = make_one_record_snap(one, sizeof(one), 3u, 1u);
        one[8] = 1u; /* reserved before klen */
        paint_store(&st, 15u);
        expect_i("k_res", ninlil_r7_frag_dur_snapshot_decode(&st, one, n),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("k_res unchanged", store_tag_unchanged(&st, 15u));
    }
    /* CRC bitflip */
    {
        uint8_t one[256];
        size_t n = make_one_record_snap(one, sizeof(one), 3u, 1u);
        one[n - 1u] ^= 0x01u;
        paint_store(&st, 16u);
        expect_i("bad crc", ninlil_r7_frag_dur_snapshot_decode(&st, one, n),
            NINLIL_R7_FRAG_DUR_CORRUPT);
        expect_t("crc unchanged", store_tag_unchanged(&st, 16u));
    }
}

/* Property: random single-byte mutators of valid snap never half-publish. */
static void test_mutator_property(void)
{
    uint8_t snap[512];
    uint8_t mut[512];
    size_t slen;
    size_t i;
    ninlil_r7_frag_dur_store st;
    uint32_t seed = 0xC0FFEEu;
    int accepted = 0;

    slen = make_one_record_snap(snap, sizeof(snap), 12u, 7u);
    for (i = 0u; i < 256u; i++) {
        size_t pos;
        seed = seed * 1664525u + 1013904223u;
        pos = (size_t)(seed % slen);
        memcpy(mut, snap, slen);
        mut[pos] ^= (uint8_t)(1u + (seed & 0x7fu));
        paint_store(&st, 20u);
        if (ninlil_r7_frag_dur_snapshot_decode(&st, mut, slen)
            == NINLIL_R7_FRAG_DUR_OK) {
            /* Extremely rare if mut lands in a no-effect way; count only. */
            accepted++;
            /* Still must be structured: key_len in range. */
            expect_t("mut key_len cap",
                !st.rows[0].in_use
                    || (st.rows[0].key_len >= 1u
                        && st.rows[0].key_len
                            <= NINLIL_R7_FRAG_DUR_KEY_MAX));
        } else {
            expect_t("mut unchanged", store_tag_unchanged(&st, 20u));
        }
    }
    /* Almost all mutations must fail; allow a tiny fluke budget. */
    expect_t("mut mostly reject", accepted <= 4);
    (void)accepted;
}

/* Explicit P0 repro: crafted 1-record klen=255 vlen=0 (pre-fix shape). */
static void test_p0_repro_klen255(void)
{
    uint8_t blob[267];
    ninlil_r7_frag_dur_store st;
    size_t i;

    memset(blob, 0, sizeof(blob));
    /* magic R7DR */
    blob[0] = 0x52u;
    blob[1] = 0x37u;
    blob[2] = 0x44u;
    blob[3] = 0x52u;
    blob[4] = 0u;
    blob[5] = 1u; /* count */
    blob[6] = 0u;
    blob[7] = 1u; /* schema */
    blob[8] = 0u; /* k_res */
    blob[9] = 255u; /* klen OOB */
    for (i = 10u; i < 10u + 255u; i++) {
        blob[i] = 0x41u;
    }
    /* pretends vlen=0 after key — but we never reach if capacity checked */
    blob[10u + 255u] = 0u;
    blob[10u + 255u + 1u] = 0u;
    /* no valid CRC; total 10+255+2+4 would be 271 — pad to 267 as reported */
    paint_store(&st, 99u);
    expect_i("p0 klen255",
        ninlil_r7_frag_dur_snapshot_decode(&st, blob, sizeof(blob)),
        NINLIL_R7_FRAG_DUR_CORRUPT);
    expect_t("p0 unchanged", store_tag_unchanged(&st, 99u));
    expect_t("p0 no in_use", st.rows[0].in_use == 0u);
    expect_t("p0 key_len not 255", st.rows[0].key_len != 255u);
}

int main(void)
{
    test_roundtrip_ok();
    test_klen_bounds();
    test_truncation_all_offsets();
    test_dup_and_out_of_order();
    test_oversize_and_schema();
    test_mutator_property();
    test_p0_repro_klen255();
    fprintf(stderr, "r7_frag_durable_snapshot_test: %d checks, %d fails\n", g_n,
        g_fail);
    return g_fail == 0 ? 0 : 1;
}
