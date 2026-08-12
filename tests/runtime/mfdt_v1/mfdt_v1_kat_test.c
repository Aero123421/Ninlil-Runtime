/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Independent wire/storage KATs from sealed MFDT vector fixtures.
 * Consumes literal hex from multi-frame-durable-transfer-spec-v1.json —
 * not self-referential lab re-encode as sole authority.
 */
#include "mfdt_v1.h"
#include "mfdt_v1_session.h"

#include <stdio.h>
#include <string.h>

/* ---- Sealed literals (spec/vectors multi-frame-durable-transfer-spec-v1) -- */

/* MF-POS-EMPTY-PAYLOAD fixture.open_body_hex */
static const char *KAT_EMPTY_OPEN_HEX =
    "65676e4349b48e245a8bb7d8cc12905b00000001000000000380000000000016e3b0c44298fc"
    "1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855202122232425262728292a2b"
    "2c2d2e2f00000000000000000000000000000000404142434445464748494a4b4c4d4e4f9091"
    "92939495969798999a9b9c9d9e9f00000000000000010001c620b8ab14d10d7195d959ab7d48"
    "c7ac5313ccb9f05328c1a58a8df77b5865bc0001000100010000e1e2e3e4e5e6e7e8e9eaebec"
    "edeeeff00000000000030d40cb46359b17ce129af28d1cb098f83a5df324e2f67eb953274ac7"
    "fdfad31113e2303132333435363738393a3b3c3d3e3f00000003505152535455565758595a5b"
    "5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081"
    "82838485868788898a8b8c8d8e8f000000000000000b000000000000000c0000000700000000"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5"
    "c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf000000000000001500000000"
    "0000001600000007000000000001000000000002000000000000000700000000000013880000"
    "0003000000006e7378";

/* MF-POS-EMPTY-PAYLOAD fixture.open_accept_hex */
static const char *KAT_EMPTY_OPEN_ACCEPT_HEX =
    "65676e4349b48e245a8bb7d8cc12905b00000001cb46359b17ce129af28d1cb098f83a5df324"
    "e2f67eb953274ac7fdfad31113e21112131415161718191a1b1c1d1e1f200000000031323334"
    "35363738393a3b3c3d3e3f400000000000061a8001000000";

/* MF-POS-EMPTY-PAYLOAD fixture.nm30_value_hex */
static const char *KAT_EMPTY_NM30_HEX =
    "4e4d3330000200b465676e4349b48e245a8bb7d8cc12905b00000001cb46359b17ce129af28d"
    "1cb098f83a5df324e2f67eb953274ac7fdfad31113e200010000000000005152535455565758"
    "595a5b5c5d5e5f6099b8ef7fde7c26074f2f5d61e2e0ec4e537a874f7344312a9f3b47e73047"
    "77dd000000000000000000000000000000003132333435363738393a3b3c3d3e3f4000000000"
    "0007a120404142434445464748494a4b4c4d4e4f02000000c7a99e9f";

/* MF-POS-ONE-BYTE fixture.open_body_hex */
static const char *KAT_ONE_OPEN_HEX =
    "a34ed374841ce22bf08716a2628be99f00000001000000010380000100010016559aead08264"
    "d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd2122232425262728292a2b2c"
    "2d2e2f30000000000000000000000000000000004142434445464748494a4b4c4d4e4f509192"
    "939495969798999a9b9c9d9e9fa0000000000000000100012aa9127751019f8e83cb2c3fc92a"
    "741250e8e813e583139caa3df80f487f1eb00001000100010000e2e3e4e5e6e7e8e9eaebeced"
    "eeeff0f10000000000030d40e536bbd435a20beaffc8bd0bf37aa23dcd3b38752283327e480b"
    "9d35b404a19e3132333435363738393a3b3c3d3e3f40000000035152535455565758595a5b5c"
    "5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182"
    "838485868788898a8b8c8d8e8f90000000000000000b000000000000000c0000000700000000"
    "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6"
    "c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0000000000000001500000000"
    "0000001600000007000000000001000000000002000000000000000700000000000013880000"
    "0003000000006e7378";

/* MF-POS-ONE-BYTE fixture.pages[0].body_hex */
static const char *KAT_ONE_PAGE_HEX =
    "a34ed374841ce22bf08716a2628be99f00000001e536bbd435a20beaffc8bd0bf37aa23dcd3b"
    "38752283327e480b9d35b404a19e000000010000000180db54818c4f98ce5d8b371e4c506331"
    "3c907a37451014a46ebc239418f814510000000100000000559aead08264d5795d3909718cdd"
    "05abd49572e84fe55590eef31a88a08fdffd";

/* Authority expected digests (MF-POS-ONE-BYTE / EMPTY) */
static const char *KAT_ONE_MD =
    "e536bbd435a20beaffc8bd0bf37aa23dcd3b38752283327e480b9d35b404a19e";
static const char *KAT_ONE_WHOLE =
    "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";
static const char *KAT_ONE_TOKEN = "0f1ea7ab66554f029dfc667fa439849b";
static const char *KAT_EMPTY_MD =
    "cb46359b17ce129af28d1cb098f83a5df324e2f67eb953274ac7fdfad31113e2";
static const char *KAT_EMPTY_WHOLE =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char *KAT_EMPTY_TOKEN = "8761b3b0fbf62abbc6be6228421a6d82";

/* MF-POS-REQID-CACHE-SAME-ID-STABLE nrc1_value_hex header (first 40 bytes) */
static const char *KAT_NRC1_HDR =
    "4e52433100013aac262728292a2b2c2d2e2f3031323334350000000100480001";

/*
 * MFN1 transcript literals calculated independently with Python hashlib +
 * struct.pack from ADR-0021's byte layout.  These values deliberately do not
 * come from the C encoder under test.
 */
static const char *KAT_MFN1_OFFER_WIRE =
    "4e434c31013400001020304000000007112233445566778800704d464e310201"
    "0000000000071122334455667788313131313131313131313131313131310000"
    "00030000800003800401a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b2b2b2b2b2b2"
    "b2b2b2b2b2b2b2b2b2b2caed7a50f6ffb50b6db750779fd4c7f8946c70a39ce6"
    "51ed0ef1ccf3316973e5";
static const char *KAT_MFN1_ACCEPT_WIRE =
    "4e434c31013500001020304000000007112233445566778800a04d464e310202000000000007"
    "1122334455667788313131313131313131313131313131314242424242424242424242424242"
    "4242000000030000800003800101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b2b2b2b2b2b2b2b2"
    "b2b2b2b2b2b2b2b2caed7a50f6ffb50b6db750779fd4c7f8946c70a39ce651ed0ef1ccf33169"
    "73e5633f353fe6d4fb790949b81fc66f2ed3e62ee3a24f201319b7563e856d638c5c";

static int g_fail;
static void expect(int c, const char *m)
{
    if (!c) {
        (void)fprintf(stderr, "FAIL: %s\n", m);
        g_fail = 1;
    }
}

static int hex_byte(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0u;
    size_t i = 0u;
    while (h[i] != '\0' && h[i + 1] != '\0' && n < cap) {
        int a = hex_byte(h[i]);
        int b = hex_byte(h[i + 1]);
        if (a < 0 || b < 0) {
            break;
        }
        out[n++] = (uint8_t)((a << 4) | b);
        i += 2u;
    }
    return n;
}

static void test_sealed_empty_open_accept_path(void)
{
    ninlil_mfdt_v1_engine_t rx;
    ninlil_mfdt_v1_workspace_t rws;
    ninlil_mfdt_v1_lab_store_t rst;
    ninlil_mfdt_v1_config_t cfg;
    ninlil_mfdt_v1_response_t resp;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    size_t olen;
    uint8_t want_md[32];
    uint8_t want_whole[32];
    uint8_t want_oa[100];
    size_t wn;

    olen = unhex(KAT_EMPTY_OPEN_HEX, open, sizeof(open));
    expect(olen == NINLIL_MFDT_V1_OPEN_BODY_MIN, "empty open len");
    (void)unhex(KAT_EMPTY_MD, want_md, 32);
    (void)unhex(KAT_EMPTY_WHOLE, want_whole, 32);
    expect(ninlil_mfdt_v1_memeq(open + 32, want_whole, 32u), "empty whole@32");
    expect(ninlil_mfdt_v1_memeq(open + 202, want_md, 32u), "empty md@202");
    expect(ninlil_mfdt_v1_get_u32(open + 20) == 0u, "empty total");
    expect(ninlil_mfdt_v1_get_u16(open + 24) == 896u, "chunk size");
    expect(open[462] == 'n' && open[463] == 's' && open[464] == 'x', "nsx");

    ninlil_mfdt_v1_memzero(&cfg, sizeof(cfg));
    cfg.policy = NINLIL_MFDT_V1_POLICY_ON;
    cfg.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    cfg.session_generation = 1u;
    cfg.mfdt_capability = 1u;
    cfg.session_generation = 1u;
    cfg.host_mode = 1u;
    cfg.now_ms = 1000ull;
    cfg.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    (void)memcpy(cfg.local_clock_epoch.bytes, open + 178, 16u);
    ninlil_mfdt_v1_lab_store_init(&rst);
    expect(ninlil_mfdt_v1_engine_init(&rx, &rws, &rst, &cfg) == 0, "rx init");
    expect(ninlil_mfdt_v1_receiver_on_open(&rx, open, (uint16_t)olen, 1ull,
                                           &resp) == 0,
           "sealed empty OPEN accept");
    expect(resp.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT, "oa type");
    expect(resp.body_len == 100u, "oa len");
    wn = unhex(KAT_EMPTY_OPEN_ACCEPT_HEX, want_oa, sizeof(want_oa));
    expect(wn == 100u, "oa kat len");
    /* BIND52 + md must match sealed; reservation/epoch lab-local may differ */
    expect(ninlil_mfdt_v1_memeq(resp.body, want_oa, 52u), "oa bind52");
    expect(ninlil_mfdt_v1_memeq(resp.body + 20, want_md, 32u), "oa md");
}

static void test_sealed_one_byte_open_page(void)
{
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t page[132];
    uint8_t md[32];
    uint8_t whole[32];
    size_t olen, plen;
    olen = unhex(KAT_ONE_OPEN_HEX, open, sizeof(open));
    plen = unhex(KAT_ONE_PAGE_HEX, page, sizeof(page));
    (void)unhex(KAT_ONE_MD, md, 32);
    (void)unhex(KAT_ONE_WHOLE, whole, 32);
    expect(olen == NINLIL_MFDT_V1_OPEN_BODY_MIN, "one open len");
    expect(plen == 132u, "one page len");
    expect(ninlil_mfdt_v1_get_u32(open + 20) == 1u, "one total");
    expect(ninlil_mfdt_v1_memeq(open + 32, whole, 32u), "one whole");
    expect(ninlil_mfdt_v1_memeq(open + 202, md, 32u), "one md");
    expect(ninlil_mfdt_v1_memeq(page + 20, md, 32u), "page md");
    expect(ninlil_mfdt_v1_get_u16(page + 52) == 0u, "page idx");
    expect(ninlil_mfdt_v1_get_u16(page + 58) == 1u, "entry count");
    /* re-encode page from sealed open tid/md/entries must match sealed page */
    {
        uint8_t out[132];
        uint8_t out_second[132];
        uint8_t out_first_snapshot[132];
        uint8_t alias[132];
        _Alignas(uint16_t) uint8_t invalid[132];
        uint8_t invalid_snapshot[132];
        uint8_t entries_second[40];
        uint8_t invalid_entries[40];
        uint16_t out_len = 0u;
        uint16_t second_len = 0u;
        uint16_t alias_len = 0u;
        uint16_t invalid_len = 0x5a5au;
        uint8_t tid[16];
        const uint8_t *entries = page + 92;
        (void)memcpy(tid, open, 16u);
        expect(ninlil_mfdt_v1_encode_page(tid, 1u, md, 0u, 1u, 0u, 1u, entries, out,
                                          &out_len) == 0 &&
                   out_len == 132u,
               "reenc page");
        expect(ninlil_mfdt_v1_memeq(out, page, 132u), "page bit-exact KAT");

        /* Back-to-back separate outputs cannot share mutable encoder scratch. */
        (void)memcpy(out_first_snapshot, out, sizeof(out));
        (void)memcpy(entries_second, entries, sizeof(entries_second));
        entries_second[39] ^= 0x5au;
        expect(ninlil_mfdt_v1_encode_page(
                   tid, 1u, md, 0u, 1u, 0u, 1u, entries_second, out_second,
                   &second_len) == 0 && second_len == sizeof(out_second),
               "second independent page encode");
        expect(memcmp(out, out_first_snapshot, sizeof(out)) == 0,
               "second encode leaves first output unchanged");
        expect(memcmp(out_second, out, sizeof(out)) != 0,
               "different entries produce independent output");

        /* Exact final-entry alias is the one supported overlap shape. */
        (void)memset(alias, 0xa5, sizeof(alias));
        (void)memcpy(alias + 92, entries, 40u);
        expect(ninlil_mfdt_v1_encode_page(
                   tid, 1u, md, 0u, 1u, 0u, 1u, alias + 92, alias,
                   &alias_len) == 0 && alias_len == sizeof(alias) &&
                   memcmp(alias, page, sizeof(alias)) == 0,
               "page final-entry alias bit-exact");

        /* Unsupported overlap and invalid page shape fail before mutation. */
        (void)memset(invalid, 0x6bu, sizeof(invalid));
        (void)memcpy(invalid_snapshot, invalid, sizeof(invalid));
        expect(ninlil_mfdt_v1_encode_page(
                   tid, 1u, md, 0u, 1u, 0u, 1u, invalid + 1, invalid,
                   &invalid_len) == NINLIL_MFDT_V1_ERR_PARAM,
               "unsupported page overlap rejected");
        expect(memcmp(invalid, invalid_snapshot, sizeof(invalid)) == 0 &&
                   invalid_len == 0x5a5au,
               "overlap reject no mutation");
        expect(ninlil_mfdt_v1_encode_page(
                   tid, 1u, md, 0u, 1u, 0u, 1u, entries, invalid,
                   (uint16_t *)(void *)(invalid + 2u)) ==
                   NINLIL_MFDT_V1_ERR_PARAM &&
                   memcmp(invalid, invalid_snapshot, sizeof(invalid)) == 0,
               "length-output overlap reject no mutation");
        expect(ninlil_mfdt_v1_encode_page(
                   tid, 1u, md, 1u, 1u, 22u, 1u, entries, invalid,
                   &invalid_len) == NINLIL_MFDT_V1_ERR_PARAM &&
                   memcmp(invalid, invalid_snapshot, sizeof(invalid)) == 0,
               "semantic reject no mutation");
        (void)memcpy(invalid_entries, entries, sizeof(invalid_entries));
        (void)memset(invalid_entries + 8u, 0, 32u);
        expect(ninlil_mfdt_v1_encode_page(
                   tid, 1u, md, 0u, 1u, 0u, 1u, invalid_entries, invalid,
                   &invalid_len) == NINLIL_MFDT_V1_ERR_PARAM &&
                   memcmp(invalid, invalid_snapshot, sizeof(invalid)) == 0 &&
                   invalid_len == 0x5a5au,
               "entry semantic reject no mutation");
    }
}

static void refresh_empty_manifest(uint8_t *open, uint16_t open_len)
{
    uint8_t digest[32];

    ninlil_mfdt_v1_manifest_digest(
        open, open + NINLIL_MFDT_V1_OPEN_BASE_BYTES,
        open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET,
        (uint16_t)(open_len - NINLIL_MFDT_V1_OPEN_TEXT_OFFSET),
        NULL, 0u, digest);
    (void)memcpy(open + 202u, digest, sizeof(digest));
}

static void test_open_revision2_boundaries_and_mutations(void)
{
    static const uint16_t binding_offsets[25] = {
        234u, 250u, 254u, 270u, 286u, 302u, 318u, 326u, 334u,
        338u, 342u, 358u, 374u, 390u, 406u, 414u, 422u, 426u,
        430u, 432u, 434u, 438u, 446u, 454u, 458u};
    typedef struct semantic_mutation {
        uint16_t offset;
        uint8_t width;
        uint8_t byte_index;
        uint8_t value;
        uint8_t clear_first;
    } semantic_mutation_t;
    static const semantic_mutation_t semantic_mutations[] = {
        {64u, 16u, 0u, 0u, 1u},    /* origin transaction */
        {96u, 16u, 0u, 0u, 1u},    /* source Runtime */
        {112u, 16u, 0u, 0u, 1u},   /* target Runtime */
        {128u, 8u, 0u, 0u, 1u},    /* descriptor revision */
        {138u, 32u, 0u, 0u, 1u},   /* descriptor digest */
        {234u, 16u, 0u, 0u, 1u},   /* original attempt */
        {250u, 4u, 3u, 4u, 1u},    /* target ordinal */
        {254u, 16u, 0u, 0u, 1u},   /* source application */
        {334u, 4u, 0u, 0x80u, 0u}, /* source identity flags */
        {338u, 4u, 3u, 1u, 1u},    /* source reserved */
        {342u, 16u, 0u, 0u, 1u},   /* target application */
        {422u, 4u, 0u, 0x80u, 0u}, /* target identity flags */
        {426u, 4u, 3u, 1u, 1u},    /* target reserved */
        {430u, 2u, 0u, 0u, 1u},    /* schema major */
        {434u, 4u, 0u, 0u, 1u},    /* family */
        {438u, 8u, 0u, 0u, 1u},    /* generation */
        {454u, 4u, 0u, 0u, 1u},    /* evidence */
        {458u, 4u, 3u, 1u, 1u},    /* binding flags */
        {462u, 1u, 0u, (uint8_t)'N', 1u} /* invalid text */
    };
    uint8_t base[NINLIL_MFDT_V1_OPEN_BODY_MIN];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX + 1u];
    uint8_t original_manifest[32];
    uint8_t changed_manifest[32];
    size_t base_len;
    size_t index;

    base_len = unhex(KAT_EMPTY_OPEN_HEX, base, sizeof(base));
    expect(base_len == sizeof(base), "revision2 OPEN fixture length");
    expect(ninlil_mfdt_v1_validate_open(
               base, (uint16_t)base_len, NULL, 0u, NULL, 0u, 1u) ==
               NINLIL_MFDT_V1_OK,
           "minimum revision2 OPEN accepted");

    (void)memcpy(original_manifest, base + 202u, sizeof(original_manifest));
    for (index = 0u;
         index < sizeof(binding_offsets) / sizeof(binding_offsets[0]);
         ++index) {
        (void)memcpy(open, base, base_len);
        open[binding_offsets[index]] ^= 0x01u;
        ninlil_mfdt_v1_manifest_digest(
            open, open + NINLIL_MFDT_V1_OPEN_BASE_BYTES,
            open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET, 3u,
            NULL, 0u, changed_manifest);
        expect(!ninlil_mfdt_v1_memeq(
                   changed_manifest, original_manifest,
                   sizeof(original_manifest)),
               "all 25 application-binding fields are manifest-bound");
    }

    for (index = 0u;
         index < sizeof(semantic_mutations) / sizeof(semantic_mutations[0]);
         ++index) {
        const semantic_mutation_t *mutation = &semantic_mutations[index];
        (void)memcpy(open, base, base_len);
        if (mutation->clear_first != 0u) {
            (void)memset(open + mutation->offset, 0, mutation->width);
        }
        open[mutation->offset + mutation->byte_index] = mutation->value;
        refresh_empty_manifest(open, (uint16_t)base_len);
        expect(ninlil_mfdt_v1_validate_open(
                   open, (uint16_t)base_len, NULL, 0u, NULL, 0u, 1u) ==
                   NINLIL_MFDT_V1_ERR_LAYOUT,
               "non-canonical original Application field rejected");
    }

    (void)memcpy(open, base, base_len);
    ninlil_mfdt_v1_put_u16(open + 170u, 63u);
    ninlil_mfdt_v1_put_u16(open + 172u, 63u);
    ninlil_mfdt_v1_put_u16(open + 174u, 63u);
    (void)memset(open + 462u, 'n', 63u);
    (void)memset(open + 525u, 's', 63u);
    (void)memset(open + 588u, 'x', 63u);
    refresh_empty_manifest(open, NINLIL_MFDT_V1_OPEN_BODY_MAX);
    expect(ninlil_mfdt_v1_validate_open(
               open, NINLIL_MFDT_V1_OPEN_BODY_MAX,
               NULL, 0u, NULL, 0u, 1u) == NINLIL_MFDT_V1_OK,
           "maximum revision2 OPEN accepted");
    open[NINLIL_MFDT_V1_OPEN_BODY_MAX] = (uint8_t)'x';
    ninlil_mfdt_v1_put_u16(open + 174u, 64u);
    expect(ninlil_mfdt_v1_validate_open(
               open, (uint16_t)(NINLIL_MFDT_V1_OPEN_BODY_MAX + 1u),
               NULL, 0u, NULL, 0u, 1u) == NINLIL_MFDT_V1_ERR_LAYOUT,
           "revision2 OPEN maximum plus one rejected");
}

static void test_nrc1_layout_and_header_kat(void)
{
    uint8_t hdr[32];
    size_t n = unhex(KAT_NRC1_HDR, hdr, sizeof(hdr));
    expect(n == 32u, "nrc1 hdr bytes");
    expect(ninlil_mfdt_v1_memeq(hdr, "NRC1", 4u), "magic");
    expect(ninlil_mfdt_v1_get_u16(hdr + 4) == 1u, "schema");
    expect(ninlil_mfdt_v1_get_u16(hdr + 6) == 15020u, "vlen");
    expect(ninlil_mfdt_v1_get_u32(hdr + 24) == 1u, "session gen");
    expect(ninlil_mfdt_v1_get_u16(hdr + 28) == 72u, "slot count");
    expect(ninlil_mfdt_v1_get_u16(hdr + 30) == 1u, "occupied");
    /* constants pin */
    expect(NINLIL_MFDT_V1_NRC1_SLOT_BYTES == 208u, "slot 208");
    expect(NINLIL_MFDT_V1_NRC1_SLOT_COUNT == 72u, "slots 72");
    expect(NINLIL_MFDT_V1_NRC1_VALUE_BYTES == 15020u, "value 15020");
    expect(NINLIL_MFDT_V1_NRC1_LOGICAL_BYTES == 15056u, "logical 15056");
}

static void test_nm30_sealed_layout(void)
{
    static const uint8_t expected_peer[16] = {
        0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
        0x48u, 0x49u, 0x4au, 0x4bu, 0x4cu, 0x4du, 0x4eu, 0x4fu};
    uint8_t nm30[NINLIL_MFDT_V1_NM30_BYTES];
    size_t n = unhex(KAT_EMPTY_NM30_HEX, nm30, sizeof(nm30));
    uint32_t crc;
    expect(n == NINLIL_MFDT_V1_NM30_BYTES, "nm30 len");
    expect(ninlil_mfdt_v1_memeq(nm30, "NM30", 4u), "nm30 magic");
    expect(ninlil_mfdt_v1_get_u16(nm30 + 4) == 2u, "schema");
    expect(ninlil_mfdt_v1_get_u16(nm30 + 6) ==
               NINLIL_MFDT_V1_NM30_BYTES,
           "hdr len");
    expect(ninlil_mfdt_v1_memeq(nm30 + 156, expected_peer, 16u),
           "terminal peer");
    expect(nm30[172] == 2u,
           "terminal owner role");
    expect(nm30[173] == 0u && nm30[174] == 0u && nm30[175] == 0u,
           "terminal reserved");
    crc = ninlil_mfdt_v1_crc32c(nm30, 176u);
    expect(crc == ninlil_mfdt_v1_get_u32(nm30 + 176), "nm30 crc");
}

static void test_publication_token_formula_empty(void)
{
    uint8_t tid[16], md[32], whole[32], ev[16], token[16], want[16];
    (void)unhex("65676e4349b48e245a8bb7d8cc12905b", tid, 16);
    (void)unhex(KAT_EMPTY_MD, md, 32);
    (void)unhex(KAT_EMPTY_WHOLE, whole, 32);
    (void)unhex("5152535455565758595a5b5c5d5e5f60", ev, 16);
    (void)unhex(KAT_EMPTY_TOKEN, want, 16);
    ninlil_mfdt_v1_publication_token(tid, 1u, md, whole, 0u, ev, token);
    expect(ninlil_mfdt_v1_memeq(token, want, 16u), "empty publication token KAT");
    (void)KAT_ONE_TOKEN;
}

static void repair_record_crcs(uint8_t *rec, uint32_t rec_len)
{
    ninlil_mfdt_v1_put_u32(
        rec + 304u, ninlil_mfdt_v1_crc32c(rec, 304u));
    ninlil_mfdt_v1_put_u32(
        rec + rec_len - 4u, ninlil_mfdt_v1_crc32c(rec, rec_len - 4u));
}

static void test_record_roundtrip(void)
{
    uint8_t tid[16], md[32];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MIN], entries[40], content[1];
    uint8_t reservation_id[16];
    uint8_t epoch[16];
    uint8_t rec[4096];
    uint32_t rlen = 0;
    uint8_t owner = 0, state = 0, pb = 0, rb = 0, pub = 0, ho = 0;
    uint32_t rev = 0, cl = 0;
    uint64_t rgen = 0, cb = 0;
    const uint8_t *ob = NULL, *en = NULL, *ct = NULL;
    uint16_t ol = 0, eb = 0;
    uint8_t md2[32];
    expect(unhex(KAT_ONE_OPEN_HEX, open, sizeof(open)) == sizeof(open),
           "record fixture open");
    (void)memcpy(tid, open, 16u);
    (void)memcpy(md, open + 202, 32u);
    content[0] = 0u; /* missing receiver chunk is canonical zero */
    memset(entries, 0, 40);
    memset(reservation_id, 0xb0, sizeof(reservation_id));
    memset(epoch, 0xc0, sizeof(epoch));
    expect(ninlil_mfdt_v1_record_pack(2u, 32u, tid, 1u, md, open,
                                      NINLIL_MFDT_V1_OPEN_BODY_MIN, entries, 40u,
                                      content, 1u, 1ull, 0u, 0ull, 8u, 0u, 0u,
                                      reservation_id, epoch, 301000ull, NULL,
                                      1u, rec, sizeof(rec),
                                      &rlen) == 0,
           "pack");
    (void)memcpy(rec + 200, epoch, 16u);
    ninlil_mfdt_v1_put_u64(rec + 216, 1000ull);
    ninlil_mfdt_v1_put_u32(rec + 304,
                           ninlil_mfdt_v1_crc32c(rec, 304u));
    ninlil_mfdt_v1_put_u32(rec + rlen - 4u,
                           ninlil_mfdt_v1_crc32c(rec, rlen - 4u));
    expect(rlen == 308u + NINLIL_MFDT_V1_OPEN_BODY_MIN + 40u + 1u + 4u,
           "record size");
    expect(ninlil_mfdt_v1_record_unpack(rec, rlen, &owner, &state, tid, &rev, md2, &ob,
                                        &ol, &en, &eb, &ct, &cl, &rgen, &pb, &cb, &rb,
                                        &pub, &ho) == 0,
           "unpack");
    expect(owner == 2u && state == 32u &&
               ol == NINLIL_MFDT_V1_OPEN_BODY_MIN && eb == 40u && cl == 1u,
           "fields");
    expect(rb == 8u, "retry budget field");

    ninlil_mfdt_v1_put_u16(rec + 4u, 1u);
    repair_record_crcs(rec, rlen);
    expect(ninlil_mfdt_v1_record_unpack(
               rec, rlen, &owner, &state, tid, &rev, md2, &ob, &ol, &en,
               &eb, &ct, &cl, &rgen, &pb, &cb, &rb, &pub, &ho) ==
               NINLIL_MFDT_V1_ERR_CORRUPT,
           "active schema1 rejected without migration");
    ninlil_mfdt_v1_put_u16(rec + 4u, NINLIL_MFDT_V1_ACTIVE_SCHEMA);
    repair_record_crcs(rec, rlen);

    /*
     * The receiver owns the reservation clock, so its durable local epoch
     * must match the reservation epoch.  A sender stores the peer epoch and
     * is covered separately by the two-clock integrated restart scenario.
     */
    (void)memset(rec + 200u, 0xd0, 16u);
    repair_record_crcs(rec, rlen);
    expect(ninlil_mfdt_v1_record_unpack(
               rec, rlen, &owner, &state, tid, &rev, md2, &ob, &ol, &en, &eb,
               &ct, &cl, &rgen, &pb, &cb, &rb, &pub, &ho) ==
               NINLIL_MFDT_V1_ERR_CORRUPT,
           "receiver foreign reservation clock epoch rejected");
    (void)memcpy(rec + 200u, epoch, 16u);
    repair_record_crcs(rec, rlen);
    expect(ninlil_mfdt_v1_record_unpack(
               rec, rlen, &owner, &state, tid, &rev, md2, &ob, &ol, &en, &eb,
               &ct, &cl, &rgen, &pb, &cb, &rb, &pub, &ho) ==
               NINLIL_MFDT_V1_OK,
           "receiver reservation clock epoch restored");

    /*
     * Semantic mutants repair both CRCs. A CRC-only reader would accept all
     * four; the production reader must reject the closed state/layout
     * violations before installing durable custody.
     */
    rec[13] = 0xffu;
    repair_record_crcs(rec, rlen);
    expect(ninlil_mfdt_v1_record_unpack(
               rec, rlen, &owner, &state, tid, &rev, md2, &ob, &ol, &en, &eb,
               &ct, &cl, &rgen, &pb, &cb, &rb, &pub, &ho) ==
               NINLIL_MFDT_V1_ERR_CORRUPT,
           "CRC-repaired invalid active state rejected");
    rec[13] = NINLIL_MFDT_V1_R_RESERVED_OPEN;
    rec[14] = 1u;
    repair_record_crcs(rec, rlen);
    expect(ninlil_mfdt_v1_record_unpack(
               rec, rlen, &owner, &state, tid, &rev, md2, &ob, &ol, &en, &eb,
               &ct, &cl, &rgen, &pb, &cb, &rb, &pub, &ho) ==
               NINLIL_MFDT_V1_ERR_CORRUPT,
           "CRC-repaired reserved field rejected");
    rec[14] = 0u;
    rec[104] = 0x80u;
    repair_record_crcs(rec, rlen);
    expect(ninlil_mfdt_v1_record_unpack(
               rec, rlen, &owner, &state, tid, &rev, md2, &ob, &ol, &en, &eb,
               &ct, &cl, &rgen, &pb, &cb, &rb, &pub, &ho) ==
               NINLIL_MFDT_V1_ERR_CORRUPT,
           "CRC-repaired bitmap overflow rejected");
    rec[104] = 0u;
    (void)memset(rec + 308u + 64u, 0, 16u);
    repair_record_crcs(rec, rlen);
    expect(ninlil_mfdt_v1_record_unpack(
               rec, rlen, &owner, &state, tid, &rev, md2, &ob, &ol, &en, &eb,
               &ct, &cl, &rgen, &pb, &cb, &rb, &pub, &ho) ==
               NINLIL_MFDT_V1_ERR_CORRUPT,
           "CRC-repaired embedded OPEN identity rejected");
}

static void test_record_preflight_boundaries(void)
{
    uint8_t tid[16];
    uint8_t manifest[32];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MIN];
    uint8_t entries[NINLIL_MFDT_V1_ENTRY_BYTES];
    uint8_t content[1] = {0u};
    uint8_t out[1024];
    uint8_t canary[sizeof(out)];
    uint32_t out_len;
    uint32_t valid_len = 0u;

    expect(unhex(KAT_ONE_OPEN_HEX, open, sizeof(open)) == sizeof(open),
           "record boundary fixture OPEN");
    (void)memcpy(tid, open, sizeof(tid));
    (void)memcpy(manifest, open + 202u, sizeof(manifest));
    (void)memset(entries, 0, sizeof(entries));
    (void)memset(out, 0xa5, sizeof(out));
    (void)memcpy(canary, out, sizeof(out));

    out_len = UINT32_C(0xdec0ad01);
    expect(ninlil_mfdt_v1_record_pack(
               2u, NINLIL_MFDT_V1_R_RESERVED_OPEN, tid, 1u, NULL,
               open, sizeof(open), entries, sizeof(entries), content,
               sizeof(content), 1u, 0u, 0u,
               NINLIL_MFDT_V1_RETRY_BUDGET_MAX, 0u, 0u, NULL, NULL, 0u,
               NULL, 1u, out, sizeof(out), &out_len) ==
               NINLIL_MFDT_V1_ERR_PARAM &&
               out_len == UINT32_C(0xdec0ad01) &&
               memcmp(out, canary, sizeof(out)) == 0,
           "record pack NULL manifest leaves output exact");

    out_len = UINT32_C(0xdec0ad02);
    expect(ninlil_mfdt_v1_record_pack(
               2u, NINLIL_MFDT_V1_R_RESERVED_OPEN, tid, 1u, manifest,
               open, sizeof(open), entries,
               (uint16_t)(sizeof(entries) - 1u), content, sizeof(content),
               1u, 0u, 0u, NINLIL_MFDT_V1_RETRY_BUDGET_MAX, 0u, 0u,
               NULL, NULL, 0u, NULL, 1u, out, sizeof(out), &out_len) ==
               NINLIL_MFDT_V1_ERR_LAYOUT &&
               out_len == UINT32_C(0xdec0ad02) &&
               memcmp(out, canary, sizeof(out)) == 0,
           "record pack invalid entry geometry leaves output exact");

    out_len = UINT32_C(0xdec0ad03);
    expect(ninlil_mfdt_v1_record_pack(
               2u, NINLIL_MFDT_V1_R_RESERVED_OPEN, tid, 1u, manifest,
               open, sizeof(open), entries, sizeof(entries), content,
               UINT32_MAX, 1u, 0u, 0u,
               NINLIL_MFDT_V1_RETRY_BUDGET_MAX, 0u, 0u, NULL, NULL, 0u,
               NULL, 1u, out, sizeof(out), &out_len) !=
               NINLIL_MFDT_V1_OK &&
               out_len == UINT32_C(0xdec0ad03) &&
               memcmp(out, canary, sizeof(out)) == 0,
           "record pack UINT32_MAX content leaves output exact");

    expect(ninlil_mfdt_v1_record_pack(
               2u, NINLIL_MFDT_V1_R_RESERVED_OPEN, tid, 1u, manifest,
               open, sizeof(open), entries, sizeof(entries), content,
               sizeof(content), 1u, 0u, 0u,
               NINLIL_MFDT_V1_RETRY_BUDGET_MAX, 0u, 0u, NULL, NULL, 0u,
               NULL, 1u, out, sizeof(out), &valid_len) ==
               NINLIL_MFDT_V1_OK,
           "record boundary valid pack");
    ninlil_mfdt_v1_put_u32(out + 88u, UINT32_MAX);
    ninlil_mfdt_v1_put_u32(
        out + 304u, ninlil_mfdt_v1_crc32c(out, 304u));
    expect(ninlil_mfdt_v1_record_unpack(
               out, valid_len, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
               NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
               NULL) == NINLIL_MFDT_V1_ERR_CORRUPT,
           "record unpack UINT32_MAX geometry rejects before pointer math");
}

static void test_sender_active_schema_gate(void)
{
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MIN];
    uint8_t tid[16];
    uint8_t manifest[32];
    uint8_t epoch[16];
    uint8_t record[1024];
    uint8_t owner = 0u, state = 0u, page_bitmap = 0u;
    uint8_t retry = 0u, publication = 0u, handoff = 0u;
    uint8_t unpacked_tid[16], unpacked_manifest[32];
    uint16_t open_len = 0u, entry_bytes = 0u;
    uint32_t revision = 0u, content_len = 0u, record_len = 0u;
    uint64_t generation = 0u, chunk_bitmap = 0u;
    const uint8_t *open_view = NULL, *entry_view = NULL;
    const uint8_t *content_view = NULL;

    expect(unhex(KAT_EMPTY_OPEN_HEX, open, sizeof(open)) == sizeof(open),
           "sender schema fixture OPEN");
    (void)memcpy(tid, open, sizeof(tid));
    (void)memcpy(manifest, open + 202u, sizeof(manifest));
    (void)memset(epoch, 0xc0, sizeof(epoch));
    expect(ninlil_mfdt_v1_record_pack(
               1u, NINLIL_MFDT_V1_S_OPEN_PENDING, tid, 1u, manifest,
               open, sizeof(open), NULL, 0u, NULL, 0u, 1u, 0u, 0ull,
               NINLIL_MFDT_V1_RETRY_BUDGET_MAX, 0u, 0u, NULL, NULL, 0ull,
               NULL, 1u, record, sizeof(record), &record_len) ==
               NINLIL_MFDT_V1_OK,
           "sender active schema2 pack");
    (void)memcpy(record + 200u, epoch, sizeof(epoch));
    repair_record_crcs(record, record_len);
    expect(ninlil_mfdt_v1_record_unpack(
               record, record_len, &owner, &state, unpacked_tid, &revision,
               unpacked_manifest, &open_view, &open_len, &entry_view,
               &entry_bytes, &content_view, &content_len, &generation,
               &page_bitmap, &chunk_bitmap, &retry, &publication,
               &handoff) == NINLIL_MFDT_V1_OK,
           "sender active schema2 accepted");
    ninlil_mfdt_v1_put_u16(record + 4u, 1u);
    repair_record_crcs(record, record_len);
    expect(ninlil_mfdt_v1_record_unpack(
               record, record_len, &owner, &state, unpacked_tid, &revision,
               unpacked_manifest, &open_view, &open_len, &entry_view,
               &entry_bytes, &content_view, &content_len, &generation,
               &page_bitmap, &chunk_bitmap, &retry, &publication,
               &handoff) == NINLIL_MFDT_V1_ERR_CORRUPT,
           "sender active schema1 rejected without migration");
}

static void test_mfn1_independent_wire_kat(void)
{
    ninlil_mfdt_v1_session_t initiator;
    ninlil_mfdt_v1_session_t responder;
    uint8_t initiator_id[16];
    uint8_t responder_id[16];
    uint8_t request_nonce[16];
    uint8_t responder_nonce[16];
    uint8_t expected_offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t expected_accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t corrupted[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t transcript_preimage[22u + 4u + 128u];
    uint8_t legacy_digest[32];
    size_t expected_offer_len;
    size_t expected_accept_len;
    size_t offer_len = 0u;
    size_t accept_len = 0u;

    (void)memset(initiator_id, 0xa1, sizeof(initiator_id));
    (void)memset(responder_id, 0xb2, sizeof(responder_id));
    (void)memset(request_nonce, 0x31, sizeof(request_nonce));
    (void)memset(responder_nonce, 0x42, sizeof(responder_nonce));
    expected_offer_len =
        unhex(KAT_MFN1_OFFER_WIRE, expected_offer, sizeof(expected_offer));
    expected_accept_len =
        unhex(KAT_MFN1_ACCEPT_WIRE, expected_accept, sizeof(expected_accept));
    expect(expected_offer_len == 138u, "MFN1 sealed OFFER length");
    expect(expected_accept_len == 186u, "MFN1 sealed ACCEPT length");

    ninlil_mfdt_v1_session_init(
        &initiator, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_session_init(
        &responder, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    expect(ninlil_mfdt_v1_session_bind(
               &initiator, 2u, 7u, 0x1122334455667788ull, 1u,
               initiator_id, responder_id) == NINLIL_MFDT_V1_OK,
           "MFN1 KAT initiator bind");
    expect(ninlil_mfdt_v1_session_bind(
               &responder, 2u, 7u, 0x1122334455667788ull, 0u,
               responder_id, initiator_id) == NINLIL_MFDT_V1_OK,
           "MFN1 KAT responder bind");
    expect(ninlil_mfdt_v1_session_build_offer(
               &initiator, 0x10203040u, request_nonce, offer, sizeof(offer),
               &offer_len) == NINLIL_MFDT_V1_OK,
           "MFN1 KAT build OFFER");
    expect(offer_len == expected_offer_len &&
               ninlil_mfdt_v1_memeq(offer, expected_offer, offer_len),
           "MFN1 OFFER bit-exact independent KAT");
    expect(ninlil_mfdt_v1_session_on_offer(
               &responder, offer, offer_len, responder_nonce, accept,
               sizeof(accept), &accept_len) == NINLIL_MFDT_V1_OK,
           "MFN1 KAT build ACCEPT");
    expect(accept_len == expected_accept_len &&
               ninlil_mfdt_v1_memeq(accept, expected_accept, accept_len),
           "MFN1 ACCEPT bit-exact independent KAT");
    expect(ninlil_mfdt_v1_session_on_accept(
               &initiator, expected_accept, expected_accept_len) ==
               NINLIL_MFDT_V1_OK,
           "MFN1 sealed ACCEPT admits initiator");

    /* A valid legacy revision-1 offer is not upgraded in place. */
    ninlil_mfdt_v1_session_init(
        &responder, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    expect(ninlil_mfdt_v1_session_bind(
               &responder, 2u, 7u, 0x1122334455667788ull, 0u,
               responder_id, initiator_id) == NINLIL_MFDT_V1_OK,
           "MFN1 revision1 responder bind");
    (void)memcpy(corrupted, expected_offer, expected_offer_len);
    corrupted[26u + 4u] = 1u;
    (void)unhex(
        "22cab507fbcbbfed2a73861252195b38e26169c34d35ed8bb3165b6838de772a",
        corrupted + 26u + 80u, 32u);
    expect(ninlil_mfdt_v1_session_on_offer(
               &responder, corrupted, expected_offer_len, responder_nonce,
               accept, sizeof(accept), &accept_len) ==
               NINLIL_MFDT_V1_ERR_LAYOUT,
           "MFN1 revision1 offer rejected without migration");

    /* A revision-1 ACCEPT cannot complete a revision-2 OFFER transcript. */
    ninlil_mfdt_v1_session_init(
        &initiator, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    expect(ninlil_mfdt_v1_session_bind(
               &initiator, 2u, 7u, 0x1122334455667788ull, 1u,
               initiator_id, responder_id) == NINLIL_MFDT_V1_OK,
           "MFN1 mixed initiator bind");
    expect(ninlil_mfdt_v1_session_build_offer(
               &initiator, 0x10203040u, request_nonce, offer, sizeof(offer),
               &offer_len) == NINLIL_MFDT_V1_OK,
           "MFN1 mixed build revision2 offer");
    (void)memcpy(corrupted, expected_accept, expected_accept_len);
    corrupted[26u + 4u] = 1u;
    (void)memcpy(transcript_preimage, "NINLIL-MFDT-ACCEPT-V1", 22u);
    ninlil_mfdt_v1_put_u32(transcript_preimage + 22u, 0x10203040u);
    (void)memcpy(transcript_preimage + 26u, corrupted + 26u, 128u);
    ninlil_mfdt_v1_sha256(
        transcript_preimage, sizeof(transcript_preimage), legacy_digest);
    (void)memcpy(corrupted + 26u + 128u, legacy_digest, 32u);
    expect(ninlil_mfdt_v1_session_on_accept(
               &initiator, corrupted, expected_accept_len) ==
               NINLIL_MFDT_V1_ERR_LAYOUT,
           "MFN1 revision2/revision1 mixed transcript rejected");

    /* A digest mutation must never be accepted as a new transcript. */
    ninlil_mfdt_v1_session_init(
        &responder, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    expect(ninlil_mfdt_v1_session_bind(
               &responder, 2u, 7u, 0x1122334455667788ull, 0u,
               responder_id, initiator_id) == NINLIL_MFDT_V1_OK,
           "MFN1 mutation responder bind");
    (void)memcpy(corrupted, expected_offer, expected_offer_len);
    corrupted[expected_offer_len - 1u] ^= 0x01u;
    expect(ninlil_mfdt_v1_session_on_offer(
               &responder, corrupted, expected_offer_len, responder_nonce,
               accept, sizeof(accept), &accept_len) ==
               NINLIL_MFDT_V1_ERR_LAYOUT,
           "MFN1 corrupted OFFER digest rejected");
}

int main(void)
{
    g_fail = 0;
    test_nrc1_layout_and_header_kat();
    test_sealed_empty_open_accept_path();
    test_sealed_one_byte_open_page();
    test_open_revision2_boundaries_and_mutations();
    test_nm30_sealed_layout();
    test_publication_token_formula_empty();
    test_record_roundtrip();
    test_record_preflight_boundaries();
    test_sender_active_schema_gate();
    test_mfn1_independent_wire_kat();
    if (g_fail) {
        (void)fprintf(stderr, "mfdt_v1_kat_test FAILED\n");
        return 1;
    }
    (void)printf("mfdt_v1_kat_test OK\n");
    return 0;
}
