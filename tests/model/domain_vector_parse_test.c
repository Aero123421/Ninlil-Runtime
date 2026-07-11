#include "domain_vector_parse.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "%s:%d fail %s\n", __FILE__, __LINE__, #c);  \
            return 1;                                                          \
        }                                                                      \
    } while (0)

/*
 * High catalog presence bits (not wire/JSON fields) for future headroom.
 * Bit 34 is real D1-B3e (subtype 34); bit 35 is real D1-B3f (subtype 33);
 * bit 36 is real D1-B3g (subtype 32). Synthetic missing/truncation arithmetic
 * uses unused bit40. Bit63 remains a storage-width proof.
 */
#define NINLIL_DV_CAT_TEST_BIT40 NINLIL_DV_CAT_BIT(40)
#define NINLIL_DV_CAT_TEST_BIT63 NINLIL_DV_CAT_BIT(63)

_Static_assert(sizeof(((ninlil_dv_file_t){0}).catalog_bits) == sizeof(uint64_t),
    "catalog_bits must be uint64_t for B3b+ presence growth");
_Static_assert(sizeof(((ninlil_dv_file_t){0}).top_bits) == sizeof(uint32_t),
    "top_bits remains uint32_t (separate from catalog presence)");
_Static_assert(NINLIL_DV_CAT_DSB3_27 == NINLIL_DV_CAT_BIT(31),
    "D1-B3b subtype 27 catalog bit is bit 31 (no shift of 0..30)");
_Static_assert(NINLIL_DV_CAT_DSB3_30 == NINLIL_DV_CAT_BIT(32),
    "D1-B3c subtype 30 catalog bit is bit 32 (no shift of 0..31)");
_Static_assert(NINLIL_DV_CAT_DSB3_31 == NINLIL_DV_CAT_BIT(33),
    "D1-B3d subtype 31 catalog bit is bit 33 (no shift of 0..32)");
_Static_assert(NINLIL_DV_CAT_DSB3_34 == NINLIL_DV_CAT_BIT(34),
    "D1-B3e subtype 34 catalog bit is bit 34 (no shift of 0..33)");
_Static_assert(NINLIL_DV_CAT_DSB3_33 == NINLIL_DV_CAT_BIT(35),
    "D1-B3f subtype 33 catalog bit is bit 35 (no shift of 0..34)");
_Static_assert(NINLIL_DV_CAT_DSB3_32 == NINLIL_DV_CAT_BIT(36),
    "D1-B3g subtype 32 catalog bit is bit 36 (no shift of 0..35)");
_Static_assert(NINLIL_DV_CAT_DSB3_42 == NINLIL_DV_CAT_BIT(39),
    "D1-B3j subtype 42 catalog bit is bit 39 (no shift of 0..38)");
_Static_assert(NINLIL_DV_CAT_DSB3_NEG == NINLIL_DV_CAT_BIT(30),
    "pre-B3b highest wire catalog bit stays bit 30");
_Static_assert(NINLIL_DV_CAT_TEST_BIT40 == (UINT64_C(1) << 40),
    "bit 40 must be expressible via UINT64_C(1) shift");
_Static_assert(NINLIL_DV_CAT_TEST_BIT63 == (UINT64_C(1) << 63),
    "bit 63 must be expressible via UINT64_C(1) shift");
_Static_assert((NINLIL_DV_CAT_REQUIRED_MASK & NINLIL_DV_CAT_TEST_BIT40) == 0u,
    "test high bits are not part of the current required mask");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_TEST_BIT40)
        != (uint64_t)(uint32_t)(NINLIL_DV_CAT_REQUIRED_MASK
            | NINLIL_DV_CAT_TEST_BIT40),
    "uint32 storage would truncate catalog presence bit 40");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK & NINLIL_DV_CAT_DSB3_30) != 0u,
    "B3c catalog bit 32 is part of the required mask");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK & NINLIL_DV_CAT_DSB3_31) != 0u,
    "B3d catalog bit 33 is part of the required mask");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK & NINLIL_DV_CAT_DSB3_34) != 0u,
    "B3e catalog bit 34 is part of the required mask");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK & NINLIL_DV_CAT_DSB3_33) != 0u,
    "B3f catalog bit 35 is part of the required mask");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK & NINLIL_DV_CAT_DSB3_32) != 0u,
    "B3g catalog bit 36 is part of the required mask");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK & NINLIL_DV_CAT_DSB3_42) != 0u,
    "B3j catalog bit 39 is part of the required mask");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_DSB3_30)
        != (uint64_t)(uint32_t)(NINLIL_DV_CAT_REQUIRED_MASK
            | NINLIL_DV_CAT_DSB3_30),
    "uint32 storage would truncate catalog presence bit 32");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_DSB3_31)
        != (uint64_t)(uint32_t)(NINLIL_DV_CAT_REQUIRED_MASK
            | NINLIL_DV_CAT_DSB3_31),
    "uint32 storage would truncate catalog presence bit 33");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_DSB3_34)
        != (uint64_t)(uint32_t)(NINLIL_DV_CAT_REQUIRED_MASK
            | NINLIL_DV_CAT_DSB3_34),
    "uint32 storage would truncate catalog presence bit 34");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_DSB3_33)
        != (uint64_t)(uint32_t)(NINLIL_DV_CAT_REQUIRED_MASK
            | NINLIL_DV_CAT_DSB3_33),
    "uint32 storage would truncate catalog presence bit 35");
_Static_assert(
    (NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_DSB3_32)
        != (uint64_t)(uint32_t)(NINLIL_DV_CAT_REQUIRED_MASK
            | NINLIL_DV_CAT_DSB3_32 | NINLIL_DV_CAT_DSB3_40),
    "uint32 storage would truncate catalog presence bits 36+");

static const char *full_catalog =
    "\"catalog\":{"
    "\"dsk1_positive_keys\":0,\"dsv1_body_exact\":0,\"dsv1_body_plus1\":0,"
    "\"dsh2_health_positive\":0,\"dsh2_fence_positive\":0,"
    "\"dso2_kind_positive\":0,\"dso2_canonical_positive\":0,"
    "\"dsw1_member_stream\":0,\"dsw1_header_positive\":0,"
    "\"dsk1_primary_id_positive\":0,\"dsv1_encode_decode_positive\":0,"
    "\"dsb1_subtype_01_positive\":0,\"dsb1_subtype_60_positive\":0,"
    "\"dsb1_subtype_62_positive\":0,\"dsb1_subtype_64_positive\":0,"
    "\"dsb1_subtype_7d_positive\":0,\"dsb1_total_positive\":0,"
    "\"dsb1_total_negative\":0,"
    "\"dsb2_subtype_10_positive\":0,\"dsb2_subtype_11_positive\":0,"
    "\"dsb2_subtype_20_positive\":0,\"dsb2_subtype_21_positive\":0,"
    "\"dsb2_subtype_22_positive\":0,\"dsb2_subtype_23_positive\":0,"
    "\"dsb2_subtype_24_positive\":0,\"dsb2_subtype_25_positive\":0,"
    "\"dsb2_total_positive\":0,\"dsb2_total_negative\":0,"
    "\"dsb3_subtype_26_positive\":0,\"dsb3_total_positive\":0,"
    "\"dsb3_total_negative\":0,\"dsb3_subtype_27_positive\":0,"
    "\"dsb3_subtype_30_positive\":0,\"dsb3_subtype_31_positive\":0,"
    "\"dsb3_subtype_34_positive\":0,\"dsb3_subtype_33_positive\":0,"
    "\"dsb3_subtype_32_positive\":0,\"dsb3_subtype_40_positive\":0,"
    "\"dsb3_subtype_41_positive\":0,\"dsb3_subtype_42_positive\":0}";

static const char *ws_def =
    "\"required_workspace_bytes_definition\":"
    "\"Additional caller-provided scratch beyond explicit inputs, outputs, "
    "and state/context objects.\"";

static const char *top_ok_prefix =
    "{\"version\":1,\"format\":\"" NINLIL_DV_FORMAT_REQUIRED "\","
    "\"scope\":\"" NINLIL_DV_SCOPE_REQUIRED "\",";

static int expect_fail(const char *text)
{
    ninlil_dv_file_t f;
    char err[128];
    int rc = ninlil_dv_parse_text(text, strlen(text), &f, err, sizeof(err));
    ninlil_dv_free(&f);
    return rc != 0;
}

static int expect_fail_doc(const char *mid)
{
    char buf[8192];
    (void)snprintf(buf, sizeof(buf), "%s%s,%s,\"vectors\":[%s]}",
        top_ok_prefix, ws_def, full_catalog, mid);
    return expect_fail(buf);
}

int main(void)
{
    uint8_t out[8];
    uint8_t big[4096];
    size_t n = 0u;
    char err[128];
    char overhex[8196];
    size_t i;

    REQUIRE(sizeof(ninlil_dv_vector_t) < 512u);
    (void)printf("sizeof(ninlil_dv_vector_t)=%zu\n", sizeof(ninlil_dv_vector_t));

    REQUIRE(ninlil_dv_hex_decode("zz", out, sizeof(out), &n, err, sizeof(err))
        != 0);
    REQUIRE(ninlil_dv_hex_decode("abc", out, sizeof(out), &n, err, sizeof(err))
        != 0);
    for (i = 0u; i < 8194u; ++i) {
        overhex[i] = 'a';
    }
    overhex[8194] = '\0';
    REQUIRE(ninlil_dv_hex_decode(overhex, big, 4096u, &n, err, sizeof(err))
        != 0);
    REQUIRE(ninlil_dv_hex_decode("==", out, sizeof(out), &n, err, sizeof(err))
        != 0);

    REQUIRE(expect_fail("{"));
    REQUIRE(expect_fail("{\"version\":1}"));
    /* missing mandatory vector field */
    REQUIRE(expect_fail_doc(
        "{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
        "\"expected_status\":\"OK\"}"));
    /* missing op-required identity_hex (health) */
    REQUIRE(expect_fail_doc(
        "{\"id\":\"DSH2_HEALTH_BAD_LEN\",\"suite\":\"DSH2\","
        "\"op\":\"health_source_id\",\"expected_status\":\"INVALID_ARGUMENT\","
        "\"required_workspace_bytes\":0,\"priority\":2,\"source_kind\":2}"));
    /* missing op-required digest_hex on OK sha256 */
    REQUIRE(expect_fail_doc(
        "{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
        "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
        "\"body_hex\":\"\"}"));
    /* missing key_length on manifest stream */
    REQUIRE(expect_fail_doc(
        "{\"id\":\"m\",\"suite\":\"DSW1\",\"op\":\"witness_manifest_stream\","
        "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
        "\"member_count\":1,\"chunk_count\":1,"
        "\"chunk_bodies_hex\":[\"00\"],"
        "\"digest_hex\":\"00\",\"digest2_hex\":\"00\"}"));

    /* unknown key / op / suite */
    REQUIRE(expect_fail_doc(
        "{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
        "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
        "\"body_hex\":\"\",\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\","
        "\"extra\":1}"));
    REQUIRE(expect_fail_doc(
        "{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"nope\","
        "\"expected_status\":\"OK\",\"required_workspace_bytes\":0}"));
    REQUIRE(expect_fail_doc(
        "{\"id\":\"a\",\"suite\":\"NOPE\",\"op\":\"sha256\","
        "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
        "\"body_hex\":\"\",\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}"));

    /* duplicate empty body_hex */
    REQUIRE(expect_fail_doc(
        "{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
        "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
        "\"body_hex\":\"\",\"body_hex\":\"\","
        "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}"));

    /* top-level: wrong version / format / scope / missing ws_def / wrong type */
    {
        char bad[8192];
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":2,\"format\":\"ninlil-domain-store-v1-d1b3c\","
            "\"scope\":\"D1-A framing + D1-B1 bodies (01/60/62/64/7d) + D1-B2 "
            "bodies (10/11/20-25 service+txn admission) + D1-B3a body "
            "(26 SCHEDULER_OWNER); not full D1 catalog\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"format\":\"wrong-format\","
            "\"scope\":\"D1-A framing + D1-B1 bodies (01/60/62/64/7d) + D1-B2 "
            "bodies (10/11/20-25 service+txn admission) + D1-B3a body "
            "(26 SCHEDULER_OWNER); not full D1 catalog\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"format\":\"ninlil-domain-store-v1-d1b3c\","
            "\"scope\":\"not-a-valid-scope\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"format\":\"ninlil-domain-store-v1-d1b3c\","
            "\"scope\":\"D1-A framing + D1-B1 bodies (01/60/62/64/7d) + D1-B2 "
            "bodies (10/11/20-25 service+txn admission) + D1-B3a body "
            "(26 SCHEDULER_OWNER); not full D1 catalog\","
            "%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":\"1\",\"format\":\"ninlil-domain-store-v1-d1b3c\","
            "\"scope\":\"D1-A framing + D1-B1 bodies (01/60/62/64/7d) + D1-B2 "
            "bodies (10/11/20-25 service+txn admission) + D1-B3a body "
            "(26 SCHEDULER_OWNER); not full D1 catalog\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
    }

    /* duplicate top-level / catalog */
    {
        char bad[8192];
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"version\":1,\"format\":\"ninlil-domain-store-v1-d1b3c\","
            "\"scope\":\"D1-A framing + D1-B1 bodies (01/60/62/64/7d) + D1-B2 "
            "bodies (10/11/20-25 service+txn admission) + D1-B3a body "
            "(26 SCHEDULER_OWNER); not full D1 catalog\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
    }

    /* valid minimal */
    {
        ninlil_dv_file_t f;
        char ok[8192];
        (void)snprintf(ok, sizeof(ok),
            "{\n"
            "  \"version\": 1,\n"
            "  \"format\": \"ninlil-domain-store-v1-d1b3j\",\n"
            "  \"scope\": \"%s\",\n"
            "  %s,\n"
            "  %s,\n"
            "  \"vectors\": [\n"
            "    {\n"
            "      \"id\": \"T1\",\n"
            "      \"suite\": \"DSK1\",\n"
            "      \"op\": \"sha256\",\n"
            "      \"expected_status\": \"OK\",\n"
            "      \"required_workspace_bytes\": 0,\n"
            "      \"body_hex\": \"\",\n"
            "      \"digest_hex\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n"
            "    }\n"
            "  ]\n"
            "}\n",
            NINLIL_DV_SCOPE_REQUIRED, ws_def, full_catalog);
        REQUIRE(ninlil_dv_parse_text(ok, strlen(ok), &f, err, sizeof(err))
            == 0);
        REQUIRE(f.vector_count == 1u);
        REQUIRE(f.catalog_bits == NINLIL_DV_CAT_REQUIRED_MASK);
        REQUIRE((f.catalog_bits & NINLIL_DV_CAT_REQUIRED_MASK)
            == NINLIL_DV_CAT_REQUIRED_MASK);
        ninlil_dv_free(&f);
    }

    /*
     * Catalog presence scalability: high bits and required-mask checks must
     * not truncate. Bits 34/35/36 are real/required (subtypes 34/33/32);
     * synthetic future-missing/truncation arithmetic uses unused bit40.
     * Bit63 proves uint64 storage width. No new JSON catalog keys for
     * synthetic bits.
     */
    {
        uint64_t present;
        uint64_t future_required;
        uint32_t present32;
        uint32_t future32;

        present = NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_TEST_BIT40
            | NINLIL_DV_CAT_TEST_BIT63;
        REQUIRE((present & NINLIL_DV_CAT_REQUIRED_MASK)
            == NINLIL_DV_CAT_REQUIRED_MASK);
        REQUIRE((present & NINLIL_DV_CAT_DSB3_31) != 0u);
        REQUIRE((present & NINLIL_DV_CAT_DSB3_34) != 0u);
        REQUIRE((present & NINLIL_DV_CAT_DSB3_33) != 0u);
        REQUIRE((present & NINLIL_DV_CAT_TEST_BIT40) != 0u);
        REQUIRE((present & NINLIL_DV_CAT_TEST_BIT63) != 0u);
        /* Same values stored in catalog_bits retain high bits. */
        {
            ninlil_dv_file_t f;
            (void)memset(&f, 0, sizeof(f));
            f.catalog_bits = present;
            REQUIRE(f.catalog_bits == present);
            REQUIRE((f.catalog_bits & NINLIL_DV_CAT_REQUIRED_MASK)
                == NINLIL_DV_CAT_REQUIRED_MASK);
            REQUIRE((f.catalog_bits & NINLIL_DV_CAT_DSB3_31)
                == NINLIL_DV_CAT_DSB3_31);
            REQUIRE((f.catalog_bits & NINLIL_DV_CAT_DSB3_34)
                == NINLIL_DV_CAT_DSB3_34);
            REQUIRE((f.catalog_bits & NINLIL_DV_CAT_TEST_BIT63)
                == NINLIL_DV_CAT_TEST_BIT63);
        }

        /*
         * Future unused bit40 required: omitting it fails completeness;
         * uint32 truncation would incorrectly treat the future bit as absent
         * from both sides and spuriously pass.
         */
        future_required =
            NINLIL_DV_CAT_REQUIRED_MASK | NINLIL_DV_CAT_TEST_BIT40;
        present = NINLIL_DV_CAT_REQUIRED_MASK;
        REQUIRE((present & future_required) != future_required);
        present32 = (uint32_t)present;
        future32 = (uint32_t)future_required;
        REQUIRE((present32 & future32) == future32);
        present |= NINLIL_DV_CAT_TEST_BIT40;
        REQUIRE((present & future_required) == future_required);
    }

    (void)printf("parser negative tests ok\n");
    return 0;
}
