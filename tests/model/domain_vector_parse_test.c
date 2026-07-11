#include "domain_vector_parse.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "%s:%d fail %s\n", __FILE__, __LINE__, #c);  \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const char *full_catalog =
    "\"catalog\":{"
    "\"dsk1_positive_keys\":0,\"dsv1_body_exact\":0,\"dsv1_body_plus1\":0,"
    "\"dsh2_health_positive\":0,\"dsh2_fence_positive\":0,"
    "\"dso2_kind_positive\":0,\"dso2_canonical_positive\":0,"
    "\"dsw1_member_stream\":0,\"dsw1_header_positive\":0,"
    "\"dsk1_primary_id_positive\":0,\"dsv1_encode_decode_positive\":0}";

static const char *ws_def =
    "\"required_workspace_bytes_definition\":"
    "\"Additional caller-provided scratch beyond explicit inputs, outputs, "
    "and state/context objects.\"";

static const char *top_ok_prefix =
    "{\"version\":1,\"format\":\"ninlil-domain-store-v1-d1a\","
    "\"scope\":\"D1-A framing/primitive slice (not full D1 body catalog)\",";

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
    char buf[4096];
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
        char bad[2048];
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":2,\"format\":\"ninlil-domain-store-v1-d1a\","
            "\"scope\":\"D1-A framing/primitive slice (not full D1 body catalog)\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"format\":\"wrong-format\","
            "\"scope\":\"D1-A framing/primitive slice (not full D1 body catalog)\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"format\":\"ninlil-domain-store-v1-d1a\","
            "\"scope\":\"not-a-valid-scope\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"format\":\"ninlil-domain-store-v1-d1a\","
            "\"scope\":\"D1-A framing/primitive slice (not full D1 body catalog)\","
            "%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            full_catalog);
        REQUIRE(expect_fail(bad));
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":\"1\",\"format\":\"ninlil-domain-store-v1-d1a\","
            "\"scope\":\"D1-A framing/primitive slice (not full D1 body catalog)\","
            "%s,%s,\"vectors\":[{\"id\":\"a\",\"suite\":\"DSK1\",\"op\":\"sha256\","
            "\"expected_status\":\"OK\",\"required_workspace_bytes\":0,"
            "\"body_hex\":\"\","
            "\"digest_hex\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}]}",
            ws_def, full_catalog);
        REQUIRE(expect_fail(bad));
    }

    /* duplicate top-level / catalog */
    {
        char bad[2048];
        (void)snprintf(bad, sizeof(bad),
            "{\"version\":1,\"version\":1,\"format\":\"ninlil-domain-store-v1-d1a\","
            "\"scope\":\"D1-A framing/primitive slice (not full D1 body catalog)\","
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
        char ok[2048];
        (void)snprintf(ok, sizeof(ok),
            "{\n"
            "  \"version\": 1,\n"
            "  \"format\": \"ninlil-domain-store-v1-d1a\",\n"
            "  \"scope\": \"D1-A framing/primitive slice (not full D1 body catalog)\",\n"
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
            ws_def, full_catalog);
        REQUIRE(ninlil_dv_parse_text(ok, strlen(ok), &f, err, sizeof(err))
            == 0);
        REQUIRE(f.vector_count == 1u);
        ninlil_dv_free(&f);
    }

    (void)printf("parser negative tests ok\n");
    return 0;
}
