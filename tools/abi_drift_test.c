#include "abi_drift_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_compare_fail(const char *doc, const char *header)
{
    ninlil_abi_catalog_t *doc_catalog;
    ninlil_abi_catalog_t *header_catalog;
    char error[NINLIL_ABI_DRIFT_MAX_ERROR];
    int result;

    doc_catalog = (ninlil_abi_catalog_t *)calloc(1, sizeof(*doc_catalog));
    header_catalog = (ninlil_abi_catalog_t *)calloc(1, sizeof(*header_catalog));
    if (doc_catalog == NULL || header_catalog == NULL) {
        free(doc_catalog);
        free(header_catalog);
        return 1;
    }
    if (ninlil_abi_parse_translation_unit(doc, "doc", doc_catalog, error, sizeof(error)) != 0) {
        fprintf(stderr, "unexpected doc parse failure: %s\n", error);
        result = 1;
        goto cleanup;
    }
    if (ninlil_abi_parse_translation_unit(header, "header", header_catalog, error, sizeof(error)) != 0) {
        fprintf(stderr, "unexpected header parse failure: %s\n", error);
        result = 1;
        goto cleanup;
    }
    if (ninlil_abi_compare_catalogs(doc_catalog, header_catalog, stderr) == 0) {
        fprintf(stderr, "expected compare failure\n");
        result = 1;
        goto cleanup;
    }
    result = 0;

cleanup:
    free(doc_catalog);
    free(header_catalog);
    return result;
}

static int expect_parse_fail(const char *source)
{
    ninlil_abi_catalog_t *catalog;
    char error[NINLIL_ABI_DRIFT_MAX_ERROR];
    int result;

    catalog = (ninlil_abi_catalog_t *)calloc(1, sizeof(*catalog));
    if (catalog == NULL) {
        return 1;
    }
    if (ninlil_abi_parse_translation_unit(source, "fixture", catalog, error, sizeof(error)) == 0) {
        fprintf(stderr, "expected parse failure\n");
        result = 1;
    } else {
        result = 0;
    }
    free(catalog);
    return result;
}

static int test_negative_field_type(void)
{
    const char *doc =
        "typedef struct ninlil_sample {\n"
        "    uint32_t value;\n"
        "} ninlil_sample_t;\n";
    const char *header =
        "typedef struct ninlil_sample {\n"
        "    uint64_t value;\n"
        "} ninlil_sample_t;\n";
    return expect_compare_fail(doc, header);
}

static int test_negative_function_signature(void)
{
    const char *doc =
        "ninlil_status_t ninlil_runtime_destroy(ninlil_runtime_t *runtime);\n";
    const char *header =
        "ninlil_status_t ninlil_runtime_destroy(const ninlil_runtime_t *runtime);\n";
    return expect_compare_fail(doc, header);
}

static int test_negative_macro_value(void)
{
    const char *doc = "#define NINLIL_OK ((ninlil_status_t)0)\n";
    const char *header = "#define NINLIL_OK ((ninlil_status_t)1)\n";
    return expect_compare_fail(doc, header);
}

static int test_negative_missing_declaration(void)
{
    const char *doc =
        "#define NINLIL_OK ((ninlil_status_t)0)\n"
        "#define NINLIL_E_INVALID_ARGUMENT ((ninlil_status_t)1)\n";
    const char *header = "#define NINLIL_OK ((ninlil_status_t)0)\n";
    return expect_compare_fail(doc, header);
}

static int test_negative_unparseable_declaration(void)
{
    const char *source = "typedef struct bad { invalid field syntax here } bad_t;\n";
    return expect_parse_fail(source);
}

static int test_negative_manifest_inventory(const char *work_dir)
{
    ninlil_abi_catalog_t *header;
    ninlil_abi_manifest_inventory_t manifest;
    char error[NINLIL_ABI_DRIFT_MAX_ERROR];
    const char *header_source =
        "#define NINLIL_OK ((ninlil_status_t)0)\n"
        "#define NINLIL_E_INVALID_ARGUMENT ((ninlil_status_t)1)\n"
        "typedef struct ninlil_sample {\n"
        "    NINLIL_STRUCT_HEADER;\n"
        "    uint32_t value;\n"
        "} ninlil_sample_t;\n";
    const char *constants_inc = "    MANIFEST_CONST(NINLIL_OK)\n";
    const char *structs_inc =
        "    MANIFEST_STRUCT_BEGIN(ninlil_sample_t)\n"
        "    MANIFEST_FIELD(ninlil_sample_t, abi_version)\n"
        "    MANIFEST_STRUCT_END(ninlil_sample_t)\n";
    char constants_path[512];
    char structs_path[512];
    FILE *out;

    header = (ninlil_abi_catalog_t *)calloc(1, sizeof(*header));
    if (header == NULL) {
        return 1;
    }
    if (ninlil_abi_parse_translation_unit(
            header_source,
            "header",
            header,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "header parse failed: %s\n", error);
        free(header);
        return 1;
    }

    snprintf(constants_path, sizeof(constants_path), "%s/abi_drift_neg_constants.inc", work_dir);
    snprintf(structs_path, sizeof(structs_path), "%s/abi_drift_neg_structs.inc", work_dir);

    out = fopen(constants_path, "wb");
    if (out == NULL) {
        return 1;
    }
    fputs(constants_inc, out);
    fclose(out);

    out = fopen(structs_path, "wb");
    if (out == NULL) {
        return 1;
    }
    fputs(structs_inc, out);
    fclose(out);

    if (ninlil_abi_parse_manifest_inventory(
            constants_path,
            structs_path,
            &manifest,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "manifest parse failed: %s\n", error);
        return 1;
    }
    if (ninlil_abi_compare_header_manifest(header, &manifest, stderr) == 0) {
        fprintf(stderr, "expected manifest compare failure\n");
        free(header);
        return 1;
    }
    free(header);
    return 0;
}

static int test_repository_check(const char *repo_root)
{
    ninlil_abi_catalog_counts_t counts;

    if (ninlil_abi_run_repository_check(repo_root, &counts, stderr) != 0) {
        fprintf(stderr, "repository abi drift check failed\n");
        return 1;
    }
    if (counts.manifest_constants != NINLIL_ABI_MANIFEST_EXPECTED_CONSTANTS
        || counts.manifest_structs != NINLIL_ABI_MANIFEST_EXPECTED_STRUCTS
        || counts.manifest_fields != NINLIL_ABI_MANIFEST_EXPECTED_FIELDS) {
        fprintf(
            stderr,
            "unexpected manifest counts: %zu %zu %zu\n",
            counts.manifest_constants,
            counts.manifest_structs,
            counts.manifest_fields);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <repo_root> <work_dir>\n", argv[0]);
        return 2;
    }

    const char *repo_root = argv[1];
    const char *work_dir = argv[2];

    if (test_negative_field_type() != 0) {
        return 1;
    }
    if (test_negative_function_signature() != 0) {
        return 1;
    }
    if (test_negative_macro_value() != 0) {
        return 1;
    }
    if (test_negative_missing_declaration() != 0) {
        return 1;
    }
    if (test_negative_unparseable_declaration() != 0) {
        return 1;
    }
    if (test_negative_manifest_inventory(work_dir) != 0) {
        return 1;
    }
    if (test_repository_check(repo_root) != 0) {
        return 1;
    }
    return 0;
}
