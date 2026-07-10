#include "vector_reference_schema.h"

#include <stdio.h>
#include <string.h>

static int parse_inventory(const char *definitions, ninlil_vector_inventory_t *out_inventory)
{
    char error[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            definitions,
            out_inventory,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "synthetic inventory parse failed: %s\n", error);
        return 1;
    }
    return 0;
}

static int make_document(
    const char *mandatory_evidence,
    const char *pull_request_bullet,
    char *out,
    size_t out_size)
{
    int written = snprintf(
        out,
        out_size,
        "### M1a mandatory suites\n"
        "\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| `REQ-1` | %s |\n"
        "\n"
        "### Pull request gate\n"
        "\n"
        "- %s\n"
        "\n"
        "### Nightly gate\n",
        mandatory_evidence,
        pull_request_bullet);

    if (written < 0 || (size_t)written >= out_size) {
        fprintf(stderr, "synthetic reference document truncated\n");
        return 1;
    }
    return 0;
}

static int expect_check_fail(
    const char *definitions,
    const char *content,
    const char *expected_error)
{
    ninlil_vector_inventory_t inventory;
    ninlil_vector_reference_result_t result;
    char error[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (parse_inventory(definitions, &inventory) != 0) {
        return 1;
    }
    if (ninlil_vector_reference_check_content(
            content,
            &inventory,
            &result,
            error,
            sizeof(error))
        == 0) {
        fprintf(stderr, "expected vector reference failure\n");
        return 1;
    }
    if (strstr(error, expected_error) == NULL) {
        fprintf(
            stderr,
            "expected error containing '%s', got '%s'\n",
            expected_error,
            error);
        return 1;
    }
    return 0;
}

static int test_reference_forms(void)
{
    const char *definitions =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_INDIVIDUAL` | x |\n"
        "| `B1_SLASH` | x |\n"
        "| `N1_START` | x |\n"
        "| `N2_MIDDLE` | x |\n"
        "| `N3_END` | x |\n"
        "| `O2A_ALPHA` | x |\n"
        "| `O2B_ALPHA` | x |\n"
        "| `O2C_ALPHA` | x |\n";
    char content[2048];
    ninlil_vector_inventory_t inventory;
    ninlil_vector_reference_result_t result;
    char error[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (parse_inventory(definitions, &inventory) != 0
        || make_document(
               "A1/B1_SLASH、N1〜N3、O2A〜O2C",
               "A1,B1、C11/C++17、NINLIL_OK、UINT64_MAX、NIN-FND-TEST-001、100 seeds",
               content,
               sizeof(content))
            != 0) {
        return 1;
    }
    if (ninlil_vector_reference_check_content(
            content,
            &inventory,
            &result,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "reference forms failed: %s\n", error);
        return 1;
    }
    if (result.definition_count != 8u || result.mandatory_unique != 8u
        || result.pull_request_unique != 2u || result.union_unique != 8u
        || result.mandatory_occurrences != 8u || result.pull_request_occurrences != 2u
        || result.mandatory_rows != 1u || result.pull_request_bullets != 1u
        || result.excluded_tokens != 3u) {
        fprintf(stderr, "unexpected synthetic coverage counts\n");
        return 1;
    }
    return 0;
}

static int test_undefined_individual(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    char content[1024];

    if (make_document("A1/Z9", "A1", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(definitions, content, "undefined vector reference Z9 at line 5");
}

static int test_undefined_full_id(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_DEFINED` | x |\n";
    char content[1024];

    if (make_document("A1_UNKNOWN", "A1", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(
        definitions,
        content,
        "undefined vector reference A1_UNKNOWN at line 5");
}

static int test_malformed_range(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    char content[1024];

    if (make_document("A1〜", "A1", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(definitions, content, "malformed vector range beginning A1〜 at line 5");
}

static int test_cross_prefix_range(void)
{
    const char *definitions =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_START` | x |\n"
        "| `B2_END` | x |\n";
    char content[1024];

    if (make_document("A1〜B2", "A1/B2", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(definitions, content, "cross-prefix vector range A1〜B2 at line 5");
}

static int test_descending_range(void)
{
    const char *definitions =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_START` | x |\n"
        "| `A2_END` | x |\n";
    char content[1024];

    if (make_document("A2〜A1", "A1/A2", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(definitions, content, "descending vector range A2〜A1 at line 5");
}

static int test_missing_intermediate(void)
{
    const char *definitions =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_START` | x |\n"
        "| `A3_END` | x |\n";
    char content[1024];

    if (make_document("A1〜A3", "A1/A3", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(
        definitions,
        content,
        "missing intermediate vector reference A2 for range A1〜A3 at line 5");
}

static int test_undefined_range_endpoint(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_START` | x |\n";
    char content[1024];

    if (make_document("A1〜A2", "A1", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(
        definitions,
        content,
        "undefined vector range endpoint A2 for A1〜A2 at line 5");
}

static int test_full_id_range_endpoint(void)
{
    const char *definitions =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_START` | x |\n"
        "| `A2_END` | x |\n";
    char content[1024];

    if (make_document("A1_START〜A2", "A1/A2", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(
        definitions,
        content,
        "full definition ID is not allowed as vector range endpoint A1_START〜A2 at line 5");
}

static int test_orphan_definition(void)
{
    const char *definitions =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_COVERED` | x |\n"
        "| `B1_ORPHAN` | x |\n";
    char content[1024];

    if (make_document("A1", "A1", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(definitions, content, "orphan vector definition B1_ORPHAN at line 4");
}

static int test_duplicate_reference_key(void)
{
    const char *definitions =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_FIRST` | x |\n"
        "| `A1_SECOND` | x |\n";
    char content[1024];

    if (make_document("A1", "A1", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(definitions, content, "duplicate vector reference key A1");
}

static int test_missing_and_wrong_headings(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    const char *missing_pull_request =
        "### M1a mandatory suites\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| x | A1 |\n"
        "### Nightly gate\n";
    const char *wrong_level_and_substring =
        "### M1a mandatory suites extra\n"
        "#### Pull request gate\n"
        "- A1\n";

    if (expect_check_fail(
            definitions,
            missing_pull_request,
            "missing exact heading ### Pull request gate")
        != 0) {
        return 1;
    }
    return expect_check_fail(
        definitions,
        wrong_level_and_substring,
        "missing exact heading ### M1a mandatory suites");
}

static int test_duplicate_heading(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    const char *content =
        "### M1a mandatory suites\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| x | A1 |\n"
        "### M1a mandatory suites\n"
        "### Pull request gate\n"
        "- A1\n";

    return expect_check_fail(
        definitions,
        content,
        "duplicate exact heading ### M1a mandatory suites at lines 1 and 5");
}

static int test_duplicate_mandatory_table(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    const char *content =
        "### M1a mandatory suites\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| x | A1 |\n"
        "\n"
        "prose\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| y | A1 |\n"
        "### Pull request gate\n"
        "- A1\n";

    return expect_check_fail(
        definitions,
        content,
        "duplicate mandatory Test evidence headers at lines 2 and 7");
}

static int test_next_section_not_borrowed(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    const char *content =
        "### M1a mandatory suites\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| x | A1 |\n"
        "### Other section\n"
        "- Z9\n"
        "### Pull request gate\n"
        "- A1\n"
        "### Nightly gate\n"
        "- Z8\n";
    ninlil_vector_inventory_t inventory;
    ninlil_vector_reference_result_t result;
    char error[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (parse_inventory(definitions, &inventory) != 0) {
        return 1;
    }
    if (ninlil_vector_reference_check_content(
            content,
            &inventory,
            &result,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "next-section content was borrowed: %s\n", error);
        return 1;
    }
    return 0;
}

static int test_mandatory_table_not_borrowed(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    const char *content =
        "### M1a mandatory suites\n"
        "### Other section\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| x | A1 |\n"
        "### Pull request gate\n"
        "- A1\n";

    return expect_check_fail(
        definitions,
        content,
        "missing mandatory Test evidence table in section at line 1");
}

static int test_overlong_line(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    char content[NINLIL_VECTOR_REFERENCE_MAX_LINE_LEN + 128u];
    size_t offset = 0u;
    size_t index;

    memcpy(content, "### M1a mandatory suites\n", sizeof("### M1a mandatory suites\n") - 1u);
    offset = sizeof("### M1a mandatory suites\n") - 1u;
    for (index = 0u; index < NINLIL_VECTOR_REFERENCE_MAX_LINE_LEN; ++index) {
        content[offset++] = 'X';
    }
    content[offset++] = '\n';
    content[offset] = '\0';

    return expect_check_fail(definitions, content, "vector reference line too long at line 2");
}

static int test_overlong_token(void)
{
    const char *definitions =
        "| Vector | Setup |\n| --- | --- |\n| `A1_ONLY` | x |\n";
    char token[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN + 1u];
    char content[1024];
    size_t index;

    token[0] = 'A';
    token[1] = '1';
    for (index = 2u; index < NINLIL_VECTOR_INVENTORY_MAX_ID_LEN; ++index) {
        token[index] = 'X';
    }
    token[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN] = '\0';
    if (make_document(token, "A1", content, sizeof(content)) != 0) {
        return 1;
    }
    return expect_check_fail(definitions, content, "overlong reference token at line 5");
}

static int test_repository_inventory_validation(void)
{
    const char *content =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_ONLY` | x |\n"
        "\n"
        "### M1a mandatory suites\n"
        "| Requirement set | Test evidence |\n"
        "| --- | --- |\n"
        "| x | A1 |\n"
        "### Pull request gate\n"
        "- A1\n";
    ninlil_vector_reference_result_t result;
    char error[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (ninlil_vector_reference_check_repository_content(
            content,
            &result,
            error,
            sizeof(error))
        == 0) {
        fprintf(stderr, "expected repository inventory validation failure\n");
        return 1;
    }
    if (strstr(
            error,
            "vector inventory validation error: vector definition count mismatch: expected 282, got 1")
        == NULL) {
        fprintf(stderr, "unexpected repository inventory validation error: %s\n", error);
        return 1;
    }
    return 0;
}

static int test_real_repository(const char *repo_root)
{
    ninlil_vector_reference_result_t result;

    if (ninlil_vector_reference_run_repository_check(repo_root, &result, stderr) != 0) {
        return 1;
    }
    if (result.definition_count != NINLIL_VECTOR_INVENTORY_EXPECTED_DEFINITION_COUNT
        || result.union_unique != NINLIL_VECTOR_INVENTORY_EXPECTED_DEFINITION_COUNT) {
        fprintf(
            stderr,
            "real repository coverage mismatch: definitions=%zu union=%zu\n",
            result.definition_count,
            result.union_unique);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <repo_root>\n", argv[0]);
        return 2;
    }
    if (test_reference_forms() != 0 || test_undefined_individual() != 0
        || test_undefined_full_id() != 0
        || test_malformed_range() != 0 || test_cross_prefix_range() != 0
        || test_descending_range() != 0 || test_missing_intermediate() != 0
        || test_undefined_range_endpoint() != 0 || test_full_id_range_endpoint() != 0
        || test_orphan_definition() != 0
        || test_duplicate_reference_key() != 0
        || test_missing_and_wrong_headings() != 0 || test_duplicate_heading() != 0
        || test_duplicate_mandatory_table() != 0
        || test_next_section_not_borrowed() != 0
        || test_mandatory_table_not_borrowed() != 0 || test_overlong_line() != 0
        || test_overlong_token() != 0 || test_repository_inventory_validation() != 0
        || test_real_repository(argv[1]) != 0) {
        return 1;
    }
    return 0;
}
