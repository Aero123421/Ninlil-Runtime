#include "vector_inventory_schema.h"

#include <stdio.h>
#include <string.h>

static int expect_parse_fail(const char *content, const char *expected_error)
{
    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        == 0) {
        fprintf(stderr, "expected vector inventory parse failure\n");
        return 1;
    }
    if (expected_error != NULL && strstr(error, expected_error) == NULL) {
        fprintf(
            stderr,
            "expected parse error containing '%s', got '%s'\n",
            expected_error,
            error);
        return 1;
    }
    return 0;
}

static int expect_parse_ok_count(const char *content, size_t expected_count)
{
    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "unexpected vector inventory parse failure: %s\n", error);
        return 1;
    }
    if (inventory.count != expected_count) {
        fprintf(
            stderr,
            "expected %zu definitions, got %zu\n",
            expected_count,
            inventory.count);
        return 1;
    }
    return 0;
}

static int expect_kind_counts(
    const ninlil_vector_inventory_t *inventory,
    size_t expected_table,
    size_t expected_explicit,
    size_t expected_bullet,
    size_t expected_canonical)
{
    ninlil_vector_inventory_kind_counts_t counts;

    ninlil_vector_inventory_count_kinds(inventory, &counts);

    if (counts.total != inventory->count || counts.table != expected_table
        || counts.explicit != expected_explicit || counts.bullet != expected_bullet
        || counts.canonical != expected_canonical) {
        fprintf(
            stderr,
            "kind mismatch: expected table=%zu explicit=%zu bullet=%zu canonical=%zu, "
            "got table=%zu explicit=%zu bullet=%zu canonical=%zu\n",
            expected_table,
            expected_explicit,
            expected_bullet,
            expected_canonical,
            counts.table,
            counts.explicit,
            counts.bullet,
            counts.canonical);
        return 1;
    }
    return 0;
}

static int test_table_definition(void)
{
    const char *content =
        "| Vector | Setup | Required result |\n"
        "| --- | --- | --- |\n"
        "| `NS1_MIN` | short | valid |\n";

    return expect_parse_ok_count(content, 1u);
}

static int test_explicit_definition(void)
{
    const char *content =
        "Vector `FULL1_M1A_REQUESTS_FULL`はfixtureです。\n"
        "Vector `D1_DEFER_TIMEOUT_RECONCILE`:\n";

    return expect_parse_ok_count(content, 2u);
}

static int test_prose_reference_ignored(void)
{
    const char *content =
        "| Vector | Setup | Required result |\n"
        "| --- | --- | --- |\n"
        "| `NS1_MIN` | short | valid |\n"
        "\n"
        "The Vector `NS2_MAX` reference must not count.\n"
        "Orientation negative vectorsはO1から次を1つずつ変更します。\n";

    return expect_parse_ok_count(content, 1u);
}

static int test_bullet_definition(void)
{
    const char *content =
        "- `TXID1_FOURTH_VALID`: draw 1=all-zero。\n"
        "- not a bullet definition because colon is missing `TXID2_FOUR_INVALID`\n";

    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "unexpected vector inventory parse failure: %s\n", error);
        return 1;
    }
    if (inventory.count != 1u) {
        fprintf(stderr, "expected 1 bullet definition, got %zu\n", inventory.count);
        return 1;
    }
    if (inventory.definitions[0].kind != NINLIL_VECTOR_DEFINITION_BULLET) {
        fprintf(stderr, "expected bullet definition kind\n");
        return 1;
    }
    if (strcmp(inventory.definitions[0].id, "TXID1_FOURTH_VALID") != 0) {
        fprintf(stderr, "unexpected bullet definition ID\n");
        return 1;
    }
    return 0;
}

static int test_canonical_heading_definition(void)
{
    const char *content =
        "### Vector C1: Reliable Command\n"
        "### Vector E1: Durable Event\n"
        "### Vector E2〜E4: Event intrinsic dedup/conflict\n";

    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "unexpected vector inventory parse failure: %s\n", error);
        return 1;
    }
    if (inventory.count != 2u) {
        fprintf(stderr, "expected 2 canonical heading definitions, got %zu\n", inventory.count);
        return 1;
    }
    if (inventory.definitions[0].kind != NINLIL_VECTOR_DEFINITION_CANONICAL_HEADING
        || strcmp(inventory.definitions[0].id, "C1") != 0) {
        fprintf(stderr, "unexpected first canonical heading definition\n");
        return 1;
    }
    if (inventory.definitions[1].kind != NINLIL_VECTOR_DEFINITION_CANONICAL_HEADING
        || strcmp(inventory.definitions[1].id, "E1") != 0) {
        fprintf(stderr, "unexpected second canonical heading definition\n");
        return 1;
    }
    return 0;
}

static int test_alias_reference_ignored(void)
{
    const char *content =
        "| Vector | Setup | Required result |\n"
        "| --- | --- | --- |\n"
        "| `NS1_MIN` | short | valid |\n"
        "\n"
        "`NS3`、ASCII `A`。\n"
        "`DR3`〜`DR8`ではdestroy return直後。\n"
        "`RL2`と`RL3`は同時に複数違反を作らず。\n"
        "`QT1`〜`QT4`はtest alias。\n"
        "Prior count=`UINT64_MAX`ではcallback/token発行0。\n"
        "Requirement `NIN-FND-ABI-001`。\n"
        "macro `NINLIL_OK`。\n";

    return expect_parse_ok_count(content, 1u);
}

static int test_duplicate_definition(void)
{
    const char *content =
        "| Vector | Setup | Required result |\n"
        "| --- | --- | --- |\n"
        "| `NS1_MIN` | short | valid |\n"
        "Vector `NS1_MIN`はduplicateです。\n";

    return expect_parse_fail(content, "duplicate vector definition NS1_MIN");
}

static int test_mixed_newline_duplicate_line_numbers(void)
{
    const char *content =
        "preamble\r"
        "| Vector | Setup |\n"
        "| --- | --- |\r\n"
        "| `FOO1` | first |\r"
        "reference only\n"
        "Vector `FOO1`はduplicateです。\r\n";
    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        == 0) {
        fprintf(stderr, "expected mixed-newline duplicate parse failure\n");
        return 1;
    }
    if (strstr(error, "duplicate vector definition FOO1 at lines 4 and 6") == NULL) {
        fprintf(
            stderr,
            "expected duplicate line numbers 4 and 6, got '%s'\n",
            error);
        return 1;
    }
    return 0;
}

static int test_malformed_id(void)
{
    const char *content =
        "| Vector | Setup | Required result |\n"
        "| --- | --- | --- |\n"
        "| `bad_id` | short | invalid |\n";

    return expect_parse_fail(content, "malformed vector ID");
}

static int test_ascii_only_id(void)
{
    const char *content =
        "Vector `Ä1_NON_ASCII`はinvalidです。\n"
        "- `LOWER1_bad`: invalid。\n";

    return expect_parse_fail(content, "malformed vector ID at line 1");
}

static int test_malformed_vector_table_row(void)
{
    const char *content =
        "| Vector | Setup | Required result |\n"
        "| --- | --- | --- |\n"
        "| NS1_MIN | missing backticks | invalid |\n";

    return expect_parse_fail(content, "malformed vector table row");
}

static int test_vector_table_header_blank(void)
{
    const char *content =
        "| Vector | Setup |\n"
        "\n"
        "Vector `A1_AFTER`はreferenceです。\n";

    return expect_parse_fail(
        content,
        "incomplete Vector table at header line 1: expected separator row before blank line 2");
}

static int test_vector_table_header_non_table(void)
{
    const char *content =
        "preamble\n"
        "| Vector | Setup |\n"
        "Vector `A1_AFTER`はdefinitionです。\n";

    return expect_parse_fail(
        content,
        "incomplete Vector table at header line 2: expected separator row before boundary line 3");
}

static int test_vector_table_separator_without_data(void)
{
    const char *blank_content =
        "| Vector | Setup |\r\n"
        "| --- | --- |\r"
        "\r";
    const char *eof_content =
        "| Vector | Setup |\n"
        "| --- | --- |";

    if (expect_parse_fail(
            blank_content,
            "incomplete Vector table at header line 1: expected at least one data row before blank line 3")
        != 0) {
        return 1;
    }
    return expect_parse_fail(
        eof_content,
        "incomplete Vector table at header line 1: expected at least one data row before EOF");
}

static int test_vector_table_header_eof(void)
{
    const char *content = "| Vector | Setup |";

    return expect_parse_fail(
        content,
        "incomplete Vector table at header line 1: expected separator row before EOF");
}

static int test_vector_table_boundary_reprocessed(void)
{
    const char *content =
        "| Vector | Setup |\n"
        "| --- | --- |\n"
        "| `A1_TABLE` | valid |\n"
        "Vector `A2_EXPLICIT`は直後のdefinitionです。\n";
    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "unexpected table boundary parse failure: %s\n", error);
        return 1;
    }
    if (inventory.count != 2u || strcmp(inventory.definitions[0].id, "A1_TABLE") != 0
        || inventory.definitions[0].kind != NINLIL_VECTOR_DEFINITION_TABLE
        || strcmp(inventory.definitions[1].id, "A2_EXPLICIT") != 0
        || inventory.definitions[1].kind != NINLIL_VECTOR_DEFINITION_EXPLICIT) {
        fprintf(stderr, "completed Vector table boundary was not reprocessed\n");
        return 1;
    }
    return 0;
}

static int test_unterminated_backtick(void)
{
    const char *content = "Vector `NS1_MIN\n";

    return expect_parse_fail(content, "unterminated backtick");
}

static int test_overlong_id_line(void)
{
    char content[NINLIL_VECTOR_INVENTORY_MAX_LINE_LEN + 32u];
    size_t i;

    memcpy(content, "Vector `", 8u);
    for (i = 8u; i < 8u + (size_t)NINLIL_VECTOR_INVENTORY_MAX_ID_LEN; ++i) {
        content[i] = 'A';
    }
    content[i++] = '`';
    content[i++] = '\n';
    content[i] = '\0';

    return expect_parse_fail(content, "vector ID too long");
}

static int test_overlong_table_id(void)
{
    char content[NINLIL_VECTOR_INVENTORY_MAX_LINE_LEN];
    size_t offset = 0u;
    size_t i;

    offset += (size_t)snprintf(
        content + offset,
        sizeof(content) - offset,
        "| Vector | Setup |\n| --- | --- |\n| `");
    for (i = 0u; i < (size_t)NINLIL_VECTOR_INVENTORY_MAX_ID_LEN; ++i) {
        content[offset++] = 'A';
    }
    memcpy(content + offset, "` | invalid |\n", sizeof("` | invalid |\n"));

    return expect_parse_fail(content, "vector ID too long at line 3");
}

static int test_overlong_line(void)
{
    char content[NINLIL_VECTOR_INVENTORY_MAX_LINE_LEN + 8u];
    size_t i;

    for (i = 0u; i < sizeof(content) - 2u; ++i) {
        content[i] = 'x';
    }
    content[i++] = '\n';
    content[i] = '\0';

    return expect_parse_fail(content, "line too long");
}

static int test_unrelated_table_not_borrowed(void)
{
    const char *content =
        "| Vector | Setup | Required result |\n"
        "| --- | --- | --- |\n"
        "| `NS1_MIN` | short | valid |\n"
        "### Unrelated table boundary\n"
        "| Foo | Bar |\n"
        "| --- | --- |\n"
        "| `NS2_MAX` | must not count |\n";

    return expect_parse_ok_count(content, 1u);
}

static int test_exact_canonical_heading(void)
{
    const char *content =
        "### Vector C1: exact\n"
        "#### Vector E1: wrong heading level\n"
        "### Vector E1 - missing colon\n"
        "### Vector E2〜E4: range reference\n"
        "### Vector E1 : whitespace before colon\n";
    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "unexpected canonical heading parse failure: %s\n", error);
        return 1;
    }
    if (inventory.count != 1u || strcmp(inventory.definitions[0].id, "C1") != 0
        || inventory.definitions[0].kind != NINLIL_VECTOR_DEFINITION_CANONICAL_HEADING) {
        fprintf(stderr, "canonical heading syntax was not matched exactly\n");
        return 1;
    }
    return 0;
}

static int test_deterministic_sort(void)
{
    const char *content =
        "Vector `Z9_LAST`はfixtureです。\n"
        "- `A2_SECOND`: fixture。\n"
        "### Vector A1: first\n";
    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            error,
            sizeof(error))
        != 0) {
        fprintf(stderr, "unexpected sort parse failure: %s\n", error);
        return 1;
    }
    if (inventory.count != 3u || strcmp(inventory.definitions[0].id, "A1") != 0
        || strcmp(inventory.definitions[1].id, "A2_SECOND") != 0
        || strcmp(inventory.definitions[2].id, "Z9_LAST") != 0) {
        fprintf(stderr, "vector inventory sort is not deterministic ASCII ID order\n");
        return 1;
    }
    return 0;
}

static int test_path_truncation(void)
{
    char repo_root[NINLIL_VECTOR_INVENTORY_MAX_PATH_LEN + 32u];
    char path[32];
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    memset(repo_root, 'r', sizeof(repo_root) - 1u);
    repo_root[sizeof(repo_root) - 1u] = '\0';
    if (ninlil_vector_inventory_build_doc14_path(
            repo_root,
            path,
            sizeof(path),
            error,
            sizeof(error))
        == 0) {
        fprintf(stderr, "expected vector inventory path truncation failure\n");
        return 1;
    }
    if (strstr(error, "vector inventory path truncated") == NULL) {
        fprintf(stderr, "unexpected path truncation error: %s\n", error);
        return 1;
    }
    return 0;
}

static int test_repository_check(const char *repo_root)
{
    ninlil_vector_repository_check_result_t result;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (ninlil_vector_run_repository_check(repo_root, &result, stderr) != 0) {
        fprintf(stderr, "repository vector inventory check failed\n");
        return 1;
    }
    if (result.kinds.total != NINLIL_VECTOR_INVENTORY_EXPECTED_DEFINITION_COUNT) {
        fprintf(
            stderr,
            "unexpected vector definition count: %zu\n",
            result.kinds.total);
        return 1;
    }
    if (result.kinds.table != NINLIL_VECTOR_INVENTORY_EXPECTED_TABLE_COUNT
        || result.kinds.explicit != NINLIL_VECTOR_INVENTORY_EXPECTED_EXPLICIT_COUNT
        || result.kinds.bullet != NINLIL_VECTOR_INVENTORY_EXPECTED_BULLET_COUNT
        || result.kinds.canonical != NINLIL_VECTOR_INVENTORY_EXPECTED_CANONICAL_HEADING_COUNT) {
        fprintf(
            stderr,
            "kind mismatch: expected table=%u explicit=%u bullet=%u canonical=%u, "
            "got table=%zu explicit=%zu bullet=%zu canonical=%zu\n",
            NINLIL_VECTOR_INVENTORY_EXPECTED_TABLE_COUNT,
            NINLIL_VECTOR_INVENTORY_EXPECTED_EXPLICIT_COUNT,
            NINLIL_VECTOR_INVENTORY_EXPECTED_BULLET_COUNT,
            NINLIL_VECTOR_INVENTORY_EXPECTED_CANONICAL_HEADING_COUNT,
            result.kinds.table,
            result.kinds.explicit,
            result.kinds.bullet,
            result.kinds.canonical);
        return 1;
    }

    {
        char doc_path[NINLIL_VECTOR_INVENTORY_MAX_PATH_LEN];
        ninlil_vector_inventory_t inventory;

        if (ninlil_vector_inventory_build_doc14_path(
                repo_root,
                doc_path,
                sizeof(doc_path),
                error,
                sizeof(error))
            != 0) {
            fprintf(stderr, "repository path build failed: %s\n", error);
            return 1;
        }
        if (ninlil_vector_inventory_parse_markdown_file(
                doc_path,
                &inventory,
                error,
                sizeof(error))
            != 0) {
            fprintf(stderr, "repository parse failed: %s\n", error);
            return 1;
        }
        if (expect_kind_counts(
                &inventory,
                NINLIL_VECTOR_INVENTORY_EXPECTED_TABLE_COUNT,
                NINLIL_VECTOR_INVENTORY_EXPECTED_EXPLICIT_COUNT,
                NINLIL_VECTOR_INVENTORY_EXPECTED_BULLET_COUNT,
                NINLIL_VECTOR_INVENTORY_EXPECTED_CANONICAL_HEADING_COUNT)
            != 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <repo_root>\n", argv[0]);
        return 2;
    }

    if (test_table_definition() != 0) {
        return 1;
    }
    if (test_explicit_definition() != 0) {
        return 1;
    }
    if (test_prose_reference_ignored() != 0) {
        return 1;
    }
    if (test_bullet_definition() != 0) {
        return 1;
    }
    if (test_canonical_heading_definition() != 0) {
        return 1;
    }
    if (test_alias_reference_ignored() != 0) {
        return 1;
    }
    if (test_duplicate_definition() != 0) {
        return 1;
    }
    if (test_mixed_newline_duplicate_line_numbers() != 0) {
        return 1;
    }
    if (test_malformed_id() != 0) {
        return 1;
    }
    if (test_ascii_only_id() != 0) {
        return 1;
    }
    if (test_malformed_vector_table_row() != 0) {
        return 1;
    }
    if (test_vector_table_header_blank() != 0) {
        return 1;
    }
    if (test_vector_table_header_non_table() != 0) {
        return 1;
    }
    if (test_vector_table_separator_without_data() != 0) {
        return 1;
    }
    if (test_vector_table_header_eof() != 0) {
        return 1;
    }
    if (test_vector_table_boundary_reprocessed() != 0) {
        return 1;
    }
    if (test_unterminated_backtick() != 0) {
        return 1;
    }
    if (test_overlong_id_line() != 0) {
        return 1;
    }
    if (test_overlong_table_id() != 0) {
        return 1;
    }
    if (test_overlong_line() != 0) {
        return 1;
    }
    if (test_unrelated_table_not_borrowed() != 0) {
        return 1;
    }
    if (test_exact_canonical_heading() != 0) {
        return 1;
    }
    if (test_deterministic_sort() != 0) {
        return 1;
    }
    if (test_path_truncation() != 0) {
        return 1;
    }
    if (test_repository_check(argv[1]) != 0) {
        return 1;
    }
    return 0;
}
