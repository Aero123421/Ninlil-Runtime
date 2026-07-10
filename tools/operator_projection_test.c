#include "operator_projection_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_BUFFER_SIZE 16384u

static const char valid_document[] =
    "# Operator fixture\n"
    "\n"
    "## Projection contract\n"
    "\n"
    "| Projection context | Default Operator State |\n"
    "| --- | --- |\n"
    "| active | `OP_A` |\n"
    "| terminal | `OP_B` |\n"
    "\n"
    "Outside prose contains OP_OUTSIDE and must not be a reference.\n"
    "\n"
    "## Outside section\n"
    "\n"
    "| Projection context | Default Operator State |\n"
    "| --- | --- |\n"
    "| outside | `OP_OUTSIDE` |\n"
    "\n"
    "## 共通Operator State\n"
    "\n"
    "| Operator code | 利用者向け意味 | 主な内部根拠 | 安全な次操作 | 禁止する表示・操作 | Default owner / timeout |\n"
    "| --- | --- | --- | --- | --- | --- |\n"
    "| `OP_A` | a | a | a | a | a |\n"
    "| `OP_B` | b | b | b | b | b |\n"
    "\n"
    "## Later section\n"
    "\n"
    "| Operator code | 利用者向け意味 | 主な内部根拠 | 安全な次操作 | 禁止する表示・操作 | Default owner / timeout |\n"
    "| --- | --- | --- | --- | --- | --- |\n"
    "| `OP_OUTSIDE` | x | x | x | x | x |\n";

static void make_registry(ninlil_reason_registry_yaml_t *registry)
{
    memset(registry, 0, sizeof(*registry));
    snprintf(registry->operator_projection_contract,
        sizeof(registry->operator_projection_contract), "%s", NINLIL_OPERATOR_PROJECTION_LINK);
    registry->code_count = 2u;
    snprintf(registry->codes[0].symbol, sizeof(registry->codes[0].symbol), "NINLIL_REASON_A");
    snprintf(registry->codes[0].operator_state_hint,
        sizeof(registry->codes[0].operator_state_hint), "reason_a");
    snprintf(registry->codes[1].symbol, sizeof(registry->codes[1].symbol), "NINLIL_REASON_B");
    snprintf(registry->codes[1].operator_state_hint,
        sizeof(registry->codes[1].operator_state_hint), "reason_b");
}

static int replace_once(
    const char *input,
    const char *needle,
    const char *replacement,
    char *output,
    size_t output_size)
{
    const char *match = strstr(input, needle);
    size_t prefix;
    size_t replacement_length;
    size_t suffix_length;
    if (match == NULL) {
        return -1;
    }
    prefix = (size_t)(match - input);
    replacement_length = strlen(replacement);
    suffix_length = strlen(match + strlen(needle));
    if (prefix + replacement_length + suffix_length + 1u > output_size) {
        return -1;
    }
    memcpy(output, input, prefix);
    memcpy(output + prefix, replacement, replacement_length);
    memcpy(output + prefix + replacement_length, match + strlen(needle), suffix_length + 1u);
    return 0;
}

static int expect_failure(
    const char *name,
    const char *content,
    const ninlil_reason_registry_yaml_t *registry,
    const char *expected_error)
{
    ninlil_operator_projection_result_t result;
    char error[NINLIL_OPERATOR_PROJECTION_MAX_ERROR] = {0};
    if (ninlil_operator_projection_check_content(
            content, registry, &result, error, sizeof(error))
        == 0) {
        fprintf(stderr, "%s: invalid projection was accepted\n", name);
        return -1;
    }
    if (strstr(error, expected_error) == NULL) {
        fprintf(stderr, "%s: expected error containing '%s', got '%s'\n", name,
            expected_error, error);
        return -1;
    }
    return 0;
}

static int expect_bytes_failure(
    const char *name,
    const char *content,
    size_t content_length,
    const ninlil_reason_registry_yaml_t *registry,
    const char *expected_error)
{
    ninlil_operator_projection_result_t result;
    char error[NINLIL_OPERATOR_PROJECTION_MAX_ERROR] = {0};
    if (ninlil_operator_projection_check_bytes(
            content, content_length, registry, &result, error, sizeof(error))
        == 0) {
        fprintf(stderr, "%s: invalid projection bytes were accepted\n", name);
        return -1;
    }
    if (strstr(error, expected_error) == NULL) {
        fprintf(stderr, "%s: expected error containing '%s', got '%s'\n", name,
            expected_error, error);
        return -1;
    }
    return 0;
}

static int replace_failure(
    const char *name,
    const char *needle,
    const char *replacement,
    const ninlil_reason_registry_yaml_t *registry,
    const char *expected_error)
{
    char content[TEST_BUFFER_SIZE];
    if (replace_once(valid_document, needle, replacement, content, sizeof(content)) != 0) {
        fprintf(stderr, "%s: test setup replacement failed\n", name);
        return -1;
    }
    return expect_failure(name, content, registry, expected_error);
}

static int test_synthetic_contract(void)
{
    static const char state_b_row[] = "| `OP_B` | b | b | b | b | b |\n";
    ninlil_reason_registry_yaml_t registry;
    ninlil_operator_projection_result_t result;
    char error[NINLIL_OPERATOR_PROJECTION_MAX_ERROR] = {0};
    char content[TEST_BUFFER_SIZE];
    char second[TEST_BUFFER_SIZE];
    int failures = 0;

    make_registry(&registry);
    if (ninlil_operator_projection_check_content(
            valid_document, &registry, &result, error, sizeof(error))
            != 0
        || result.context_rows != 2u || result.state_codes != 2u || result.references != 2u
        || result.reason_hints != 2u) {
        fprintf(stderr, "valid synthetic projection failed: %s\n", error);
        ++failures;
    }

#define REPLACE_FAILURE(name, needle, replacement, expected)                              \
    do {                                                                                   \
        failures += replace_failure(name, needle, replacement, &registry, expected) != 0; \
    } while (0)

    REPLACE_FAILURE("wrong projection heading", "## Projection contract",
        "### Projection contract", "wrong heading form for ## Projection contract");
    REPLACE_FAILURE("ambiguous projection heading", "## Outside section",
        "### Projection-contract\n## Outside section", "ambiguous heading ## Projection contract");
    REPLACE_FAILURE("wrong state heading", "## 共通Operator State",
        "### 共通Operator State", "wrong heading form for ## 共通Operator State");
    REPLACE_FAILURE("ambiguous state heading", "## Later section",
        "### 共通Operator State\n## Later section", "ambiguous heading ## 共通Operator State");
    REPLACE_FAILURE("unknown reference", "| terminal | `OP_B` |",
        "| terminal | `OP_UNKNOWN` |", "unknown operator state reference OP_UNKNOWN");
    REPLACE_FAILURE("duplicate reference", "| terminal | `OP_B` |",
        "| terminal | `OP_A` |", "duplicate operator reference OP_A");
    REPLACE_FAILURE("unbackticked reference", "| terminal | `OP_B` |",
        "| terminal | OP_B |", "operator reference must be backticked");
    REPLACE_FAILURE("missing state definition", state_b_row, "",
        "unknown operator state reference OP_B");
    REPLACE_FAILURE("duplicate state definition", state_b_row,
        "| `OP_B` | b | b | b | b | b |\n| `OP_A` | duplicate | x | x | x | x |\n",
        "duplicate operator state OP_A");
    REPLACE_FAILURE("state without projection", state_b_row,
        "| `OP_B` | b | b | b | b | b |\n| `OP_C` | c | c | c | c | c |\n",
        "operator state OP_C has no projection reference");
    REPLACE_FAILURE("wrong context table heading", "Default Operator State",
        "Default State", "missing projection table");
    REPLACE_FAILURE("wrong context separator", "| --- | --- |\n| active",
        "| -- | --- |\n| active", "invalid projection table separator");
    REPLACE_FAILURE("malformed context row", "| active | `OP_A` |",
        "| active | `OP_A` | extra |", "malformed projection context row");
    REPLACE_FAILURE("wrong state table heading", "Operator code | 利用者向け意味",
        "State code | 利用者向け意味", "missing projection table");
    REPLACE_FAILURE("wrong state separator", "| --- | --- | --- | --- | --- | --- |\n| `OP_A`",
        "| -- | --- | --- | --- | --- | --- |\n| `OP_A`",
        "invalid projection table separator");
    REPLACE_FAILURE("malformed state row", "| `OP_A` | a | a | a | a | a |",
        "| `OP_A` | a | a | a | a |", "malformed operator state row");

#undef REPLACE_FAILURE

    if (replace_once(valid_document, "| terminal | `OP_B` |\n", "", content,
            sizeof(content))
            != 0
        || replace_once(content, "## Outside section\n",
            "## Outside section\n| terminal | `OP_B` |\n", second, sizeof(second))
            != 0) {
        fputs("section-bounded context setup failed\n", stderr);
        ++failures;
    } else {
        failures += expect_failure("context outside section cannot satisfy projection", second,
                        &registry, "operator state OP_B has no projection reference")
            != 0;
    }
    if (replace_once(valid_document, state_b_row, "", content, sizeof(content)) != 0
        || replace_once(content, "## Later section\n", "## Later section\n| `OP_B` | b | b | b | b | b |\n",
            second, sizeof(second))
            != 0) {
        fputs("section-bounded state setup failed\n", stderr);
        ++failures;
    } else {
        failures += expect_failure("state outside section cannot satisfy definition", second,
                        &registry, "unknown operator state reference OP_B")
            != 0;
    }
    if (replace_once(valid_document, "## Outside section\n",
            "| Projection context | Default Operator State |\n"
            "| --- | --- |\n| extra | `OP_A` |\n\n## Outside section\n",
            content, sizeof(content))
        != 0) {
        fputs("ambiguous table setup failed\n", stderr);
        ++failures;
    } else {
        failures += expect_failure("ambiguous context table", content, &registry,
                        "ambiguous projection table")
            != 0;
    }

    make_registry(&registry);
    snprintf(registry.operator_projection_contract, sizeof(registry.operator_projection_contract),
        "../docs/11-operator-model.md#wrong-heading");
    failures += expect_failure("wrong registry link", valid_document, &registry,
                    "operator projection contract link mismatch")
        != 0;
    make_registry(&registry);
    registry.codes[1].operator_state_hint[0] = '\0';
    failures += expect_failure("empty reason hint", valid_document, &registry,
                    "empty operator_state_hint for reason NINLIL_REASON_B")
        != 0;
    make_registry(&registry);
    {
        char embedded_nul[sizeof(valid_document)];
        memcpy(embedded_nul, valid_document, sizeof(embedded_nul));
        embedded_nul[8] = '\0';
        failures += expect_bytes_failure("embedded NUL", embedded_nul,
                        sizeof(embedded_nul) - 1u, &registry, "contains embedded NUL")
            != 0;
    }
    if (replace_once(valid_document, "Operator fixture", "Operator fixture", content,
            sizeof(content))
        != 0) {
        fputs("invalid UTF-8 setup failed\n", stderr);
        ++failures;
    } else {
        char *invalid = strstr(content, "Operator fixture");
        if (invalid == NULL) {
            fputs("invalid UTF-8 lookup failed\n", stderr);
            ++failures;
        } else {
            invalid[0] = (char)0xc0;
            failures += expect_failure("invalid UTF-8", content, &registry, "not valid UTF-8") != 0;
        }
    }
    return failures == 0 ? 0 : -1;
}

static int test_real_repository(const char *repo_root)
{
    ninlil_operator_projection_result_t result;
    if (ninlil_operator_projection_run_repository_check(repo_root, &result, stderr) != 0) {
        return -1;
    }
    if (result.context_rows != 7u || result.state_codes != 15u || result.references != 15u
        || result.reason_hints != 54u) {
        fprintf(stderr,
            "unexpected operator projection counts: contexts=%zu states=%zu references=%zu "
            "reason_hints=%zu\n",
            result.context_rows, result.state_codes, result.references, result.reason_hints);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <repository-root>\n", argv[0]);
        return 2;
    }
    if (test_synthetic_contract() != 0 || test_real_repository(argv[1]) != 0) {
        return 1;
    }
    puts("operator projection negative and repository tests ok");
    return 0;
}
