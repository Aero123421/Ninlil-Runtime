#include "traceability_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 16384u

typedef struct source_fixture {
    const char *path;
    const char *content;
} source_fixture_t;

typedef struct resolver_fixture {
    const source_fixture_t *sources;
    size_t count;
} resolver_fixture_t;

static const char cmake_fixture[] =
    "add_test(NAME known_test COMMAND fixture)\n"
    "add_test(\n"
    "    NAME second_test\n"
    "    COMMAND fixture\n"
    ")\n"
    "# add_test(NAME commented_test COMMAND fixture)\n"
    "add_test(NAME dynamic_${suffix} COMMAND fixture)\n";

static const char valid_manifest[] =
    "format: NINLIL_TRACEABILITY_V1\n"
    "schema_version: 1\n"
    "scope: PR1\n"
    "completion_target: PR3\n"
    "requirements:\n"
    "  - id: NIN-PR1-TEST-001\n"
    "    title: \"Verified fixture\"\n"
    "    source: docs/test.md\n"
    "    heading: \"# Test heading\"\n"
    "    owner: PR1\n"
    "    profile: FOUNDATION_M1A_TEST\n"
    "    gate: PR1\n"
    "    status: verified\n"
    "    tests: [known_test]\n"
    "    gap: \"\"\n";

static const char all_status_manifest[] =
    "format: NINLIL_TRACEABILITY_V1\n"
    "schema_version: 1\n"
    "scope: PR1\n"
    "completion_target: PR3\n"
    "requirements:\n"
    "  - id: NIN-PR1-TEST-001\n"
    "    title: \"Verified fixture\"\n"
    "    source: docs/test.md\n"
    "    heading: \"# 日本語の試験見出し\"\n"
    "    owner: PR1\n"
    "    profile: FOUNDATION_M1A_TEST\n"
    "    gate: PR1\n"
    "    status: verified\n"
    "    tests: [known_test]\n"
    "    gap: \"\"\n"
    "  - id: NIN-PR1-TEST-002\n"
    "    title: \"Partial fixture\"\n"
    "    source: docs/other.md\n"
    "    heading: \"### 別の試験見出し\"\n"
    "    owner: PR1\n"
    "    profile: FOUNDATION_M1A_TEST\n"
    "    gate: PR1\n"
    "    status: partial\n"
    "    tests: [second_test]\n"
    "    gap: \"Remaining behavior is not tested.\"\n"
    "  - id: NIN-PR1-TEST-003\n"
    "    title: \"Planned fixture\"\n"
    "    source: docs/planned.md\n"
    "    heading: \"### Planned heading\"\n"
    "    owner: PR1\n"
    "    profile: FOUNDATION_M1A_TEST\n"
    "    gate: PR1\n"
    "    status: planned\n"
    "    tests: []\n"
    "    gap: \"No executable test exists yet.\"\n";

static int fixture_resolver(
    void *user,
    const char *source_path,
    const char *heading,
    size_t *out_count,
    size_t *out_first_line,
    size_t *out_second_line,
    char *error_out,
    size_t error_out_size)
{
    const resolver_fixture_t *fixture = (const resolver_fixture_t *)user;
    size_t index;

    *out_count = 0u;
    *out_first_line = 0u;
    *out_second_line = 0u;
    for (index = 0u; index < fixture->count; ++index) {
        if (strcmp(fixture->sources[index].path, source_path) == 0) {
            const char *cursor = fixture->sources[index].content;
            size_t line = 1u;
            size_t heading_length = strlen(heading);
            while (*cursor != '\0') {
                const char *end = strchr(cursor, '\n');
                size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
                if (length > 0u && cursor[length - 1u] == '\r') {
                    --length;
                }
                if (length == heading_length && memcmp(cursor, heading, length) == 0) {
                    ++(*out_count);
                    if (*out_count == 1u) {
                        *out_first_line = line;
                    } else if (*out_count == 2u) {
                        *out_second_line = line;
                    }
                }
                if (end == NULL) {
                    break;
                }
                cursor = end + 1;
                ++line;
            }
            return 0;
        }
    }
    snprintf(error_out, error_out_size, "fixture source not found: %s", source_path);
    return -1;
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
    const char *manifest,
    const char *cmake,
    const resolver_fixture_t *fixture,
    const char *expected_error)
{
    char error[NINLIL_TRACEABILITY_MAX_ERROR] = {0};
    ninlil_traceability_result_t result;

    if (ninlil_traceability_check_content(
            manifest, cmake, fixture_resolver, (void *)fixture, &result, error, sizeof(error))
        == 0) {
        fprintf(stderr, "%s: invalid input was accepted\n", name);
        return -1;
    }
    if (strstr(error, expected_error) == NULL) {
        fprintf(stderr, "%s: expected error containing '%s', got '%s'\n", name, expected_error,
            error);
        return -1;
    }
    return 0;
}

static int replace_failure(
    const char *name,
    const char *needle,
    const char *replacement,
    const resolver_fixture_t *fixture,
    const char *expected_error)
{
    char manifest[BUFFER_SIZE];
    if (replace_once(valid_manifest, needle, replacement, manifest, sizeof(manifest)) != 0) {
        fprintf(stderr, "%s: test setup replacement failed\n", name);
        return -1;
    }
    return expect_failure(name, manifest, cmake_fixture, fixture, expected_error);
}

static int test_in_memory_checks(void)
{
    static const source_fixture_t valid_sources[] = {
        {"docs/test.md",
            "Introduction\n# Test heading\n# 日本語の試験見出し\n状態: Normative pre-alpha\n"
            "####NoSpace\n### \nBody\n"},
        {"docs/other.md", "### 別の試験見出し\n"},
        {"docs/planned.md", "### Planned heading\n"}};
    static const source_fixture_t missing_heading_sources[] = {
        {"docs/test.md", "# Different heading\n"}};
    static const source_fixture_t duplicate_heading_sources[] = {
        {"docs/test.md", "# Test heading\nBody\n# Test heading\n"}};
    const resolver_fixture_t fixture = {
        valid_sources, sizeof(valid_sources) / sizeof(valid_sources[0])};
    const resolver_fixture_t missing_heading = {missing_heading_sources, 1u};
    const resolver_fixture_t duplicate_heading = {duplicate_heading_sources, 1u};
    ninlil_traceability_result_t result;
    char error[NINLIL_TRACEABILITY_MAX_ERROR] = {0};
    char manifest[BUFFER_SIZE];
    char second[BUFFER_SIZE];
    char *overlong;
    size_t overlong_size = NINLIL_TRACEABILITY_MAX_LINE_LEN + 512u;
    int failures = 0;

    if (ninlil_traceability_check_content(all_status_manifest, cmake_fixture, fixture_resolver,
            (void *)&fixture, &result, error, sizeof(error))
            != 0
        || result.entries != 3u || result.verified != 1u || result.partial != 1u
        || result.planned != 1u || result.test_links != 2u) {
        fprintf(stderr, "positive status check failed: %s\n", error);
        ++failures;
    }

    if (replace_once(valid_manifest, "    gap: \"\"\n",
            "    gap: \"\"\n  - id: NIN-PR1-TEST-001\n"
            "    title: \"Duplicate\"\n    source: docs/test.md\n"
            "    heading: \"# Test heading\"\n    owner: PR1\n"
            "    profile: FOUNDATION_M1A_TEST\n    gate: PR1\n"
            "    status: verified\n    tests: [known_test]\n    gap: \"\"\n",
            manifest, sizeof(manifest))
        != 0) {
        fprintf(stderr, "duplicate ID setup failed\n");
        ++failures;
    } else {
        failures += expect_failure("duplicate ID", manifest, cmake_fixture, &fixture,
                        "duplicate requirement ID")
            != 0;
    }

#define REPLACE_FAILURE(name, needle, replacement, expected)                               \
    do {                                                                                    \
        failures += replace_failure(name, needle, replacement, &fixture, expected) != 0;   \
    } while (0)

    REPLACE_FAILURE("broken source", "docs/test.md", "docs/missing.md", "source resolution failed");
    failures += expect_failure("missing heading", valid_manifest, cmake_fixture,
                    &missing_heading, "heading not found")
        != 0;
    failures += expect_failure("duplicate heading", valid_manifest, cmake_fixture,
                    &duplicate_heading, "duplicate heading")
        != 0;
    REPLACE_FAILURE("path traversal", "docs/test.md", "docs/../test.md", "invalid source path");
    REPLACE_FAILURE("unknown test", "[known_test]", "[not_registered]", "unknown CTest ID");
    REPLACE_FAILURE("commented test", "[known_test]", "[commented_test]", "unknown CTest ID");
    REPLACE_FAILURE("dynamic test", "[known_test]", "[dynamic_test]", "unknown CTest ID");
    REPLACE_FAILURE("invalid owner", "owner: PR1", "owner: PR2", "invalid owner");
    REPLACE_FAILURE("invalid profile", "profile: FOUNDATION_M1A_TEST", "profile: OTHER",
        "invalid profile");
    REPLACE_FAILURE("invalid gate", "gate: PR1", "gate: PR2", "invalid gate");
    REPLACE_FAILURE("invalid status", "status: verified", "status: complete", "invalid status");
    REPLACE_FAILURE("verified without test", "tests: [known_test]", "tests: []",
        "verified entry");
    REPLACE_FAILURE("verified with gap", "gap: \"\"", "gap: \"unexpected\"",
        "verified entry");
    if (replace_once(valid_manifest, "status: verified", "status: planned", manifest,
            sizeof(manifest))
            != 0
        || replace_once(manifest, "gap: \"\"", "gap: \"planned\"", second, sizeof(second))
            != 0) {
        fprintf(stderr, "planned-with-test setup failed\n");
        ++failures;
    } else {
        failures += expect_failure("planned with test", second, cmake_fixture, &fixture,
                        "planned entry")
            != 0;
    }
    REPLACE_FAILURE("planned without gap", "status: verified", "status: planned",
        "planned entry");
    if (replace_once(valid_manifest, "status: verified", "status: partial", manifest,
            sizeof(manifest))
            != 0) {
        fprintf(stderr, "partial-without-gap setup failed\n");
        ++failures;
    } else {
        failures += expect_failure("partial without gap", manifest, cmake_fixture, &fixture,
                        "partial entry")
            != 0;
    }
    if (replace_once(valid_manifest, "status: verified", "status: partial", manifest,
            sizeof(manifest))
            != 0
        || replace_once(manifest, "tests: [known_test]", "tests: []", second, sizeof(second))
            != 0
        || replace_once(second, "gap: \"\"", "gap: \"remaining\"", manifest,
            sizeof(manifest))
            != 0) {
        fprintf(stderr, "partial-without-test setup failed\n");
        ++failures;
    } else {
        failures += expect_failure("partial without test", manifest, cmake_fixture, &fixture,
                        "partial entry")
            != 0;
    }
    REPLACE_FAILURE("malformed indentation", "    title:", "   title:",
        "malformed indentation");
    REPLACE_FAILURE("unknown field", "    owner: PR1\n",
        "    mystery: value\n    owner: PR1\n", "unknown or malformed field");
    REPLACE_FAILURE("duplicate field", "    owner: PR1\n",
        "    owner: PR1\n    owner: PR1\n", "duplicate field owner");
    REPLACE_FAILURE("missing field", "    owner: PR1\n", "", "missing requirement field");
    REPLACE_FAILURE("numeric junk", "schema_version: 1", "schema_version: 1junk",
        "invalid top-level schema");
    REPLACE_FAILURE("numeric overflow", "schema_version: 1",
        "schema_version: 999999999999999999999999999999999999999", "invalid top-level schema");
    REPLACE_FAILURE("trailing test comma", "[known_test]", "[known_test, ]",
        "tests require comma-space");
    REPLACE_FAILURE("unquoted title", "title: \"Verified fixture\"", "title: Verified fixture",
        "quoted scalar");
    REPLACE_FAILURE("prose anchor", "# Test heading", "状態: Normative pre-alpha",
        "invalid Markdown ATX heading");
    REPLACE_FAILURE("ATX missing space", "# Test heading", "####NoSpace",
        "invalid Markdown ATX heading");
    REPLACE_FAILURE("ATX empty text", "# Test heading", "### ",
        "invalid Markdown ATX heading");
    REPLACE_FAILURE("YAML comment", "    owner: PR1\n", "    # owner: PR1\n",
        "unknown or malformed field");
    REPLACE_FAILURE("YAML alias", "source: docs/test.md", "source: *test_source",
        "invalid source path");

#undef REPLACE_FAILURE

    if (replace_once(valid_manifest, "Verified fixture", "Verified fixture", manifest,
            sizeof(manifest))
        != 0) {
        fprintf(stderr, "UTF-8 setup failed\n");
        ++failures;
    } else {
        char *title = strstr(manifest, "Verified fixture");
        if (title == NULL) {
            fprintf(stderr, "UTF-8 title lookup failed\n");
            ++failures;
        } else {
            title[0] = (char)0xc0;
            failures += expect_failure("invalid UTF-8", manifest, cmake_fixture, &fixture,
                            "not valid UTF-8")
                != 0;
        }
    }

    overlong = (char *)malloc(overlong_size);
    if (overlong == NULL) {
        fprintf(stderr, "overlong test allocation failed\n");
        ++failures;
    } else {
        const char *needle = "    title: \"Verified fixture\"\n";
        char *match = strstr(valid_manifest, needle);
        size_t prefix = match == NULL ? 0u : (size_t)(match - valid_manifest);
        const char *suffix = match == NULL ? "" : match + strlen(needle);
        const char *line_prefix = "    title: \"";
        size_t fill = NINLIL_TRACEABILITY_MAX_LINE_LEN;
        if (match == NULL || prefix + strlen(line_prefix) + fill + 3u + strlen(suffix)
                >= overlong_size) {
            fprintf(stderr, "overlong test setup failed\n");
            ++failures;
        } else {
            memcpy(overlong, valid_manifest, prefix);
            memcpy(overlong + prefix, line_prefix, strlen(line_prefix));
            memset(overlong + prefix + strlen(line_prefix), 'A', fill);
            strcpy(overlong + prefix + strlen(line_prefix) + fill, "\"\n");
            strcat(overlong, suffix);
            failures += expect_failure("overlong line", overlong, cmake_fixture, &fixture,
                            "line too long")
                != 0;
        }
        free(overlong);
    }
    return failures == 0 ? 0 : -1;
}

static int test_real_repository(const char *repo_root)
{
    ninlil_traceability_result_t result;
    if (ninlil_traceability_run_repository_check(repo_root, &result, stderr) != 0) {
        return -1;
    }
    if (result.entries != 9u || result.verified != 5u || result.partial != 0u
        || result.planned != 4u || result.test_links != 15u) {
        fprintf(stderr,
            "unexpected repository counts: entries=%zu verified=%zu partial=%zu planned=%zu "
            "test_links=%zu\n",
            result.entries, result.verified, result.partial, result.planned, result.test_links);
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
    if (test_in_memory_checks() != 0 || test_real_repository(argv[1]) != 0) {
        return 1;
    }
    puts("traceability negative and repository tests ok");
    return 0;
}
