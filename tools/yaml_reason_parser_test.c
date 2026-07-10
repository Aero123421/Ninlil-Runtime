#define _POSIX_C_SOURCE 200809L

#include "yaml_reason_schema.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int expect_parse_content_fail(const char *content)
{
    ninlil_reason_registry_yaml_t registry;

    if (ninlil_parse_reason_registry_yaml_content(content, &registry) == 0) {
        fprintf(stderr, "expected parse failure for content\n");
        return 1;
    }
    return 0;
}

static int expect_parse_content_fail_with_error(
    const char *content,
    const char *expected_error)
{
    ninlil_reason_registry_yaml_t registry;
    char error[512];

    if (ninlil_parse_reason_registry_yaml_content_ex(content, &registry, error, sizeof(error)) == 0) {
        fprintf(stderr, "expected parse failure for content\n");
        return 1;
    }
    if (strstr(error, expected_error) == NULL) {
        fprintf(
            stderr,
            "expected parse error containing '%s', got '%s'\n",
            expected_error,
            error);
        return 1;
    }
    return 0;
}

static int expect_parse_file_fail(const char *path)
{
    ninlil_reason_registry_yaml_t registry;

    if (ninlil_parse_reason_registry_yaml(path, &registry) == 0) {
        fprintf(stderr, "expected parse failure for %s\n", path);
        return 1;
    }
    return 0;
}

static int write_workdir_fixture(
    const char *work_dir,
    const char *label,
    const char *content,
    char *out_path,
    size_t out_path_size)
{
    int fd;
    size_t length = strlen(content);

    snprintf(out_path, out_path_size, "%s/reason_yaml_%s_XXXXXX", work_dir, label);
    fd = mkstemp(out_path);
    if (fd < 0) {
        return -1;
    }
    if (write(fd, content, length) != (ssize_t)length) {
        close(fd);
        unlink(out_path);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(out_path);
        return -1;
    }
    return 0;
}

static int load_valid_registry(const char *repo_root, ninlil_reason_registry_yaml_t *registry)
{
    char yaml_path[512];

    snprintf(
        yaml_path,
        sizeof(yaml_path),
        "%s/schemas/foundation-m1a-reason-codes.yaml",
        repo_root);
    return ninlil_parse_reason_registry_yaml(yaml_path, registry);
}

static int test_valid_yaml(const char *repo_root)
{
    ninlil_reason_registry_yaml_t registry;

    if (load_valid_registry(repo_root, &registry) != 0) {
        fprintf(stderr, "valid yaml test failed\n");
        return 1;
    }
    if (registry.code_count != 54u) {
        fprintf(stderr, "valid yaml test expected 54 codes\n");
        return 1;
    }
    return 0;
}

static int test_reject_tabs(const char *work_dir)
{
    char path[512];
    const char *content =
        "schema_version: 1\n"
        "registry:\tninlil-foundation-reason-codes\n";

    if (write_workdir_fixture(work_dir, "tabs", content, path, sizeof(path)) != 0) {
        return 1;
    }
    if (expect_parse_file_fail(path) != 0) {
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

static int test_reject_trailing_numeric_junk(void)
{
    const char *content =
        "schema_version: 1x\n"
        "registry: ninlil-foundation-reason-codes\n"
        "integer_type: uint32\n"
        "normative_source: ../docs/12-foundation-abi.md#44-reason-code\n"
        "operator_projection_contract: ../docs/11-operator-model.md#共通operator-state\n"
        "reserved_values:\n"
        "  - 67\n"
        "m1a_public_generated_zero:\n"
        "  - NINLIL_REASON_UNSUPPORTED_FAMILY\n"
        "codes:\n";

    return expect_parse_content_fail(content);
}

static int test_reject_uint32_overflow(void)
{
    const char *content =
        "schema_version: 4294967296\n"
        "registry: ninlil-foundation-reason-codes\n"
        "integer_type: uint32\n"
        "normative_source: ../docs/12-foundation-abi.md#44-reason-code\n"
        "operator_projection_contract: ../docs/11-operator-model.md#共通operator-state\n"
        "reserved_values:\n"
        "  - 67\n"
        "m1a_public_generated_zero:\n"
        "  - NINLIL_REASON_UNSUPPORTED_FAMILY\n"
        "codes:\n";

    return expect_parse_content_fail(content);
}

static int test_reject_bad_indentation(void)
{
    const char *content =
        "  schema_version: 1\n"
        "registry: ninlil-foundation-reason-codes\n"
        "integer_type: uint32\n"
        "normative_source: ../docs/12-foundation-abi.md#44-reason-code\n"
        "operator_projection_contract: ../docs/11-operator-model.md#共通operator-state\n"
        "reserved_values:\n"
        "  - 67\n"
        "m1a_public_generated_zero:\n"
        "  - NINLIL_REASON_UNSUPPORTED_FAMILY\n"
        "codes:\n";

    return expect_parse_content_fail(content);
}

static int test_reject_unknown_code_field(void)
{
    const char *content =
        "schema_version: 1\n"
        "registry: ninlil-foundation-reason-codes\n"
        "integer_type: uint32\n"
        "normative_source: ../docs/12-foundation-abi.md#44-reason-code\n"
        "operator_projection_contract: ../docs/11-operator-model.md#共通operator-state\n"
        "reserved_values:\n"
        "  - 67\n"
        "m1a_public_generated_zero:\n"
        "  - NINLIL_REASON_UNSUPPORTED_FAMILY\n"
        "codes:\n"
        "  - symbol: NINLIL_REASON_NONE\n"
        "    value: 0\n"
        "    unknown_field: bad\n"
        "    milestone: M1a\n"
        "    category: success\n"
        "    default_retry_guidance: NINLIL_RETRY_NEVER\n"
        "    operator_state_hint: no_error\n";

    return expect_parse_content_fail(content);
}

static int test_reject_missing_code_field(void)
{
    const char *content =
        "schema_version: 1\n"
        "registry: ninlil-foundation-reason-codes\n"
        "integer_type: uint32\n"
        "normative_source: ../docs/12-foundation-abi.md#44-reason-code\n"
        "operator_projection_contract: ../docs/11-operator-model.md#共通operator-state\n"
        "reserved_values:\n"
        "  - 67\n"
        "m1a_public_generated_zero:\n"
        "  - NINLIL_REASON_UNSUPPORTED_FAMILY\n"
        "codes:\n"
        "  - symbol: NINLIL_REASON_NONE\n"
        "    value: 0\n"
        "    category: success\n"
        "    default_retry_guidance: NINLIL_RETRY_NEVER\n"
        "    operator_state_hint: no_error\n";

    return expect_parse_content_fail(content);
}

static int test_reject_oversized_scalar(void)
{
    char *content;
    char *oversized;
    size_t i;
    size_t content_size;
    int result;
    const char *prefix =
        "schema_version: 1\n"
        "registry: ";
    const char *suffix =
        "\n"
        "integer_type: uint32\n";

    oversized = (char *)malloc(NINLIL_REASON_REGISTRY_MAX_PATH_LEN + 1u);
    if (oversized == NULL) {
        return 1;
    }
    for (i = 0; i < NINLIL_REASON_REGISTRY_MAX_PATH_LEN; ++i) {
        oversized[i] = 'a';
    }
    oversized[NINLIL_REASON_REGISTRY_MAX_PATH_LEN] = '\0';

    content_size = strlen(prefix) + strlen(oversized) + strlen(suffix) + 1u;
    content = (char *)malloc(content_size);
    if (content == NULL) {
        free(oversized);
        return 1;
    }
    snprintf(content, content_size, "%s%s%s", prefix, oversized, suffix);
    free(oversized);

    result = expect_parse_content_fail_with_error(content, "scalar value too long");
    free(content);
    return result;
}

static int test_reject_oversized_line(const char *work_dir)
{
    char path[512];
    FILE *out;
    size_t i;
    int fd;

    snprintf(path, sizeof(path), "%s/reason_yaml_long_XXXXXX", work_dir);
    fd = mkstemp(path);
    if (fd < 0) {
        return 1;
    }
    out = fdopen(fd, "wb");
    if (out == NULL) {
        close(fd);
        unlink(path);
        return 1;
    }
    for (i = 0; i < (NINLIL_YAML_MAX_LINE_LEN + 128u); ++i) {
        fputc('a', out);
    }
    fputc('\n', out);
    fclose(out);

    if (expect_parse_file_fail(path) != 0) {
        unlink(path);
        return 1;
    }
    unlink(path);
    return 0;
}

static int test_reject_duplicate_symbol(const char *repo_root)
{
    ninlil_reason_registry_yaml_t registry;

    if (load_valid_registry(repo_root, &registry) != 0) {
        return 1;
    }
    memcpy(
        registry.codes[1].symbol,
        registry.codes[0].symbol,
        sizeof(registry.codes[0].symbol));
    if (ninlil_validate_reason_registry(&registry) == 0) {
        fprintf(stderr, "duplicate symbol test failed\n");
        return 1;
    }
    return 0;
}

static int test_reject_duplicate_value(const char *repo_root)
{
    ninlil_reason_registry_yaml_t registry;

    if (load_valid_registry(repo_root, &registry) != 0) {
        return 1;
    }
    registry.codes[1].value = registry.codes[0].value;
    if (ninlil_validate_reason_registry(&registry) == 0) {
        fprintf(stderr, "duplicate value test failed\n");
        return 1;
    }
    return 0;
}

static int test_reject_reserved_collision(const char *repo_root)
{
    ninlil_reason_registry_yaml_t registry;

    if (load_valid_registry(repo_root, &registry) != 0) {
        return 1;
    }
    registry.codes[0].value = 67u;
    if (ninlil_validate_reason_registry(&registry) == 0) {
        fprintf(stderr, "reserved collision test failed\n");
        return 1;
    }
    return 0;
}

static int test_reject_generated_zero_missing(const char *repo_root)
{
    ninlil_reason_registry_yaml_t registry;

    if (load_valid_registry(repo_root, &registry) != 0) {
        return 1;
    }
    registry.m1a_public_generated_zero[0][0] = '\0';
    if (ninlil_validate_reason_registry(&registry) == 0) {
        fprintf(stderr, "generated-zero missing test failed\n");
        return 1;
    }
    return 0;
}

static int test_anchor_checks(const char *repo_root)
{
    if (ninlil_validate_reason_registry_links(repo_root) != 0) {
        fprintf(stderr, "anchor checks failed\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *repo_root;
    const char *work_dir;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <repo_root> <work_dir>\n", argv[0]);
        return 2;
    }
    repo_root = argv[1];
    work_dir = argv[2];

    if (test_valid_yaml(repo_root) != 0) {
        return 1;
    }
    if (test_reject_tabs(work_dir) != 0) {
        return 1;
    }
    if (test_reject_trailing_numeric_junk() != 0) {
        return 1;
    }
    if (test_reject_uint32_overflow() != 0) {
        return 1;
    }
    if (test_reject_bad_indentation() != 0) {
        return 1;
    }
    if (test_reject_unknown_code_field() != 0) {
        return 1;
    }
    if (test_reject_missing_code_field() != 0) {
        return 1;
    }
    if (test_reject_oversized_scalar() != 0) {
        return 1;
    }
    if (test_reject_oversized_line(work_dir) != 0) {
        return 1;
    }
    if (test_reject_duplicate_symbol(repo_root) != 0) {
        return 1;
    }
    if (test_reject_duplicate_value(repo_root) != 0) {
        return 1;
    }
    if (test_reject_reserved_collision(repo_root) != 0) {
        return 1;
    }
    if (test_reject_generated_zero_missing(repo_root) != 0) {
        return 1;
    }
    if (test_anchor_checks(repo_root) != 0) {
        return 1;
    }
    return 0;
}
