#include "hook_registry_schema.h"

#include <stdio.h>
#include <string.h>

static const char *k_sample_heading = "## 17. Named fault hook registry";
static const char *k_hook_a = "runtime.before_service_registry_commit";
static const char *k_hook_b = "runtime.after_service_registry_commit";
static const char *k_hook_c = "controller.before_admission_begin";

static int expect_parse_fail(const char *content, const char *expected_error)
{
    ninlil_hook_registry_t registry;
    char error[NINLIL_HOOK_REGISTRY_MAX_ERROR];

    if (ninlil_hook_registry_parse_markdown_content(
            content,
            k_sample_heading,
            &registry,
            error,
            sizeof(error))
        == 0) {
        fprintf(stderr, "expected hook registry parse failure\n");
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

static int expect_compare_fail(
    const ninlil_hook_registry_t *left,
    const ninlil_hook_registry_t *right)
{
    if (ninlil_hook_registry_compare_ordered(left, right, "left", "right", stderr) == 0) {
        fprintf(stderr, "expected hook registry compare failure\n");
        return 1;
    }
    return 0;
}

static int append_hook_for_test(
    ninlil_hook_registry_t *registry,
    const char *hook_name,
    char *error_out,
    size_t error_out_size)
{
    size_t i;

    if (registry->count >= NINLIL_HOOK_REGISTRY_MAX_HOOKS) {
        return -1;
    }
    for (i = 0; i < registry->count; ++i) {
        if (strcmp(registry->hooks[i], hook_name) == 0) {
            snprintf(error_out, error_out_size, "duplicate hook name: %s", hook_name);
            return -1;
        }
    }
    snprintf(
        registry->hooks[registry->count],
        sizeof(registry->hooks[registry->count]),
        "%s",
        hook_name);
    registry->count += 1u;
    return 0;
}

static int build_registry_from_hooks(
    ninlil_hook_registry_t *registry,
    const char *const *hooks,
    size_t hook_count)
{
    size_t i;
    char error[NINLIL_HOOK_REGISTRY_MAX_ERROR];

    memset(registry, 0, sizeof(*registry));
    for (i = 0; i < hook_count; ++i) {
        if (append_hook_for_test(registry, hooks[i], error, sizeof(error)) != 0) {
            fprintf(stderr, "unexpected registry build failure: %s\n", error);
            return 1;
        }
    }
    return 0;
}

static int test_negative_duplicate(void)
{
    const char *content =
        "## 17. Named fault hook registry\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "runtime.before_service_registry_commit\n"
        "```\n";

    return expect_parse_fail(content, "duplicate hook name");
}

static int test_negative_invalid_name(void)
{
    const char *content =
        "## 17. Named fault hook registry\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "controller.BAD_HOOK\n"
        "```\n";

    return expect_parse_fail(content, "invalid hook name");
}

static int test_negative_missing_heading(void)
{
    const char *content =
        "## 99. Wrong heading\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "```\n";

    return expect_parse_fail(content, "heading not found");
}

static int test_negative_missing_block(void)
{
    const char *content =
        "## 17. Named fault hook registry\n"
        "\n"
        "No fenced block here.\n";

    return expect_parse_fail(content, "```text block not found");
}

static int test_negative_heading_substring(void)
{
    const char *content =
        "See ## 17. Named fault hook registry for details.\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "```\n";

    return expect_parse_fail(content, "heading not found");
}

static int test_negative_wrong_heading_level(void)
{
    const char *content =
        "### 17. Named fault hook registry\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "```\n";

    return expect_parse_fail(content, "heading not found");
}

static int test_negative_duplicate_heading(void)
{
    const char *content =
        "## 17. Named fault hook registry\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "```\n"
        "\n"
        "## 17. Named fault hook registry\n"
        "\n"
        "```text\n"
        "runtime.after_service_registry_commit\n"
        "```\n";

    return expect_parse_fail(content, "heading is ambiguous");
}

static int test_negative_next_section_block_borrowing(void)
{
    const char *content =
        "## 17. Named fault hook registry\n"
        "\n"
        "No fenced block in this section.\n"
        "\n"
        "## 18. Placement contract\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "```\n";

    return expect_parse_fail(content, "```text block not found");
}

static int test_negative_overlong_next_heading_block_borrowing(void)
{
    char content[1024];
    size_t pos = 0u;
    size_t i;

    pos += (size_t)snprintf(
        content + pos,
        sizeof(content) - pos,
        "## 17. Named fault hook registry\n"
        "\n"
        "No fenced block in this section.\n"
        "\n"
        "## 18. Placement contract");
    for (i = 0u; i < 300u && pos + 2u < sizeof(content); ++i) {
        content[pos++] = 'x';
    }
    pos += (size_t)snprintf(
        content + pos,
        sizeof(content) - pos,
        "\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "```\n");

    return expect_parse_fail(content, "```text block not found");
}

static int test_negative_overlong_hook_name(void)
{
    char content[512];
    char hook_name[128];
    size_t i;

    memcpy(hook_name, "runtime.", 8u);
    for (i = 8u; i < 96u; ++i) {
        hook_name[i] = 'a';
    }
    hook_name[96u] = '\0';

    snprintf(
        content,
        sizeof(content),
        "## 17. Named fault hook registry\n"
        "\n"
        "```text\n"
        "runtime.before_service_registry_commit\n"
        "%s\n"
        "```\n",
        hook_name);

    return expect_parse_fail(content, "hook name too long");
}

static int test_negative_order_swap(void)
{
    const char *const left_hooks[] = {k_hook_a, k_hook_b, k_hook_c};
    const char *const right_hooks[] = {k_hook_a, k_hook_c, k_hook_b};
    ninlil_hook_registry_t left;
    ninlil_hook_registry_t right;

    if (build_registry_from_hooks(&left, left_hooks, 3u) != 0) {
        return 1;
    }
    if (build_registry_from_hooks(&right, right_hooks, 3u) != 0) {
        return 1;
    }
    return expect_compare_fail(&left, &right);
}

static int test_negative_missing_hook(void)
{
    const char *const left_hooks[] = {k_hook_a, k_hook_b, k_hook_c};
    const char *const right_hooks[] = {k_hook_a, k_hook_b};
    ninlil_hook_registry_t left;
    ninlil_hook_registry_t right;

    if (build_registry_from_hooks(&left, left_hooks, 3u) != 0) {
        return 1;
    }
    if (build_registry_from_hooks(&right, right_hooks, 2u) != 0) {
        return 1;
    }
    return expect_compare_fail(&left, &right);
}

static int test_repository_check(const char *repo_root)
{
    size_t count = 0;

    if (ninlil_hook_run_repository_check(repo_root, &count, stderr) != 0) {
        fprintf(stderr, "repository hook registry check failed\n");
        return 1;
    }
    if (count != NINLIL_HOOK_REGISTRY_EXPECTED_COUNT) {
        fprintf(stderr, "unexpected hook registry count: %zu\n", count);
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

    if (test_negative_duplicate() != 0) {
        return 1;
    }
    if (test_negative_invalid_name() != 0) {
        return 1;
    }
    if (test_negative_missing_heading() != 0) {
        return 1;
    }
    if (test_negative_missing_block() != 0) {
        return 1;
    }
    if (test_negative_heading_substring() != 0) {
        return 1;
    }
    if (test_negative_wrong_heading_level() != 0) {
        return 1;
    }
    if (test_negative_duplicate_heading() != 0) {
        return 1;
    }
    if (test_negative_next_section_block_borrowing() != 0) {
        return 1;
    }
    if (test_negative_overlong_next_heading_block_borrowing() != 0) {
        return 1;
    }
    if (test_negative_overlong_hook_name() != 0) {
        return 1;
    }
    if (test_negative_order_swap() != 0) {
        return 1;
    }
    if (test_negative_missing_hook() != 0) {
        return 1;
    }
    if (test_repository_check(argv[1]) != 0) {
        return 1;
    }
    return 0;
}
