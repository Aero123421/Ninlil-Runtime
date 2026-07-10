#include "hook_registry_schema.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int set_error(char *error_out, size_t error_out_size, const char *message)
{
    if (error_out != NULL && error_out_size > 0u) {
        snprintf(error_out, error_out_size, "%s", message);
    }
    return -1;
}

static void trim_trailing(char *line)
{
    size_t length;

    if (line == NULL) {
        return;
    }
    length = strlen(line);
    while (length > 0u && (line[length - 1u] == '\n' || line[length - 1u] == '\r'
                           || isspace((unsigned char)line[length - 1u]))) {
        line[--length] = '\0';
    }
}

static void trim_both(char *line)
{
    size_t start = 0;
    size_t length;

    if (line == NULL) {
        return;
    }
    trim_trailing(line);
    length = strlen(line);
    while (start < length && isspace((unsigned char)line[start])) {
        ++start;
    }
    if (start > 0u) {
        memmove(line, line + start, length - start + 1u);
    }
}

static int registry_contains(const ninlil_hook_registry_t *registry, const char *hook_name)
{
    size_t i;

    for (i = 0; i < registry->count; ++i) {
        if (strcmp(registry->hooks[i], hook_name) == 0) {
            return 1;
        }
    }
    return 0;
}

int ninlil_hook_registry_is_valid_hook_name(const char *name)
{
    const char *dot;
    const char *suffix;
    size_t role_len;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }

    dot = strchr(name, '.');
    if (dot == NULL || strchr(dot + 1, '.') != NULL) {
        return 0;
    }

    role_len = (size_t)(dot - name);
    if (role_len == 7u && strncmp(name, "runtime", 7) == 0) {
        /* ok */
    } else if (role_len == 10u && strncmp(name, "controller", 10) == 0) {
        /* ok */
    } else if (role_len == 8u && strncmp(name, "endpoint", 8) == 0) {
        /* ok */
    } else {
        return 0;
    }

    suffix = dot + 1;
    if (suffix[0] == '\0') {
        return 0;
    }

    for (; *suffix != '\0'; ++suffix) {
        unsigned char ch = (unsigned char)*suffix;
        if (!((ch >= 'a' && ch <= 'z') || ch == '_')) {
            return 0;
        }
    }

    return 1;
}

typedef struct {
    const char *start;
    size_t len;
} line_view_t;

static line_view_t line_view_trim_trailing(line_view_t view)
{
    while (view.len > 0u) {
        unsigned char ch = (unsigned char)view.start[view.len - 1u];
        if (ch != '\n' && ch != '\r' && !isspace(ch)) {
            break;
        }
        --view.len;
    }
    return view;
}

static int line_view_equals_cstr(line_view_t view, const char *expected)
{
    size_t expected_len;

    if (expected == NULL) {
        return 0;
    }
    view = line_view_trim_trailing(view);
    expected_len = strlen(expected);
    if (view.len != expected_len) {
        return 0;
    }
    return memcmp(view.start, expected, expected_len) == 0;
}

static int line_view_heading_level(line_view_t view)
{
    size_t i = 0;

    view = line_view_trim_trailing(view);
    while (i < view.len && view.start[i] == '#') {
        ++i;
    }
    if (i == 0u || i >= view.len || view.start[i] != ' ') {
        return 0;
    }
    return (int)i;
}

static int read_next_line_view(
    const char *content,
    size_t *cursor,
    size_t content_length,
    line_view_t *out_view)
{
    size_t start;

    if (content == NULL || cursor == NULL || out_view == NULL) {
        return 0;
    }

    while (*cursor < content_length
           && (content[*cursor] == '\n' || content[*cursor] == '\r')) {
        ++(*cursor);
    }
    if (*cursor >= content_length) {
        return 0;
    }

    start = *cursor;
    while (*cursor < content_length && content[*cursor] != '\n' && content[*cursor] != '\r') {
        ++(*cursor);
    }

    out_view->start = content + start;
    out_view->len = *cursor - start;
    return 1;
}

static int line_view_copy_trimmed(line_view_t view, char *line, size_t line_size)
{
    line_view_t trimmed;

    trimmed = line_view_trim_trailing(view);
    if (trimmed.len >= line_size) {
        return -1;
    }
    memcpy(line, trimmed.start, trimmed.len);
    line[trimmed.len] = '\0';
    return 0;
}

static int append_hook(
    ninlil_hook_registry_t *registry,
    const char *hook_name,
    char *error_out,
    size_t error_out_size)
{
    if (!ninlil_hook_registry_is_valid_hook_name(hook_name)) {
        char message[NINLIL_HOOK_REGISTRY_MAX_ERROR];
        snprintf(message, sizeof(message), "invalid hook name: %s", hook_name);
        return set_error(error_out, error_out_size, message);
    }
    if (strlen(hook_name) >= NINLIL_HOOK_REGISTRY_MAX_HOOK_NAME_LEN) {
        char message[NINLIL_HOOK_REGISTRY_MAX_ERROR];
        snprintf(message, sizeof(message), "hook name too long: %s", hook_name);
        return set_error(error_out, error_out_size, message);
    }
    if (registry_contains(registry, hook_name)) {
        char message[NINLIL_HOOK_REGISTRY_MAX_ERROR];
        snprintf(message, sizeof(message), "duplicate hook name: %s", hook_name);
        return set_error(error_out, error_out_size, message);
    }
    if (registry->count >= NINLIL_HOOK_REGISTRY_MAX_HOOKS) {
        return set_error(error_out, error_out_size, "hook registry exceeds maximum capacity");
    }
    snprintf(
        registry->hooks[registry->count],
        sizeof(registry->hooks[registry->count]),
        "%s",
        hook_name);
    registry->count += 1u;
    return 0;
}

static int parse_code_block_line(
    const char *line,
    ninlil_hook_registry_t *registry,
    char *error_out,
    size_t error_out_size)
{
    char trimmed[NINLIL_HOOK_REGISTRY_MAX_LINE_LEN];

    snprintf(trimmed, sizeof(trimmed), "%s", line);
    trim_both(trimmed);
    if (trimmed[0] == '\0') {
        return 0;
    }
    if (trimmed[0] == '#') {
        return 0;
    }
    return append_hook(registry, trimmed, error_out, error_out_size);
}

static int count_exact_heading_lines(
    const char *content,
    const char *heading,
    char *error_out,
    size_t error_out_size)
{
    size_t cursor = 0u;
    size_t content_length;
    line_view_t view;
    int count = 0;

    (void)error_out;
    (void)error_out_size;

    content_length = strlen(content);
    while (read_next_line_view(content, &cursor, content_length, &view) != 0) {
        if (line_view_equals_cstr(view, heading)) {
            ++count;
        }
    }
    return count;
}

int ninlil_hook_registry_parse_markdown_content(
    const char *content,
    const char *heading,
    ninlil_hook_registry_t *out_registry,
    char *error_out,
    size_t error_out_size)
{
    size_t cursor = 0u;
    size_t content_length;
    char line[NINLIL_HOOK_REGISTRY_MAX_LINE_LEN];
    line_view_t view;
    int heading_count;
    int section_heading_level = 0;
    int in_target_section = 0;
    int in_code_block = 0;

    if (content == NULL || heading == NULL || out_registry == NULL) {
        return set_error(error_out, error_out_size, "invalid hook registry parse arguments");
    }

    memset(out_registry, 0, sizeof(*out_registry));

    heading_count = count_exact_heading_lines(content, heading, error_out, error_out_size);
    if (heading_count < 0) {
        return -1;
    }
    if (heading_count == 0) {
        return set_error(error_out, error_out_size, "hook registry heading not found");
    }
    if (heading_count > 1) {
        return set_error(error_out, error_out_size, "hook registry heading is ambiguous");
    }

    content_length = strlen(content);
    while (read_next_line_view(content, &cursor, content_length, &view) != 0) {
        int line_level;

        if (!in_target_section) {
            if (line_view_equals_cstr(view, heading)) {
                section_heading_level = line_view_heading_level(view);
                if (section_heading_level <= 0) {
                    return set_error(error_out, error_out_size, "hook registry heading level is invalid");
                }
                in_target_section = 1;
            }
            continue;
        }

        if (!in_code_block) {
            line_level = line_view_heading_level(view);
            if (line_level > 0 && line_level <= section_heading_level) {
                return set_error(error_out, error_out_size, "hook registry ```text block not found");
            }
            if (line_view_equals_cstr(view, "```text")) {
                in_code_block = 1;
            }
            continue;
        }

        if (line_view_copy_trimmed(view, line, sizeof(line)) != 0) {
            return set_error(error_out, error_out_size, "hook registry line too long");
        }
        if (strcmp(line, "```") == 0) {
            return 0;
        }
        if (parse_code_block_line(line, out_registry, error_out, error_out_size) != 0) {
            return -1;
        }
    }

    if (!in_target_section) {
        return set_error(error_out, error_out_size, "hook registry heading not found");
    }
    if (in_code_block) {
        return set_error(error_out, error_out_size, "hook registry ```text block not closed");
    }
    return set_error(error_out, error_out_size, "hook registry ```text block not found");
}

static char *read_file_contents(const char *path, char *error_out, size_t error_out_size)
{
    FILE *file;
    char *buffer;
    long file_size;
    size_t read_size;

    file = fopen(path, "rb");
    if (file == NULL) {
        char message[NINLIL_HOOK_REGISTRY_MAX_ERROR];
        snprintf(message, sizeof(message), "cannot open %s", path);
        set_error(error_out, error_out_size, message);
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot seek hook registry markdown file");
        return NULL;
    }
    file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot size hook registry markdown file");
        return NULL;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot rewind hook registry markdown file");
        return NULL;
    }

    buffer = (char *)malloc((size_t)file_size + 1u);
    if (buffer == NULL) {
        fclose(file);
        set_error(error_out, error_out_size, "out of memory reading hook registry markdown file");
        return NULL;
    }

    read_size = fread(buffer, 1u, (size_t)file_size, file);
    fclose(file);
    if (read_size != (size_t)file_size) {
        free(buffer);
        set_error(error_out, error_out_size, "short read on hook registry markdown file");
        return NULL;
    }
    buffer[read_size] = '\0';
    return buffer;
}

int ninlil_hook_registry_parse_markdown_file(
    const char *path,
    const char *heading,
    ninlil_hook_registry_t *out_registry,
    char *error_out,
    size_t error_out_size)
{
    char *content;
    int result;

    content = read_file_contents(path, error_out, error_out_size);
    if (content == NULL) {
        return -1;
    }
    result = ninlil_hook_registry_parse_markdown_content(
        content,
        heading,
        out_registry,
        error_out,
        error_out_size);
    free(content);
    return result;
}

int ninlil_hook_registry_validate(
    const ninlil_hook_registry_t *registry,
    char *error_out,
    size_t error_out_size)
{
    size_t i;
    size_t j;

    if (registry == NULL) {
        return set_error(error_out, error_out_size, "hook registry is null");
    }
    if (registry->count != NINLIL_HOOK_REGISTRY_EXPECTED_COUNT) {
        char message[NINLIL_HOOK_REGISTRY_MAX_ERROR];
        snprintf(
            message,
            sizeof(message),
            "hook registry count mismatch: expected %u, got %zu",
            NINLIL_HOOK_REGISTRY_EXPECTED_COUNT,
            registry->count);
        return set_error(error_out, error_out_size, message);
    }

    for (i = 0; i < registry->count; ++i) {
        if (!ninlil_hook_registry_is_valid_hook_name(registry->hooks[i])) {
            char message[NINLIL_HOOK_REGISTRY_MAX_ERROR];
            snprintf(message, sizeof(message), "invalid hook name at index %zu: %s", i, registry->hooks[i]);
            return set_error(error_out, error_out_size, message);
        }
        for (j = i + 1u; j < registry->count; ++j) {
            if (strcmp(registry->hooks[i], registry->hooks[j]) == 0) {
                char message[NINLIL_HOOK_REGISTRY_MAX_ERROR];
                snprintf(message, sizeof(message), "duplicate hook name: %s", registry->hooks[i]);
                return set_error(error_out, error_out_size, message);
            }
        }
    }

    return 0;
}

int ninlil_hook_registry_compare_ordered(
    const ninlil_hook_registry_t *left,
    const ninlil_hook_registry_t *right,
    const char *left_label,
    const char *right_label,
    FILE *error_stream)
{
    size_t i;
    size_t max_count;

    if (left == NULL || right == NULL) {
        if (error_stream != NULL) {
            fprintf(error_stream, "hook registry compare error: null registry\n");
        }
        return -1;
    }

    if (left->count != right->count) {
        if (error_stream != NULL) {
            fprintf(
                error_stream,
                "hook registry count mismatch between %s (%zu) and %s (%zu)\n",
                left_label != NULL ? left_label : "left",
                left->count,
                right_label != NULL ? right_label : "right",
                right->count);
        }
        return -1;
    }

    max_count = left->count;
    for (i = 0; i < max_count; ++i) {
        if (strcmp(left->hooks[i], right->hooks[i]) != 0) {
            if (error_stream != NULL) {
                fprintf(
                    error_stream,
                    "hook registry order mismatch at index %zu: %s has %s, %s has %s\n",
                    i,
                    left_label != NULL ? left_label : "left",
                    left->hooks[i],
                    right_label != NULL ? right_label : "right",
                    right->hooks[i]);
            }
            return -1;
        }
    }

    return 0;
}

int ninlil_hook_run_repository_check(const char *repo_root, size_t *out_count, FILE *error_stream)
{
    char ch12_path[NINLIL_HOOK_REGISTRY_MAX_PATH_LEN];
    char ch14_path[NINLIL_HOOK_REGISTRY_MAX_PATH_LEN];
    ninlil_hook_registry_t ch12_registry;
    ninlil_hook_registry_t ch14_registry;
    char error[NINLIL_HOOK_REGISTRY_MAX_ERROR];

    if (repo_root == NULL) {
        if (error_stream != NULL) {
            fprintf(error_stream, "hook registry check error: repo_root is null\n");
        }
        return -1;
    }

    snprintf(ch12_path, sizeof(ch12_path), "%s/%s", repo_root, NINLIL_HOOK_REGISTRY_CH12_PATH);
    snprintf(ch14_path, sizeof(ch14_path), "%s/%s", repo_root, NINLIL_HOOK_REGISTRY_CH14_PATH);

    if (ninlil_hook_registry_parse_markdown_file(
            ch12_path,
            NINLIL_HOOK_REGISTRY_CH12_HEADING,
            &ch12_registry,
            error,
            sizeof(error))
        != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "hook registry ch12 parse error: %s\n", error);
        }
        return -1;
    }
    if (ninlil_hook_registry_validate(&ch12_registry, error, sizeof(error)) != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "hook registry ch12 validation error: %s\n", error);
        }
        return -1;
    }

    if (ninlil_hook_registry_parse_markdown_file(
            ch14_path,
            NINLIL_HOOK_REGISTRY_CH14_HEADING,
            &ch14_registry,
            error,
            sizeof(error))
        != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "hook registry ch14 parse error: %s\n", error);
        }
        return -1;
    }
    if (ninlil_hook_registry_validate(&ch14_registry, error, sizeof(error)) != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "hook registry ch14 validation error: %s\n", error);
        }
        return -1;
    }

    if (ninlil_hook_registry_compare_ordered(
            &ch12_registry,
            &ch14_registry,
            "ch12",
            "ch14",
            error_stream)
        != 0) {
        return -1;
    }

    if (out_count != NULL) {
        *out_count = ch12_registry.count;
    }
    return 0;
}
