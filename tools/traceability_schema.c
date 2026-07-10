#include "traceability_schema.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIELD_ID ((uint32_t)1u << 0)
#define FIELD_TITLE ((uint32_t)1u << 1)
#define FIELD_SOURCE ((uint32_t)1u << 2)
#define FIELD_HEADING ((uint32_t)1u << 3)
#define FIELD_OWNER ((uint32_t)1u << 4)
#define FIELD_PROFILE ((uint32_t)1u << 5)
#define FIELD_GATE ((uint32_t)1u << 6)
#define FIELD_STATUS ((uint32_t)1u << 7)
#define FIELD_TESTS ((uint32_t)1u << 8)
#define FIELD_GAP ((uint32_t)1u << 9)
#define ALL_FIELDS ((uint32_t)0x3ffu)
#define MAX_KNOWN_TESTS 256u
#define MAX_REPOSITORY_PATH 1024u

typedef struct line_view {
    const char *start;
    size_t len;
} line_view_t;

typedef struct line_reader {
    const char *content;
    size_t length;
    size_t cursor;
    size_t next_line;
} line_reader_t;

typedef struct traceability_entry {
    char id[NINLIL_TRACEABILITY_MAX_ID_LEN];
    char title[NINLIL_TRACEABILITY_MAX_TITLE_LEN];
    char source[NINLIL_TRACEABILITY_MAX_PATH_LEN];
    char heading[NINLIL_TRACEABILITY_MAX_HEADING_LEN];
    char owner[16];
    char profile[48];
    char gate[16];
    ninlil_traceability_status_t status;
    char tests[NINLIL_TRACEABILITY_MAX_TESTS_PER_ENTRY]
              [NINLIL_TRACEABILITY_MAX_TEST_ID_LEN];
    size_t test_count;
    char gap[NINLIL_TRACEABILITY_MAX_GAP_LEN];
    size_t line_number;
    uint32_t fields;
} traceability_entry_t;

typedef struct traceability_manifest {
    traceability_entry_t entries[NINLIL_TRACEABILITY_MAX_ENTRIES];
    size_t count;
} traceability_manifest_t;

typedef struct test_registry {
    char ids[MAX_KNOWN_TESTS][NINLIL_TRACEABILITY_MAX_TEST_ID_LEN];
    size_t count;
} test_registry_t;

typedef struct repository_resolver {
    const char *root;
} repository_resolver_t;

static int ascii_space(unsigned char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
        || ch == '\v';
}

static int ascii_digit(unsigned char ch)
{
    return ch >= '0' && ch <= '9';
}

static int ascii_upper(unsigned char ch)
{
    return ch >= 'A' && ch <= 'Z';
}

static int ascii_lower(unsigned char ch)
{
    return ch >= 'a' && ch <= 'z';
}

static int set_error(char *out, size_t out_size, const char *message)
{
    if (out != NULL && out_size > 0u) {
        snprintf(out, out_size, "%s", message);
    }
    return -1;
}

static int valid_utf8(const char *text, size_t length)
{
    size_t index = 0u;

    while (index < length) {
        unsigned char a = (unsigned char)text[index];
        if (a <= 0x7fu) {
            if (a < 0x20u && a != '\n' && a != '\r' && a != '\t') {
                return 0;
            }
            ++index;
        } else if (a >= 0xc2u && a <= 0xdfu) {
            if (index + 1u >= length
                || ((unsigned char)text[index + 1u] & 0xc0u) != 0x80u) {
                return 0;
            }
            index += 2u;
        } else if (a >= 0xe0u && a <= 0xefu) {
            unsigned char b;
            unsigned char c;
            if (index + 2u >= length) {
                return 0;
            }
            b = (unsigned char)text[index + 1u];
            c = (unsigned char)text[index + 2u];
            if ((b & 0xc0u) != 0x80u || (c & 0xc0u) != 0x80u
                || (a == 0xe0u && b < 0xa0u) || (a == 0xedu && b >= 0xa0u)) {
                return 0;
            }
            index += 3u;
        } else if (a >= 0xf0u && a <= 0xf4u) {
            unsigned char b;
            unsigned char c;
            unsigned char d;
            if (index + 3u >= length) {
                return 0;
            }
            b = (unsigned char)text[index + 1u];
            c = (unsigned char)text[index + 2u];
            d = (unsigned char)text[index + 3u];
            if ((b & 0xc0u) != 0x80u || (c & 0xc0u) != 0x80u
                || (d & 0xc0u) != 0x80u || (a == 0xf0u && b < 0x90u)
                || (a == 0xf4u && b >= 0x90u)) {
                return 0;
            }
            index += 4u;
        } else {
            return 0;
        }
    }
    return 1;
}

static int next_line(line_reader_t *reader, line_view_t *view, size_t *line_number)
{
    size_t start;

    if (reader->cursor >= reader->length) {
        return 0;
    }
    start = reader->cursor;
    *line_number = reader->next_line;
    while (reader->cursor < reader->length && reader->content[reader->cursor] != '\n'
           && reader->content[reader->cursor] != '\r') {
        ++reader->cursor;
    }
    view->start = reader->content + start;
    view->len = reader->cursor - start;
    if (reader->cursor < reader->length) {
        if (reader->content[reader->cursor] == '\r') {
            ++reader->cursor;
            if (reader->cursor < reader->length && reader->content[reader->cursor] == '\n') {
                ++reader->cursor;
            }
        } else {
            ++reader->cursor;
        }
        ++reader->next_line;
    }
    return 1;
}

static int view_equals(line_view_t view, const char *literal)
{
    size_t length = strlen(literal);
    return view.len == length && memcmp(view.start, literal, length) == 0;
}

static int view_prefix(line_view_t view, const char *prefix, line_view_t *value)
{
    size_t length = strlen(prefix);
    if (view.len < length || memcmp(view.start, prefix, length) != 0) {
        return 0;
    }
    value->start = view.start + length;
    value->len = view.len - length;
    return 1;
}

static int copy_view(
    line_view_t view,
    char *out,
    size_t out_size,
    const char *field,
    size_t line,
    char *error_out,
    size_t error_out_size)
{
    char message[NINLIL_TRACEABILITY_MAX_ERROR];
    if (view.len == 0u) {
        snprintf(message, sizeof(message), "empty %s at line %zu", field, line);
        return set_error(error_out, error_out_size, message);
    }
    if (view.len >= out_size) {
        snprintf(message, sizeof(message), "overlong %s at line %zu", field, line);
        return set_error(error_out, error_out_size, message);
    }
    memcpy(out, view.start, view.len);
    out[view.len] = '\0';
    return 0;
}

static int parse_quoted(
    line_view_t value,
    char *out,
    size_t out_size,
    int allow_empty,
    const char *field,
    size_t line,
    char *error_out,
    size_t error_out_size)
{
    line_view_t inner;
    size_t index;
    char message[NINLIL_TRACEABILITY_MAX_ERROR];

    if (value.len < 2u || value.start[0] != '"' || value.start[value.len - 1u] != '"') {
        snprintf(message, sizeof(message), "%s must be a quoted scalar at line %zu", field, line);
        return set_error(error_out, error_out_size, message);
    }
    inner.start = value.start + 1u;
    inner.len = value.len - 2u;
    if (!allow_empty && inner.len == 0u) {
        snprintf(message, sizeof(message), "empty %s at line %zu", field, line);
        return set_error(error_out, error_out_size, message);
    }
    for (index = 0u; index < inner.len; ++index) {
        unsigned char ch = (unsigned char)inner.start[index];
        if (ch == '"' || ch == '\\' || ch < 0x20u) {
            snprintf(message, sizeof(message), "unsupported quoted scalar syntax at line %zu", line);
            return set_error(error_out, error_out_size, message);
        }
    }
    if (inner.len >= out_size) {
        snprintf(message, sizeof(message), "overlong %s at line %zu", field, line);
        return set_error(error_out, error_out_size, message);
    }
    memcpy(out, inner.start, inner.len);
    out[inner.len] = '\0';
    return 0;
}

static int stable_id(const char *id)
{
    static const char prefix[] = "NIN-PR1-";
    size_t length = strlen(id);
    size_t index;
    size_t last_dash = 0u;

    if (strncmp(id, prefix, sizeof(prefix) - 1u) != 0 || length < sizeof(prefix) + 4u) {
        return 0;
    }
    for (index = sizeof(prefix) - 1u; index < length; ++index) {
        unsigned char ch = (unsigned char)id[index];
        if (ch == '-') {
            if (index == sizeof(prefix) - 1u || index == last_dash + 1u) {
                return 0;
            }
            last_dash = index;
        } else if (!ascii_upper(ch) && !ascii_digit(ch)) {
            return 0;
        }
    }
    if (last_dash == 0u || length - last_dash - 1u != 3u) {
        return 0;
    }
    for (index = last_dash + 1u; index < length; ++index) {
        if (!ascii_digit((unsigned char)id[index])) {
            return 0;
        }
    }
    return 1;
}

static int valid_test_id(const char *id)
{
    size_t index;
    if (id[0] == '\0' || (!ascii_upper((unsigned char)id[0])
                           && !ascii_lower((unsigned char)id[0]) && id[0] != '_')) {
        return 0;
    }
    for (index = 1u; id[index] != '\0'; ++index) {
        unsigned char ch = (unsigned char)id[index];
        if (!ascii_upper(ch) && !ascii_lower(ch) && !ascii_digit(ch) && ch != '_'
            && ch != '.' && ch != '+' && ch != '-') {
            return 0;
        }
    }
    return 1;
}

static int valid_source_path(const char *path)
{
    size_t index;
    size_t segment_start = 0u;
    size_t length = strlen(path);

    if (length == 0u || path[0] == '/' || path[length - 1u] == '/') {
        return 0;
    }
    for (index = 0u; index <= length; ++index) {
        unsigned char ch = (unsigned char)path[index];
        if (index == length || ch == '/') {
            size_t segment_length = index - segment_start;
            if (segment_length == 0u
                || (segment_length == 1u && path[segment_start] == '.')
                || (segment_length == 2u && path[segment_start] == '.'
                    && path[segment_start + 1u] == '.')) {
                return 0;
            }
            segment_start = index + 1u;
        } else if (!ascii_upper(ch) && !ascii_lower(ch) && !ascii_digit(ch) && ch != '_'
                   && ch != '-' && ch != '.') {
            return 0;
        }
    }
    return 1;
}

static int valid_markdown_atx_heading(const char *heading)
{
    size_t length = strlen(heading);
    size_t hashes = 0u;
    size_t index;
    int has_text = 0;

    while (hashes < length && heading[hashes] == '#') {
        ++hashes;
    }
    if (hashes == 0u || hashes > 6u || hashes >= length || heading[hashes] != ' '
        || hashes + 1u >= length || ascii_space((unsigned char)heading[hashes + 1u])
        || ascii_space((unsigned char)heading[length - 1u])) {
        return 0;
    }
    for (index = hashes + 1u; index < length; ++index) {
        if (heading[index] != '#' && !ascii_space((unsigned char)heading[index])) {
            has_text = 1;
            break;
        }
    }
    return has_text;
}

static int parse_tests(
    line_view_t value,
    traceability_entry_t *entry,
    size_t line,
    char *error_out,
    size_t error_out_size)
{
    size_t cursor;
    char message[NINLIL_TRACEABILITY_MAX_ERROR];

    if (value.len < 2u || value.start[0] != '[' || value.start[value.len - 1u] != ']') {
        snprintf(message, sizeof(message), "tests must be an inline sequence at line %zu", line);
        return set_error(error_out, error_out_size, message);
    }
    if (value.len == 2u) {
        return 0;
    }
    cursor = 1u;
    while (cursor < value.len - 1u) {
        size_t start;
        size_t end;
        line_view_t token;
        if (value.start[cursor] == ' ') {
            snprintf(message, sizeof(message), "unexpected test whitespace at line %zu", line);
            return set_error(error_out, error_out_size, message);
        }
        start = cursor;
        while (cursor < value.len - 1u && value.start[cursor] != ',') {
            ++cursor;
        }
        end = cursor;
        if (end > start && value.start[end - 1u] == ' ') {
            snprintf(message, sizeof(message), "unexpected test whitespace at line %zu", line);
            return set_error(error_out, error_out_size, message);
        }
        token.start = value.start + start;
        token.len = end - start;
        if (entry->test_count >= NINLIL_TRACEABILITY_MAX_TESTS_PER_ENTRY) {
            snprintf(message, sizeof(message), "too many tests at line %zu", line);
            return set_error(error_out, error_out_size, message);
        }
        if (copy_view(
                token,
                entry->tests[entry->test_count],
                sizeof(entry->tests[entry->test_count]),
                "test ID",
                line,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
        if (!valid_test_id(entry->tests[entry->test_count])) {
            snprintf(
                message,
                sizeof(message),
                "invalid test ID %s at line %zu",
                entry->tests[entry->test_count],
                line);
            return set_error(error_out, error_out_size, message);
        }
        ++entry->test_count;
        if (cursor < value.len - 1u) {
            if (cursor + 2u >= value.len || value.start[cursor + 1u] != ' '
                || value.start[cursor + 2u] == ' ' || value.start[cursor + 2u] == ']') {
                snprintf(message, sizeof(message), "tests require comma-space at line %zu", line);
                return set_error(error_out, error_out_size, message);
            }
            cursor += 2u;
        }
    }
    return 0;
}

static int set_field_seen(
    traceability_entry_t *entry,
    uint32_t field,
    const char *name,
    size_t line,
    char *error_out,
    size_t error_out_size)
{
    char message[NINLIL_TRACEABILITY_MAX_ERROR];
    if ((entry->fields & field) != 0u) {
        snprintf(message, sizeof(message), "duplicate field %s at line %zu", name, line);
        return set_error(error_out, error_out_size, message);
    }
    entry->fields |= field;
    return 0;
}

static int parse_entry_field(
    traceability_entry_t *entry,
    line_view_t line_view,
    size_t line,
    char *error_out,
    size_t error_out_size)
{
    line_view_t value;
    char message[NINLIL_TRACEABILITY_MAX_ERROR];

#define FIELD_PREFIX(name, bit, body)                                                        \
    if (view_prefix(line_view, "    " name ": ", &value)) {                               \
        if (set_field_seen(entry, bit, name, line, error_out, error_out_size) != 0) {        \
            return -1;                                                                       \
        }                                                                                    \
        body                                                                                 \
        return 0;                                                                            \
    }

    FIELD_PREFIX(
        "id",
        FIELD_ID,
        if (copy_view(value, entry->id, sizeof(entry->id), "id", line, error_out, error_out_size)
            != 0) return -1;)
    FIELD_PREFIX(
        "title",
        FIELD_TITLE,
        if (parse_quoted(value, entry->title, sizeof(entry->title), 0, "title", line, error_out,
                error_out_size)
            != 0) return -1;)
    FIELD_PREFIX(
        "source",
        FIELD_SOURCE,
        if (copy_view(value, entry->source, sizeof(entry->source), "source", line, error_out,
                error_out_size)
            != 0) return -1;)
    FIELD_PREFIX(
        "heading",
        FIELD_HEADING,
        if (parse_quoted(value, entry->heading, sizeof(entry->heading), 0, "heading", line,
                error_out, error_out_size)
            != 0) return -1;)
    FIELD_PREFIX(
        "owner",
        FIELD_OWNER,
        if (copy_view(value, entry->owner, sizeof(entry->owner), "owner", line, error_out,
                error_out_size)
            != 0) return -1;)
    FIELD_PREFIX(
        "profile",
        FIELD_PROFILE,
        if (copy_view(value, entry->profile, sizeof(entry->profile), "profile", line, error_out,
                error_out_size)
            != 0) return -1;)
    FIELD_PREFIX(
        "gate",
        FIELD_GATE,
        if (copy_view(value, entry->gate, sizeof(entry->gate), "gate", line, error_out,
                error_out_size)
            != 0) return -1;)
    FIELD_PREFIX(
        "status",
        FIELD_STATUS,
        if (view_equals(value, "verified")) entry->status = NINLIL_TRACEABILITY_VERIFIED;
        else if (view_equals(value, "partial")) entry->status = NINLIL_TRACEABILITY_PARTIAL;
        else if (view_equals(value, "planned")) entry->status = NINLIL_TRACEABILITY_PLANNED;
        else {
            snprintf(message, sizeof(message), "invalid status at line %zu", line);
            return set_error(error_out, error_out_size, message);
        })
    FIELD_PREFIX(
        "tests",
        FIELD_TESTS,
        if (parse_tests(value, entry, line, error_out, error_out_size) != 0) return -1;)
    FIELD_PREFIX(
        "gap",
        FIELD_GAP,
        if (parse_quoted(value, entry->gap, sizeof(entry->gap), 1, "gap", line, error_out,
                error_out_size)
            != 0) return -1;)

#undef FIELD_PREFIX

    snprintf(message, sizeof(message), "unknown or malformed field at line %zu", line);
    return set_error(error_out, error_out_size, message);
}

static int finalize_entry(
    traceability_entry_t *entry,
    const traceability_manifest_t *manifest,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    size_t test;
    char message[NINLIL_TRACEABILITY_MAX_ERROR];

    if (entry->fields != ALL_FIELDS) {
        snprintf(message, sizeof(message), "missing requirement field near line %zu", entry->line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (!stable_id(entry->id)) {
        snprintf(message, sizeof(message), "invalid stable requirement ID %s at line %zu", entry->id,
            entry->line_number);
        return set_error(error_out, error_out_size, message);
    }
    for (index = 0u; index < manifest->count; ++index) {
        if (strcmp(manifest->entries[index].id, entry->id) == 0) {
            snprintf(message, sizeof(message), "duplicate requirement ID %s at lines %zu and %zu",
                entry->id, manifest->entries[index].line_number, entry->line_number);
            return set_error(error_out, error_out_size, message);
        }
    }
    if (!valid_source_path(entry->source)) {
        snprintf(message, sizeof(message), "invalid source path %s at line %zu", entry->source,
            entry->line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (!valid_markdown_atx_heading(entry->heading)) {
        snprintf(message, sizeof(message), "invalid Markdown ATX heading in %s at line %zu",
            entry->id, entry->line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (strcmp(entry->owner, "PR1") != 0) {
        snprintf(message, sizeof(message), "invalid owner %s at line %zu", entry->owner,
            entry->line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (strcmp(entry->profile, "FOUNDATION_M1A_TEST") != 0) {
        snprintf(message, sizeof(message), "invalid profile %s at line %zu", entry->profile,
            entry->line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (strcmp(entry->gate, "PR1") != 0) {
        snprintf(message, sizeof(message), "invalid gate %s at line %zu", entry->gate,
            entry->line_number);
        return set_error(error_out, error_out_size, message);
    }
    for (test = 0u; test < entry->test_count; ++test) {
        size_t prior;
        for (prior = 0u; prior < test; ++prior) {
            if (strcmp(entry->tests[prior], entry->tests[test]) == 0) {
                snprintf(message, sizeof(message), "duplicate test ID %s in %s", entry->tests[test],
                    entry->id);
                return set_error(error_out, error_out_size, message);
            }
        }
    }
    if (entry->status == NINLIL_TRACEABILITY_VERIFIED
        && (entry->test_count == 0u || entry->gap[0] != '\0')) {
        snprintf(message, sizeof(message), "verified entry %s requires tests and an empty gap", entry->id);
        return set_error(error_out, error_out_size, message);
    }
    if (entry->status == NINLIL_TRACEABILITY_PARTIAL
        && (entry->test_count == 0u || entry->gap[0] == '\0')) {
        snprintf(message, sizeof(message), "partial entry %s requires tests and a non-empty gap", entry->id);
        return set_error(error_out, error_out_size, message);
    }
    if (entry->status == NINLIL_TRACEABILITY_PLANNED
        && (entry->test_count != 0u || entry->gap[0] == '\0')) {
        snprintf(message, sizeof(message), "planned entry %s requires zero tests and a non-empty gap", entry->id);
        return set_error(error_out, error_out_size, message);
    }
    return 0;
}

static int parse_manifest(
    const char *content,
    traceability_manifest_t *manifest,
    char *error_out,
    size_t error_out_size)
{
    static const char *top_lines[] = {
        "format: NINLIL_TRACEABILITY_V1",
        "schema_version: 1",
        "scope: PR1",
        "completion_target: PR3",
        "requirements:"};
    line_reader_t reader;
    line_view_t view;
    size_t line;
    size_t top_index = 0u;
    traceability_entry_t current;
    int have_current = 0;
    char message[NINLIL_TRACEABILITY_MAX_ERROR];

    memset(manifest, 0, sizeof(*manifest));
    memset(&current, 0, sizeof(current));
    if (!valid_utf8(content, strlen(content))) {
        return set_error(error_out, error_out_size, "manifest is not valid UTF-8");
    }
    reader.content = content;
    reader.length = strlen(content);
    reader.cursor = 0u;
    reader.next_line = 1u;
    while (next_line(&reader, &view, &line)) {
        line_view_t id_value;
        if (view.len >= NINLIL_TRACEABILITY_MAX_LINE_LEN) {
            snprintf(message, sizeof(message), "traceability line too long at line %zu", line);
            return set_error(error_out, error_out_size, message);
        }
        if (view.len == 0u) {
            continue;
        }
        if (top_index < sizeof(top_lines) / sizeof(top_lines[0])) {
            if (!view_equals(view, top_lines[top_index])) {
                snprintf(message, sizeof(message), "invalid top-level schema at line %zu", line);
                return set_error(error_out, error_out_size, message);
            }
            ++top_index;
            continue;
        }
        if (view_prefix(view, "  - id: ", &id_value)) {
            if (have_current != 0) {
                if (finalize_entry(&current, manifest, error_out, error_out_size) != 0) {
                    return -1;
                }
                manifest->entries[manifest->count++] = current;
            }
            if (manifest->count >= NINLIL_TRACEABILITY_MAX_ENTRIES) {
                return set_error(error_out, error_out_size, "too many traceability entries");
            }
            memset(&current, 0, sizeof(current));
            current.line_number = line;
            have_current = 1;
            current.fields = FIELD_ID;
            if (copy_view(id_value, current.id, sizeof(current.id), "id", line, error_out,
                    error_out_size)
                != 0) {
                return -1;
            }
            continue;
        }
        if (have_current == 0 || view.len < 4u || memcmp(view.start, "    ", 4u) != 0) {
            snprintf(message, sizeof(message), "malformed indentation at line %zu", line);
            return set_error(error_out, error_out_size, message);
        }
        if (parse_entry_field(&current, view, line, error_out, error_out_size) != 0) {
            return -1;
        }
    }
    if (top_index != sizeof(top_lines) / sizeof(top_lines[0])) {
        return set_error(error_out, error_out_size, "missing top-level traceability metadata");
    }
    if (have_current == 0) {
        return set_error(error_out, error_out_size, "traceability requirements must not be empty");
    }
    if (finalize_entry(&current, manifest, error_out, error_out_size) != 0) {
        return -1;
    }
    manifest->entries[manifest->count++] = current;
    return 0;
}

static int registry_contains(const test_registry_t *registry, const char *id)
{
    size_t index;
    for (index = 0u; index < registry->count; ++index) {
        if (strcmp(registry->ids[index], id) == 0) {
            return 1;
        }
    }
    return 0;
}

static int cmake_call_is_line_comment(const char *content, const char *call)
{
    const char *line = call;
    const char *cursor;
    int quoted = 0;

    while (line > content && line[-1] != '\n' && line[-1] != '\r') {
        --line;
    }
    for (cursor = line; cursor < call; ++cursor) {
        if (*cursor == '\\' && quoted != 0 && cursor + 1 < call) {
            ++cursor;
        } else if (*cursor == '"') {
            quoted = !quoted;
        } else if (*cursor == '#' && quoted == 0) {
            return 1;
        }
    }
    return 0;
}

static int parse_test_registry(
    const char *content,
    test_registry_t *registry,
    char *error_out,
    size_t error_out_size)
{
    const char *cursor = content;
    const char *end = content + strlen(content);
    char message[NINLIL_TRACEABILITY_MAX_ERROR];

    memset(registry, 0, sizeof(*registry));
    while (cursor < end) {
        const char *call = strstr(cursor, "add_test(");
        const char *close;
        const char *scan;
        if (call == NULL) {
            break;
        }
        if (cmake_call_is_line_comment(content, call)) {
            cursor = call + strlen("add_test(");
            continue;
        }
        close = strchr(call, ')');
        if (close == NULL) {
            return set_error(error_out, error_out_size, "unterminated add_test registration");
        }
        scan = call + strlen("add_test(");
        while (scan < close) {
            const char *token_start;
            size_t token_length;
            while (scan < close && ascii_space((unsigned char)*scan)) {
                ++scan;
            }
            token_start = scan;
            while (scan < close && !ascii_space((unsigned char)*scan)) {
                ++scan;
            }
            token_length = (size_t)(scan - token_start);
            if (token_length == 4u && memcmp(token_start, "NAME", 4u) == 0) {
                char id[NINLIL_TRACEABILITY_MAX_TEST_ID_LEN];
                while (scan < close && ascii_space((unsigned char)*scan)) {
                    ++scan;
                }
                token_start = scan;
                while (scan < close && !ascii_space((unsigned char)*scan)) {
                    ++scan;
                }
                token_length = (size_t)(scan - token_start);
                if (token_length > 0u && token_length < sizeof(id)) {
                    memcpy(id, token_start, token_length);
                    id[token_length] = '\0';
                    if (valid_test_id(id) && strchr(id, '$') == NULL) {
                        if (registry_contains(registry, id)) {
                            snprintf(message, sizeof(message), "duplicate literal CTest name %s", id);
                            return set_error(error_out, error_out_size, message);
                        }
                        if (registry->count >= MAX_KNOWN_TESTS) {
                            return set_error(error_out, error_out_size, "too many literal CTest names");
                        }
                        memcpy(registry->ids[registry->count], id, token_length + 1u);
                        ++registry->count;
                    }
                }
                break;
            }
        }
        cursor = close + 1u;
    }
    return 0;
}

static int validate_links(
    const traceability_manifest_t *manifest,
    const test_registry_t *registry,
    ninlil_traceability_heading_resolver_fn resolver,
    void *resolver_user,
    ninlil_traceability_result_t *result,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    char message[NINLIL_TRACEABILITY_MAX_ERROR];

    memset(result, 0, sizeof(*result));
    result->entries = manifest->count;
    for (index = 0u; index < manifest->count; ++index) {
        const traceability_entry_t *entry = &manifest->entries[index];
        size_t test;
        size_t count = 0u;
        size_t first = 0u;
        size_t second = 0u;
        char resolver_error[NINLIL_TRACEABILITY_MAX_ERROR];

        for (test = 0u; test < entry->test_count; ++test) {
            if (!registry_contains(registry, entry->tests[test])) {
                snprintf(message, sizeof(message), "unknown CTest ID %s in %s", entry->tests[test],
                    entry->id);
                return set_error(error_out, error_out_size, message);
            }
        }
        if (resolver(resolver_user, entry->source, entry->heading, &count, &first, &second,
                resolver_error, sizeof(resolver_error))
            != 0) {
            snprintf(message, sizeof(message), "source resolution failed for %s: %s", entry->id,
                resolver_error);
            return set_error(error_out, error_out_size, message);
        }
        if (count == 0u) {
            snprintf(message, sizeof(message), "heading not found for %s in %s: %s", entry->id,
                entry->source, entry->heading);
            return set_error(error_out, error_out_size, message);
        }
        if (count != 1u) {
            snprintf(message, sizeof(message), "duplicate heading for %s in %s at lines %zu and %zu",
                entry->id, entry->source, first, second);
            return set_error(error_out, error_out_size, message);
        }
        result->test_links += entry->test_count;
        if (entry->status == NINLIL_TRACEABILITY_VERIFIED) {
            ++result->verified;
        } else if (entry->status == NINLIL_TRACEABILITY_PARTIAL) {
            ++result->partial;
        } else {
            ++result->planned;
        }
    }
    return 0;
}

int ninlil_traceability_check_content(
    const char *manifest_content,
    const char *cmake_content,
    ninlil_traceability_heading_resolver_fn heading_resolver,
    void *resolver_user,
    ninlil_traceability_result_t *out_result,
    char *error_out,
    size_t error_out_size)
{
    traceability_manifest_t manifest;
    test_registry_t registry;
    ninlil_traceability_result_t result;

    if (out_result != NULL) {
        memset(out_result, 0, sizeof(*out_result));
    }
    if (manifest_content == NULL || cmake_content == NULL || heading_resolver == NULL) {
        return set_error(error_out, error_out_size, "invalid traceability checker arguments");
    }
    if (parse_manifest(manifest_content, &manifest, error_out, error_out_size) != 0
        || parse_test_registry(cmake_content, &registry, error_out, error_out_size) != 0
        || validate_links(&manifest, &registry, heading_resolver, resolver_user, &result, error_out,
               error_out_size)
            != 0) {
        return -1;
    }
    if (out_result != NULL) {
        *out_result = result;
    }
    return 0;
}

static char *read_file(const char *path, char *error_out, size_t error_out_size)
{
    FILE *file = fopen(path, "rb");
    long size;
    char *content;
    size_t read_size;
    if (file == NULL) {
        char message[NINLIL_TRACEABILITY_MAX_ERROR];
        snprintf(message, sizeof(message), "cannot open %s", path);
        set_error(error_out, error_out_size, message);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0
        || fseek(file, 0, SEEK_SET) != 0 || (uintmax_t)size > (uintmax_t)SIZE_MAX - 1u) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot size traceability input file");
        return NULL;
    }
    content = (char *)malloc((size_t)size + 1u);
    if (content == NULL) {
        fclose(file);
        set_error(error_out, error_out_size, "out of memory reading traceability input");
        return NULL;
    }
    read_size = fread(content, 1u, (size_t)size, file);
    fclose(file);
    if (read_size != (size_t)size) {
        free(content);
        set_error(error_out, error_out_size, "short read on traceability input");
        return NULL;
    }
    content[read_size] = '\0';
    return content;
}

static int repository_heading_resolver(
    void *user,
    const char *source_path,
    const char *heading,
    size_t *out_count,
    size_t *out_first_line,
    size_t *out_second_line,
    char *error_out,
    size_t error_out_size)
{
    const repository_resolver_t *resolver = (const repository_resolver_t *)user;
    char path[MAX_REPOSITORY_PATH];
    char *content;
    line_reader_t reader;
    line_view_t view;
    size_t line;
    int written = snprintf(path, sizeof(path), "%s/%s", resolver->root, source_path);

    *out_count = 0u;
    *out_first_line = 0u;
    *out_second_line = 0u;
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return set_error(error_out, error_out_size, "resolved source path is too long");
    }
    content = read_file(path, error_out, error_out_size);
    if (content == NULL) {
        return -1;
    }
    if (!valid_utf8(content, strlen(content))) {
        free(content);
        return set_error(error_out, error_out_size, "source file is not valid UTF-8");
    }
    reader.content = content;
    reader.length = strlen(content);
    reader.cursor = 0u;
    reader.next_line = 1u;
    while (next_line(&reader, &view, &line)) {
        if (view_equals(view, heading)) {
            ++(*out_count);
            if (*out_count == 1u) {
                *out_first_line = line;
            } else if (*out_count == 2u) {
                *out_second_line = line;
            }
        }
    }
    free(content);
    return 0;
}

int ninlil_traceability_run_repository_check(
    const char *repo_root,
    ninlil_traceability_result_t *out_result,
    FILE *error_stream)
{
    char manifest_path[MAX_REPOSITORY_PATH];
    char cmake_path[MAX_REPOSITORY_PATH];
    char error[NINLIL_TRACEABILITY_MAX_ERROR];
    char *manifest;
    char *cmake;
    repository_resolver_t resolver;
    int written_manifest;
    int written_cmake;
    int result;

    if (out_result != NULL) {
        memset(out_result, 0, sizeof(*out_result));
    }
    if (repo_root == NULL) {
        return -1;
    }
    written_manifest = snprintf(manifest_path, sizeof(manifest_path), "%s/%s", repo_root,
        NINLIL_TRACEABILITY_MANIFEST_PATH);
    written_cmake = snprintf(cmake_path, sizeof(cmake_path), "%s/CMakeLists.txt", repo_root);
    if (written_manifest < 0 || (size_t)written_manifest >= sizeof(manifest_path)
        || written_cmake < 0 || (size_t)written_cmake >= sizeof(cmake_path)) {
        if (error_stream != NULL) {
            fprintf(error_stream, "traceability path is too long\n");
        }
        return -1;
    }
    manifest = read_file(manifest_path, error, sizeof(error));
    if (manifest == NULL) {
        if (error_stream != NULL) fprintf(error_stream, "traceability read error: %s\n", error);
        return -1;
    }
    cmake = read_file(cmake_path, error, sizeof(error));
    if (cmake == NULL) {
        free(manifest);
        if (error_stream != NULL) fprintf(error_stream, "traceability read error: %s\n", error);
        return -1;
    }
    resolver.root = repo_root;
    result = ninlil_traceability_check_content(manifest, cmake, repository_heading_resolver,
        &resolver, out_result, error, sizeof(error));
    free(cmake);
    free(manifest);
    if (result != 0 && error_stream != NULL) {
        fprintf(error_stream, "traceability check error: %s\n", error);
    }
    return result;
}
