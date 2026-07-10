#include "yaml_reason_schema.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NINLIL_REASON_EXPECTED_CODE_COUNT 54u
#define NINLIL_REASON_EXPECTED_ZERO_COUNT 9u
#define NINLIL_YAML_MAX_LINE_LEN 2048u
#define NINLIL_YAML_INDENT_TOP 0
#define NINLIL_YAML_INDENT_LIST 2
#define NINLIL_YAML_INDENT_CODE_FIELD 4

#define NINLIL_NORMATIVE_SOURCE "../docs/12-foundation-abi.md#44-reason-code"
#define NINLIL_OPERATOR_PROJECTION "../docs/11-operator-model.md#共通operator-state"

static const char *const k_expected_generated_zero[NINLIL_REASON_EXPECTED_ZERO_COUNT] = {
    "NINLIL_REASON_UNSUPPORTED_FAMILY",
    "NINLIL_REASON_UNSUPPORTED_SELECTOR",
    "NINLIL_REASON_INVALID_CONTENT_DIGEST",
    "NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID",
    "NINLIL_REASON_MODIFICATION_REQUIRED",
    "NINLIL_REASON_EVENT_RECEIPT_TIMEOUT",
    "NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT",
    "NINLIL_REASON_BEARER_UNAVAILABLE",
    "NINLIL_REASON_CAPACITY_UNAVAILABLE",
};

typedef struct yaml_parser {
    char **lines;
    size_t line_count;
    size_t line_capacity;
    size_t index;
    char error[512];
} yaml_parser_t;

static void set_error(yaml_parser_t *parser, const char *message)
{
    snprintf(parser->error, sizeof(parser->error), "%s", message);
}

static void report_parse_error(
    const char *message,
    char *error_out,
    size_t error_out_size)
{
    if (error_out != NULL && error_out_size > 0u) {
        snprintf(error_out, error_out_size, "%s", message);
    }
    fprintf(stderr, "reason YAML parse error: %s\n", message);
}

static char *ninlil_dup_string(const char *src, size_t length)
{
    char *copy;

    copy = (char *)malloc(length + 1u);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, src, length);
    copy[length] = '\0';
    return copy;
}

static void trim_trailing(char *line)
{
    size_t end;

    end = strlen(line);
    while (end > 0u
           && (line[end - 1u] == ' '
               || line[end - 1u] == '\t'
               || line[end - 1u] == '\r'
               || line[end - 1u] == '\n')) {
        --end;
    }
    line[end] = '\0';
}

static void strip_comment(char *line)
{
    char in_single = 0;
    char in_double = 0;
    size_t i;

    for (i = 0; line[i] != '\0'; ++i) {
        if (!in_single && !in_double && line[i] == '#') {
            if (i == 0u || isspace((unsigned char)line[i - 1u])) {
                line[i] = '\0';
                break;
            }
        }
        if (line[i] == '\'' && !in_double) {
            in_single = (char)!in_single;
        } else if (line[i] == '"' && !in_single) {
            in_double = (char)!in_double;
        }
    }
}

static int line_indent(const char *line, int *out_indent)
{
    int indent = 0;

    while (line[indent] == ' ') {
        ++indent;
    }
    if (line[indent] == '\t') {
        return -1;
    }
    *out_indent = indent;
    return 0;
}

static int require_indent(yaml_parser_t *parser, const char *line, int expected_indent)
{
    int indent = 0;

    if (line_indent(line, &indent) != 0) {
        set_error(parser, "tabs are not allowed in reason registry YAML");
        return -1;
    }
    if (indent != expected_indent) {
        set_error(parser, "unexpected indentation");
        return -1;
    }
    return 0;
}

static int copy_scalar_strict(
    yaml_parser_t *parser,
    const char *src,
    char *dst,
    size_t dst_size)
{
    size_t length;

    if (src == NULL || src[0] == '\0') {
        set_error(parser, "empty scalar value");
        return -1;
    }
    length = strlen(src);
    if (length >= dst_size) {
        set_error(parser, "scalar value too long");
        return -1;
    }
    memcpy(dst, src, length + 1u);
    return 0;
}

static int parse_strict_u32(yaml_parser_t *parser, const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || text[0] == '\0') {
        set_error(parser, "empty unsigned integer");
        return -1;
    }
    if (text[0] == '-' || text[0] == '+') {
        set_error(parser, "signed unsigned integer");
        return -1;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno == ERANGE) {
        set_error(parser, "unsigned integer out of range");
        return -1;
    }
    if (end == text || (end != NULL && *end != '\0')) {
        set_error(parser, "invalid unsigned integer");
        return -1;
    }
    if (value > (unsigned long)UINT32_MAX) {
        set_error(parser, "unsigned integer exceeds uint32");
        return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

static int push_line(yaml_parser_t *parser, char *line)
{
    char **grown;

    if (parser->line_count + 1u > parser->line_capacity) {
        size_t new_capacity = parser->line_capacity == 0u ? 64u : parser->line_capacity * 2u;
        grown = (char **)realloc(parser->lines, new_capacity * sizeof(char *));
        if (grown == NULL) {
            set_error(parser, "out of memory");
            return -1;
        }
        parser->lines = grown;
        parser->line_capacity = new_capacity;
    }

    parser->lines[parser->line_count++] = line;
    return 0;
}

static int ingest_line(yaml_parser_t *parser, char *line, int saw_newline)
{
    if (!saw_newline && strlen(line) >= (NINLIL_YAML_MAX_LINE_LEN - 1u)) {
        set_error(parser, "line too long");
        free(line);
        return -1;
    }
    if (strchr(line, '\t') != NULL) {
        set_error(parser, "tabs are not allowed in reason registry YAML");
        free(line);
        return -1;
    }
    strip_comment(line);
    trim_trailing(line);
    if (line[0] == '\0') {
        free(line);
        return 0;
    }
    if (push_line(parser, line) != 0) {
        free(line);
        return -1;
    }
    return 0;
}

static int load_lines_from_file(const char *path, yaml_parser_t *parser)
{
    FILE *file;
    char buffer[NINLIL_YAML_MAX_LINE_LEN];

    file = fopen(path, "rb");
    if (file == NULL) {
        snprintf(parser->error, sizeof(parser->error), "cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    parser->lines = NULL;
    parser->line_count = 0;
    parser->line_capacity = 0;
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        size_t length = strlen(buffer);
        char *copy;
        int saw_newline = (length > 0u && buffer[length - 1u] == '\n');

        copy = ninlil_dup_string(buffer, length);
        if (copy == NULL) {
            set_error(parser, "out of memory");
            fclose(file);
            return -1;
        }
        if (ingest_line(parser, copy, saw_newline) != 0) {
            fclose(file);
            return -1;
        }
    }
    if (ferror(file) != 0) {
        set_error(parser, "failed to read YAML");
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

static int load_lines_from_content(const char *content, yaml_parser_t *parser)
{
    const char *cursor = content;

    parser->lines = NULL;
    parser->line_count = 0;
    parser->line_capacity = 0;
    while (cursor != NULL && *cursor != '\0') {
        const char *newline = strchr(cursor, '\n');
        size_t length = newline != NULL ? (size_t)(newline - cursor) : strlen(cursor);
        char *copy;
        int saw_newline = newline != NULL;

        if (length >= NINLIL_YAML_MAX_LINE_LEN) {
            set_error(parser, "line too long");
            return -1;
        }
        copy = ninlil_dup_string(cursor, length);
        if (copy == NULL) {
            set_error(parser, "out of memory");
            return -1;
        }
        if (ingest_line(parser, copy, saw_newline) != 0) {
            return -1;
        }
        cursor = newline != NULL ? newline + 1 : cursor + length;
    }
    return 0;
}

static void free_lines(yaml_parser_t *parser)
{
    size_t i;

    for (i = 0; i < parser->line_count; ++i) {
        free(parser->lines[i]);
    }
    free(parser->lines);
    parser->lines = NULL;
    parser->line_count = 0;
    parser->line_capacity = 0;
}

static const char *current_line(const yaml_parser_t *parser)
{
    if (parser->index >= parser->line_count) {
        return NULL;
    }
    return parser->lines[parser->index];
}

static int expect_line(yaml_parser_t *parser)
{
    if (parser->index >= parser->line_count) {
        set_error(parser, "unexpected end of YAML");
        return -1;
    }
    return 0;
}

static int parse_top_level_exact(yaml_parser_t *parser, const char *expected_line)
{
    if (expect_line(parser) != 0) {
        return -1;
    }
    if (strcmp(current_line(parser), expected_line) != 0) {
        snprintf(parser->error, sizeof(parser->error), "expected %s", expected_line);
        return -1;
    }
    if (require_indent(parser, current_line(parser), NINLIL_YAML_INDENT_TOP) != 0) {
        return -1;
    }
    ++parser->index;
    return 0;
}

static int parse_top_level_scalar(
    yaml_parser_t *parser,
    const char *key,
    char *out,
    size_t out_size)
{
    const char *line;
    size_t key_len;
    const char *value;

    if (expect_line(parser) != 0) {
        return -1;
    }
    line = current_line(parser);
    if (require_indent(parser, line, NINLIL_YAML_INDENT_TOP) != 0) {
        return -1;
    }
    key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != ':') {
        snprintf(parser->error, sizeof(parser->error), "expected key %s", key);
        return -1;
    }
    value = line + key_len + 1u;
    while (*value == ' ') {
        ++value;
    }
    if (copy_scalar_strict(parser, value, out, out_size) != 0) {
        return -1;
    }
    ++parser->index;
    return 0;
}

static int parse_top_level_u32(yaml_parser_t *parser, const char *key, uint32_t *out)
{
    const char *line;
    size_t key_len;
    const char *value;

    if (expect_line(parser) != 0) {
        return -1;
    }
    line = current_line(parser);
    if (require_indent(parser, line, NINLIL_YAML_INDENT_TOP) != 0) {
        return -1;
    }
    key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != ':') {
        snprintf(parser->error, sizeof(parser->error), "expected key %s", key);
        return -1;
    }
    value = line + key_len + 1u;
    while (*value == ' ') {
        ++value;
    }
    if (parse_strict_u32(parser, value, out) != 0) {
        return -1;
    }
    ++parser->index;
    return 0;
}

static int parse_list_u32_items(
    yaml_parser_t *parser,
    uint32_t *entries,
    size_t max_entries,
    size_t *out_count)
{
    *out_count = 0;
    while (parser->index < parser->line_count) {
        const char *line = current_line(parser);
        const char *value;
        int indent = 0;

        if (line_indent(line, &indent) != 0) {
            set_error(parser, "tabs are not allowed in reason registry YAML");
            return -1;
        }
        if (indent != NINLIL_YAML_INDENT_LIST) {
            break;
        }
        if (strncmp(line + indent, "- ", 2) != 0) {
            set_error(parser, "expected list item");
            return -1;
        }
        if (*out_count >= max_entries) {
            set_error(parser, "list too long");
            return -1;
        }
        value = line + indent + 2u;
        while (*value == ' ') {
            ++value;
        }
        if (parse_strict_u32(parser, value, &entries[*out_count]) != 0) {
            return -1;
        }
        ++*out_count;
        ++parser->index;
    }
    return 0;
}

static int parse_list_string_items(
    yaml_parser_t *parser,
    char entries[][NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN],
    size_t max_entries,
    size_t *out_count)
{
    *out_count = 0;
    while (parser->index < parser->line_count) {
        const char *line = current_line(parser);
        const char *value;
        int indent = 0;

        if (line_indent(line, &indent) != 0) {
            set_error(parser, "tabs are not allowed in reason registry YAML");
            return -1;
        }
        if (indent != NINLIL_YAML_INDENT_LIST) {
            break;
        }
        if (strncmp(line + indent, "- ", 2) != 0) {
            set_error(parser, "expected list item");
            return -1;
        }
        if (*out_count >= max_entries) {
            set_error(parser, "list too long");
            return -1;
        }
        value = line + indent + 2u;
        while (*value == ' ') {
            ++value;
        }
        if (copy_scalar_strict(
                parser,
                value,
                entries[*out_count],
                NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN)
            != 0) {
            return -1;
        }
        ++*out_count;
        ++parser->index;
    }
    return 0;
}

static int parse_code_field_scalar(
    yaml_parser_t *parser,
    const char *key,
    char *out,
    size_t out_size)
{
    const char *line;
    size_t key_len;
    const char *value;

    if (expect_line(parser) != 0) {
        return -1;
    }
    line = current_line(parser);
    if (require_indent(parser, line, NINLIL_YAML_INDENT_CODE_FIELD) != 0) {
        return -1;
    }
    key_len = strlen(key);
    if (strncmp(line + NINLIL_YAML_INDENT_CODE_FIELD, key, key_len) != 0
        || line[NINLIL_YAML_INDENT_CODE_FIELD + key_len] != ':') {
        snprintf(parser->error, sizeof(parser->error), "expected code field %s", key);
        return -1;
    }
    value = line + NINLIL_YAML_INDENT_CODE_FIELD + key_len + 1u;
    while (*value == ' ') {
        ++value;
    }
    if (copy_scalar_strict(parser, value, out, out_size) != 0) {
        return -1;
    }
    ++parser->index;
    return 0;
}

static int parse_code_field_u32(yaml_parser_t *parser, const char *key, uint32_t *out)
{
    const char *line;
    size_t key_len;
    const char *value;

    if (expect_line(parser) != 0) {
        return -1;
    }
    line = current_line(parser);
    if (require_indent(parser, line, NINLIL_YAML_INDENT_CODE_FIELD) != 0) {
        return -1;
    }
    key_len = strlen(key);
    if (strncmp(line + NINLIL_YAML_INDENT_CODE_FIELD, key, key_len) != 0
        || line[NINLIL_YAML_INDENT_CODE_FIELD + key_len] != ':') {
        snprintf(parser->error, sizeof(parser->error), "expected code field %s", key);
        return -1;
    }
    value = line + NINLIL_YAML_INDENT_CODE_FIELD + key_len + 1u;
    while (*value == ' ') {
        ++value;
    }
    if (parse_strict_u32(parser, value, out) != 0) {
        return -1;
    }
    ++parser->index;
    return 0;
}

static int parse_code_block(yaml_parser_t *parser, ninlil_reason_code_entry_t *entry)
{
    const char *line;
    const char *symbol_value;

    memset(entry, 0, sizeof(*entry));
    if (expect_line(parser) != 0) {
        return -1;
    }
    line = current_line(parser);
    if (require_indent(parser, line, NINLIL_YAML_INDENT_LIST) != 0) {
        return -1;
    }
    if (strncmp(line + NINLIL_YAML_INDENT_LIST, "- symbol:", 9) != 0) {
        set_error(parser, "expected code list item");
        return -1;
    }
    symbol_value = line + NINLIL_YAML_INDENT_LIST + 9u;
    while (*symbol_value == ' ') {
        ++symbol_value;
    }
    if (copy_scalar_strict(
            parser,
            symbol_value,
            entry->symbol,
            sizeof(entry->symbol))
        != 0) {
        return -1;
    }
    ++parser->index;

    if (parse_code_field_u32(parser, "value", &entry->value) != 0) {
        return -1;
    }
    if (parse_code_field_scalar(parser, "milestone", entry->milestone, sizeof(entry->milestone)) != 0) {
        return -1;
    }
    if (parse_code_field_scalar(parser, "category", entry->category, sizeof(entry->category)) != 0) {
        return -1;
    }
    if (parse_code_field_scalar(
            parser,
            "default_retry_guidance",
            entry->default_retry_guidance,
            sizeof(entry->default_retry_guidance))
        != 0) {
        return -1;
    }
    if (parse_code_field_scalar(
            parser,
            "operator_state_hint",
            entry->operator_state_hint,
            sizeof(entry->operator_state_hint))
        != 0) {
        return -1;
    }
    return 0;
}

static int parse_reason_registry(yaml_parser_t *parser, ninlil_reason_registry_yaml_t *out_registry)
{
    memset(out_registry, 0, sizeof(*out_registry));

    if (parse_top_level_u32(parser, "schema_version", &out_registry->schema_version) != 0
        || parse_top_level_scalar(parser, "registry", out_registry->registry, sizeof(out_registry->registry))
               != 0
        || parse_top_level_scalar(
               parser,
               "integer_type",
               out_registry->integer_type,
               sizeof(out_registry->integer_type))
               != 0
        || parse_top_level_scalar(
               parser,
               "normative_source",
               out_registry->normative_source,
               sizeof(out_registry->normative_source))
               != 0
        || parse_top_level_scalar(
               parser,
               "operator_projection_contract",
               out_registry->operator_projection_contract,
               sizeof(out_registry->operator_projection_contract))
               != 0) {
        return -1;
    }

    if (parse_top_level_exact(parser, "reserved_values:") != 0) {
        return -1;
    }
    if (parse_list_u32_items(
            parser,
            out_registry->reserved_values,
            NINLIL_REASON_REGISTRY_MAX_RESERVED,
            &out_registry->reserved_value_count)
        != 0) {
        return -1;
    }

    if (parse_top_level_exact(parser, "m1a_public_generated_zero:") != 0) {
        return -1;
    }
    if (parse_list_string_items(
            parser,
            out_registry->m1a_public_generated_zero,
            NINLIL_REASON_REGISTRY_MAX_ZERO_SYMBOLS,
            &out_registry->m1a_public_generated_zero_count)
        != 0) {
        return -1;
    }

    if (parse_top_level_exact(parser, "codes:") != 0) {
        return -1;
    }

    while (parser->index < parser->line_count) {
        if (out_registry->code_count >= NINLIL_REASON_REGISTRY_MAX_CODES) {
            set_error(parser, "too many codes");
            return -1;
        }
        if (parse_code_block(parser, &out_registry->codes[out_registry->code_count]) != 0) {
            return -1;
        }
        ++out_registry->code_count;
    }

    return 0;
}

static int parse_registry_document(
    yaml_parser_t *parser,
    ninlil_reason_registry_yaml_t *out_registry,
    char *error_out,
    size_t error_out_size)
{
    if (parse_reason_registry(parser, out_registry) != 0) {
        report_parse_error(parser->error, error_out, error_out_size);
        return -1;
    }
    if (ninlil_validate_reason_registry(out_registry) != 0) {
        return -1;
    }
    return 0;
}

int ninlil_parse_reason_registry_yaml_content_ex(
    const char *content,
    ninlil_reason_registry_yaml_t *out_registry,
    char *error_out,
    size_t error_out_size)
{
    yaml_parser_t parser;
    int result;

    memset(&parser, 0, sizeof(parser));
    if (error_out != NULL && error_out_size > 0u) {
        error_out[0] = '\0';
    }
    if (load_lines_from_content(content, &parser) != 0) {
        report_parse_error(parser.error, error_out, error_out_size);
        result = -1;
    } else {
        result = parse_registry_document(&parser, out_registry, error_out, error_out_size);
    }
    free_lines(&parser);
    return result;
}

int ninlil_parse_reason_registry_yaml_content(
    const char *content,
    ninlil_reason_registry_yaml_t *out_registry)
{
    return ninlil_parse_reason_registry_yaml_content_ex(content, out_registry, NULL, 0u);
}

int ninlil_parse_reason_registry_yaml(
    const char *path,
    ninlil_reason_registry_yaml_t *out_registry)
{
    yaml_parser_t parser;
    int result;

    memset(&parser, 0, sizeof(parser));
    if (load_lines_from_file(path, &parser) != 0) {
        report_parse_error(parser.error, NULL, 0u);
        result = -1;
    } else {
        result = parse_registry_document(&parser, out_registry, NULL, 0u);
    }
    free_lines(&parser);
    return result;
}

int ninlil_validate_reason_registry(const ninlil_reason_registry_yaml_t *out_registry)
{
    size_t i;

    if (out_registry->schema_version != 1u) {
        fprintf(stderr, "reason YAML validation error: schema_version must be 1\n");
        return -1;
    }
    if (strcmp(out_registry->registry, "ninlil-foundation-reason-codes") != 0) {
        fprintf(stderr, "reason YAML validation error: unexpected registry id\n");
        return -1;
    }
    if (strcmp(out_registry->integer_type, "uint32") != 0) {
        fprintf(stderr, "reason YAML validation error: integer_type must be uint32\n");
        return -1;
    }
    if (strcmp(out_registry->normative_source, NINLIL_NORMATIVE_SOURCE) != 0) {
        fprintf(stderr, "reason YAML validation error: normative_source mismatch\n");
        return -1;
    }
    if (strcmp(out_registry->operator_projection_contract, NINLIL_OPERATOR_PROJECTION) != 0) {
        fprintf(stderr, "reason YAML validation error: operator_projection_contract mismatch\n");
        return -1;
    }
    if (out_registry->code_count != NINLIL_REASON_EXPECTED_CODE_COUNT) {
        fprintf(
            stderr,
            "reason YAML validation error: expected %u codes, found %zu\n",
            NINLIL_REASON_EXPECTED_CODE_COUNT,
            out_registry->code_count);
        return -1;
    }
    if (out_registry->m1a_public_generated_zero_count != NINLIL_REASON_EXPECTED_ZERO_COUNT) {
        fprintf(
            stderr,
            "reason YAML validation error: expected %u generated-zero symbols\n",
            NINLIL_REASON_EXPECTED_ZERO_COUNT);
        return -1;
    }

    for (i = 0; i < NINLIL_REASON_EXPECTED_ZERO_COUNT; ++i) {
        size_t j;
        int found = 0;
        for (j = 0; j < out_registry->m1a_public_generated_zero_count; ++j) {
            if (strcmp(out_registry->m1a_public_generated_zero[j], k_expected_generated_zero[i]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(
                stderr,
                "reason YAML validation error: missing generated-zero symbol %s\n",
                k_expected_generated_zero[i]);
            return -1;
        }
    }

    for (i = 0; i < out_registry->code_count; ++i) {
        size_t j;
        if (out_registry->codes[i].operator_state_hint[0] == '\0') {
            fprintf(
                stderr,
                "reason YAML validation error: empty operator_state_hint for %s\n",
                out_registry->codes[i].symbol);
            return -1;
        }
        for (j = i + 1; j < out_registry->code_count; ++j) {
            if (strcmp(out_registry->codes[i].symbol, out_registry->codes[j].symbol) == 0) {
                fprintf(
                    stderr,
                    "reason YAML validation error: duplicate symbol %s\n",
                    out_registry->codes[i].symbol);
                return -1;
            }
            if (out_registry->codes[i].value == out_registry->codes[j].value) {
                fprintf(
                    stderr,
                    "reason YAML validation error: duplicate value %u\n",
                    out_registry->codes[i].value);
                return -1;
            }
        }
    }

    for (i = 0; i < out_registry->reserved_value_count; ++i) {
        size_t j;
        for (j = 0; j < out_registry->code_count; ++j) {
            if (out_registry->codes[j].value == out_registry->reserved_values[i]) {
                fprintf(
                    stderr,
                    "reason YAML validation error: reserved value %u used by %s\n",
                    out_registry->reserved_values[i],
                    out_registry->codes[j].symbol);
                return -1;
            }
        }
    }

    return 0;
}

static void append_slug_char(char *slug, size_t slug_size, char ch)
{
    size_t len = strlen(slug);
    if (len + 2u >= slug_size) {
        return;
    }
    if (len > 0u && slug[len - 1u] == '-' && ch == '-') {
        return;
    }
    slug[len] = ch;
    slug[len + 1u] = '\0';
}

static void heading_to_slug(const char *heading, char *slug, size_t slug_size)
{
    size_t i;
    int last_was_space = 0;

    slug[0] = '\0';
    for (i = 0; heading[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)heading[i];
        if (ch == '#') {
            continue;
        }
        if (isspace(ch)) {
            if (slug[0] != '\0') {
                append_slug_char(slug, slug_size, '-');
                last_was_space = 1;
            }
            continue;
        }
        if (ch == '.' || ch == ':' || ch == ',' || ch == '(' || ch == ')') {
            continue;
        }
        if (isalnum(ch)) {
            append_slug_char(slug, slug_size, (char)tolower(ch));
            last_was_space = 0;
            continue;
        }
        if ((ch & 0x80u) != 0u) {
            append_slug_char(slug, slug_size, (char)ch);
            last_was_space = 0;
            continue;
        }
        (void)last_was_space;
    }
    while (slug[0] != '\0' && slug[strlen(slug) - 1u] == '-') {
        slug[strlen(slug) - 1u] = '\0';
    }
}

int ninlil_markdown_anchor_exists(const char *markdown_path, const char *anchor)
{
    FILE *file;
    char line[512];
    char slug[256];

    file = fopen(markdown_path, "rb");
    if (file == NULL) {
        fprintf(stderr, "anchor check error: cannot open %s\n", markdown_path);
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        trim_trailing(line);
        if (line[0] != '#') {
            continue;
        }
        heading_to_slug(line, slug, sizeof(slug));
        if (strcmp(slug, anchor) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    fprintf(stderr, "anchor check error: anchor %s not found in %s\n", anchor, markdown_path);
    return 0;
}

int ninlil_scan_header_reason_codes(
    const char *path,
    ninlil_header_reason_table_t *out_table)
{
    FILE *file;
    char line[512];

    memset(out_table, 0, sizeof(*out_table));
    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "header scan error: cannot open %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char symbol[NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN];
        unsigned int value = 0;
        int matched = sscanf(
            line,
            "#define %95s ((ninlil_reason_t)%u",
            symbol,
            &value);
        if (matched == 2 && strncmp(symbol, "NINLIL_REASON_", 14) == 0) {
            if (out_table->count >= NINLIL_REASON_REGISTRY_MAX_CODES) {
                fclose(file);
                fprintf(stderr, "header scan error: too many reason symbols\n");
                return -1;
            }
            if (strlen(symbol) >= NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN) {
                fclose(file);
                fprintf(stderr, "header scan error: reason symbol too long\n");
                return -1;
            }
            memcpy(
                out_table->entries[out_table->count].symbol,
                symbol,
                strlen(symbol) + 1u);
            out_table->entries[out_table->count].value = value;
            ++out_table->count;
        }
    }

    fclose(file);
    return 0;
}

int ninlil_validate_reason_registry_links(const char *repo_root)
{
    char path[NINLIL_REASON_REGISTRY_MAX_PATH_LEN];

    snprintf(path, sizeof(path), "%s/docs/12-foundation-abi.md", repo_root);
    if (!ninlil_markdown_anchor_exists(path, "44-reason-code")) {
        return -1;
    }
    snprintf(path, sizeof(path), "%s/docs/11-operator-model.md", repo_root);
    if (!ninlil_markdown_anchor_exists(path, "共通operator-state")) {
        return -1;
    }
    return 0;
}

int ninlil_compare_header_yaml(
    const ninlil_reason_registry_yaml_t *yaml_registry,
    const ninlil_header_reason_table_t *header_table)
{
    size_t i;

    if (header_table->count != yaml_registry->code_count) {
        fprintf(
            stderr,
            "reason drift error: header has %zu reason symbols, YAML has %zu\n",
            header_table->count,
            yaml_registry->code_count);
        return -1;
    }

    for (i = 0; i < yaml_registry->code_count; ++i) {
        size_t j;
        int found = 0;
        for (j = 0; j < header_table->count; ++j) {
            if (strcmp(yaml_registry->codes[i].symbol, header_table->entries[j].symbol) == 0) {
                if (yaml_registry->codes[i].value != header_table->entries[j].value) {
                    fprintf(
                        stderr,
                        "reason drift error: value mismatch for %s (yaml=%u header=%u)\n",
                        yaml_registry->codes[i].symbol,
                        yaml_registry->codes[i].value,
                        header_table->entries[j].value);
                    return -1;
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(
                stderr,
                "reason drift error: YAML symbol %s missing from header\n",
                yaml_registry->codes[i].symbol);
            return -1;
        }
    }

    for (i = 0; i < header_table->count; ++i) {
        size_t j;
        int found = 0;
        for (j = 0; j < yaml_registry->code_count; ++j) {
            if (strcmp(header_table->entries[i].symbol, yaml_registry->codes[j].symbol) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(
                stderr,
                "reason drift error: header symbol %s missing from YAML\n",
                header_table->entries[i].symbol);
            return -1;
        }
    }

    return 0;
}

int ninlil_emit_reason_registry_artifact(
    const ninlil_reason_registry_yaml_t *registry,
    FILE *out)
{
    size_t i;

    fprintf(out, "reason_registry_format_version=1\n");
    fprintf(out, "schema_version=%u\n", registry->schema_version);
    fprintf(out, "registry=%s\n", registry->registry);
    fprintf(out, "integer_type=%s\n", registry->integer_type);
    fprintf(out, "normative_source=%s\n", registry->normative_source);
    fprintf(out, "operator_projection_contract=%s\n", registry->operator_projection_contract);

    for (i = 0; i < registry->reserved_value_count; ++i) {
        fprintf(out, "reserved_value=%u\n", registry->reserved_values[i]);
    }
    for (i = 0; i < registry->m1a_public_generated_zero_count; ++i) {
        fprintf(out, "generated_zero=%s\n", registry->m1a_public_generated_zero[i]);
    }
    for (i = 0; i < registry->code_count; ++i) {
        const ninlil_reason_code_entry_t *code = &registry->codes[i];
        fprintf(
            out,
            "code symbol=%s value=%u milestone=%s category=%s default_retry_guidance=%s operator_state_hint=%s\n",
            code->symbol,
            code->value,
            code->milestone,
            code->category,
            code->default_retry_guidance,
            code->operator_state_hint);
    }
    return ferror(out) ? -1 : 0;
}

static int trim_line_in_place(char *line)
{
    trim_trailing(line);
    return 0;
}

static int read_trimmed_line(FILE *stream, char *line, size_t line_size, int *out_eof)
{
    if (fgets(line, (int)line_size, stream) == NULL) {
        *out_eof = feof(stream) != 0;
        return *out_eof ? 0 : -1;
    }
    trim_line_in_place(line);
    *out_eof = 0;
    return 0;
}

int ninlil_compare_reason_artifact_streams(FILE *expected, FILE *actual)
{
    char expected_line[4096];
    char actual_line[4096];
    size_t line_no = 0;
    int expected_eof = 0;
    int actual_eof = 0;

    while (read_trimmed_line(expected, expected_line, sizeof(expected_line), &expected_eof) == 0
           && !expected_eof) {
        ++line_no;
        if (read_trimmed_line(actual, actual_line, sizeof(actual_line), &actual_eof) != 0
            || actual_eof) {
            fprintf(stderr, "artifact drift error: actual artifact too short at line %zu\n", line_no);
            return -1;
        }
        if (strcmp(expected_line, actual_line) != 0) {
            fprintf(
                stderr,
                "artifact drift error at line %zu:\n  expected: %s\n  actual:   %s\n",
                line_no,
                expected_line,
                actual_line);
            return -1;
        }
    }
    if (read_trimmed_line(actual, actual_line, sizeof(actual_line), &actual_eof) != 0) {
        return -1;
    }
    if (!actual_eof) {
        fprintf(stderr, "artifact drift error: actual artifact has extra lines\n");
        return -1;
    }
    return 0;
}
