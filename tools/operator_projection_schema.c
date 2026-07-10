#include "operator_projection_schema.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DOCUMENT_LINES 512u
#define MAX_DOCUMENT_LINE_LEN 2048u
#define MAX_OPERATOR_CODES 64u
#define MAX_OPERATOR_CODE_LEN 64u
#define MAX_REPOSITORY_PATH 1024u
#define MAX_TABLE_CELLS 8u

typedef struct line_view {
    const char *start;
    size_t len;
    size_t line_number;
} line_view_t;

typedef struct document_lines {
    line_view_t lines[MAX_DOCUMENT_LINES];
    size_t count;
} document_lines_t;

typedef struct section_range {
    size_t heading_index;
    size_t begin;
    size_t end;
} section_range_t;

typedef struct operator_code {
    char value[MAX_OPERATOR_CODE_LEN];
    size_t line_number;
} operator_code_t;

typedef struct projection_context {
    operator_code_t states[MAX_OPERATOR_CODES];
    size_t state_count;
    operator_code_t references[MAX_OPERATOR_CODES];
    size_t reference_count;
    size_t context_rows;
} projection_context_t;

static int ascii_space(unsigned char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
        || ch == '\v';
}

static int ascii_upper(unsigned char ch)
{
    return ch >= 'A' && ch <= 'Z';
}

static int ascii_digit(unsigned char ch)
{
    return ch >= '0' && ch <= '9';
}

static int set_error(char *error_out, size_t error_out_size, const char *message)
{
    if (error_out != NULL && error_out_size > 0u) {
        snprintf(error_out, error_out_size, "%s", message);
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

static line_view_t trim_both(line_view_t view)
{
    size_t leading = 0u;
    while (leading < view.len && ascii_space((unsigned char)view.start[leading])) {
        ++leading;
    }
    view.start += leading;
    view.len -= leading;
    while (view.len > 0u && ascii_space((unsigned char)view.start[view.len - 1u])) {
        --view.len;
    }
    return view;
}

static int view_equals(line_view_t view, const char *text)
{
    size_t length = strlen(text);
    return view.len == length && memcmp(view.start, text, length) == 0;
}

static int markdown_heading_level(line_view_t view)
{
    size_t hashes = 0u;
    while (hashes < view.len && view.start[hashes] == '#') {
        ++hashes;
    }
    if (hashes == 0u || hashes > 6u || hashes >= view.len || view.start[hashes] != ' '
        || hashes + 1u >= view.len || ascii_space((unsigned char)view.start[hashes + 1u])
        || ascii_space((unsigned char)view.start[view.len - 1u])) {
        return 0;
    }
    return (int)hashes;
}

static void append_slug_byte(char *slug, size_t slug_size, unsigned char value)
{
    size_t length = strlen(slug);
    if (length + 1u < slug_size) {
        slug[length] = (char)value;
        slug[length + 1u] = '\0';
    }
}

static void heading_slug(line_view_t view, char *slug, size_t slug_size)
{
    size_t index = 0u;
    int pending_dash = 0;
    slug[0] = '\0';
    while (index < view.len && view.start[index] == '#') {
        ++index;
    }
    if (index < view.len && view.start[index] == ' ') {
        ++index;
    }
    for (; index < view.len; ++index) {
        unsigned char ch = (unsigned char)view.start[index];
        if (ascii_space(ch)) {
            if (slug[0] != '\0') {
                pending_dash = 1;
            }
        } else if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                   || ascii_digit(ch) || ch == '_' || ch == '-' || ch >= 0x80u) {
            if (pending_dash != 0 && slug[strlen(slug) - 1u] != '-') {
                append_slug_byte(slug, slug_size, (unsigned char)'-');
            }
            if (ch >= 'A' && ch <= 'Z') {
                ch = (unsigned char)(ch - 'A' + 'a');
            }
            if (ch != '-' || slug[0] == '\0' || slug[strlen(slug) - 1u] != '-') {
                append_slug_byte(slug, slug_size, ch);
            }
            pending_dash = 0;
        }
    }
}

static int parse_lines(
    const char *content,
    size_t length,
    document_lines_t *document,
    char *error_out,
    size_t error_out_size)
{
    size_t cursor = 0u;
    size_t line_number = 1u;

    if (content == NULL || document == NULL) {
        return set_error(error_out, error_out_size, "invalid operator projection input");
    }
    if (memchr(content, '\0', length) != NULL) {
        return set_error(error_out, error_out_size, "operator model contains embedded NUL");
    }
    if (!valid_utf8(content, length)) {
        return set_error(error_out, error_out_size, "operator model is not valid UTF-8");
    }
    memset(document, 0, sizeof(*document));
    while (cursor < length) {
        size_t start = cursor;
        if (document->count >= MAX_DOCUMENT_LINES) {
            return set_error(error_out, error_out_size, "operator model has too many lines");
        }
        while (cursor < length && content[cursor] != '\n' && content[cursor] != '\r') {
            ++cursor;
        }
        document->lines[document->count].start = content + start;
        document->lines[document->count].len = cursor - start;
        document->lines[document->count].line_number = line_number;
        if (document->lines[document->count].len >= MAX_DOCUMENT_LINE_LEN) {
            char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
            snprintf(message, sizeof(message), "operator model line too long at line %zu", line_number);
            return set_error(error_out, error_out_size, message);
        }
        ++document->count;
        if (cursor < length && content[cursor] == '\r') {
            ++cursor;
            if (cursor < length && content[cursor] == '\n') {
                ++cursor;
            }
        } else if (cursor < length) {
            ++cursor;
        }
        ++line_number;
    }
    return 0;
}

static int find_section(
    const document_lines_t *document,
    const char *heading,
    section_range_t *out_section,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    size_t match = 0u;
    size_t count = 0u;
    size_t second_line = 0u;
    int level;
    line_view_t expected_view;
    char expected_slug[256];
    char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];

    expected_view.start = heading;
    expected_view.len = strlen(heading);
    expected_view.line_number = 0u;
    heading_slug(expected_view, expected_slug, sizeof(expected_slug));
    for (index = 0u; index < document->count; ++index) {
        char slug[256];
        if (markdown_heading_level(document->lines[index]) == 0) {
            continue;
        }
        heading_slug(document->lines[index], slug, sizeof(slug));
        if (strcmp(slug, expected_slug) == 0) {
            if (count == 0u) {
                match = index;
            } else if (count == 1u) {
                second_line = document->lines[index].line_number;
            }
            ++count;
        }
    }
    if (count == 0u) {
        snprintf(message, sizeof(message), "missing exact heading %s", heading);
        return set_error(error_out, error_out_size, message);
    }
    if (count != 1u) {
        snprintf(message, sizeof(message), "ambiguous heading %s at lines %zu and %zu", heading,
            document->lines[match].line_number, second_line);
        return set_error(error_out, error_out_size, message);
    }
    if (!view_equals(document->lines[match], heading)) {
        snprintf(message, sizeof(message), "wrong heading form for %s at line %zu", heading,
            document->lines[match].line_number);
        return set_error(error_out, error_out_size, message);
    }
    level = markdown_heading_level(document->lines[match]);
    if (level == 0) {
        snprintf(message, sizeof(message), "invalid exact heading %s", heading);
        return set_error(error_out, error_out_size, message);
    }
    out_section->heading_index = match;
    out_section->begin = match + 1u;
    out_section->end = document->count;
    for (index = match + 1u; index < document->count; ++index) {
        int next_level = markdown_heading_level(document->lines[index]);
        if (next_level > 0 && next_level <= level) {
            out_section->end = index;
            break;
        }
    }
    return 0;
}

static size_t split_table_cells(line_view_t view, line_view_t *cells, size_t capacity)
{
    size_t count = 0u;
    size_t start = 1u;
    size_t index;

    view = trim_both(view);
    if (view.len < 3u || view.start[0] != '|' || view.start[view.len - 1u] != '|') {
        return 0u;
    }
    for (index = 1u; index < view.len; ++index) {
        if (view.start[index] == '|') {
            if (count >= capacity) {
                return capacity + 1u;
            }
            cells[count].start = view.start + start;
            cells[count].len = index - start;
            cells[count].line_number = view.line_number;
            cells[count] = trim_both(cells[count]);
            ++count;
            start = index + 1u;
        }
    }
    return count;
}

static int table_separator(line_view_t view, size_t expected_cells)
{
    line_view_t cells[MAX_TABLE_CELLS];
    size_t count = split_table_cells(view, cells, MAX_TABLE_CELLS);
    size_t index;
    if (count != expected_cells) {
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        size_t ch;
        size_t dashes = 0u;
        for (ch = 0u; ch < cells[index].len; ++ch) {
            if (cells[index].start[ch] == '-') {
                ++dashes;
            } else if (cells[index].start[ch] != ':') {
                return 0;
            }
        }
        if (dashes < 3u) {
            return 0;
        }
    }
    return 1;
}

static int header_cells_equal(
    line_view_t view,
    const char *const *expected,
    size_t expected_count)
{
    line_view_t cells[MAX_TABLE_CELLS];
    size_t count = split_table_cells(view, cells, MAX_TABLE_CELLS);
    size_t index;
    if (count != expected_count) {
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        if (!view_equals(cells[index], expected[index])) {
            return 0;
        }
    }
    return 1;
}

static int find_table(
    const document_lines_t *document,
    const section_range_t *section,
    const char *const *headers,
    size_t header_count,
    size_t *out_header_index,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    size_t match = 0u;
    size_t count = 0u;
    size_t second_line = 0u;
    char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];

    for (index = section->begin; index < section->end; ++index) {
        if (header_cells_equal(document->lines[index], headers, header_count)) {
            if (count == 0u) {
                match = index;
            } else if (count == 1u) {
                second_line = document->lines[index].line_number;
            }
            ++count;
        }
    }
    if (count == 0u) {
        snprintf(message, sizeof(message), "missing projection table in section at line %zu",
            document->lines[section->heading_index].line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (count != 1u) {
        snprintf(message, sizeof(message), "ambiguous projection table at lines %zu and %zu",
            document->lines[match].line_number, second_line);
        return set_error(error_out, error_out_size, message);
    }
    if (match + 1u >= section->end
        || !table_separator(document->lines[match + 1u], header_count)) {
        snprintf(message, sizeof(message), "invalid projection table separator after line %zu",
            document->lines[match].line_number);
        return set_error(error_out, error_out_size, message);
    }
    *out_header_index = match;
    return 0;
}

static int valid_operator_code(const char *code)
{
    size_t index;
    size_t length = strlen(code);
    if (length <= 3u || strncmp(code, "OP_", 3u) != 0 || code[length - 1u] == '_') {
        return 0;
    }
    for (index = 3u; index < length; ++index) {
        unsigned char ch = (unsigned char)code[index];
        if (!ascii_upper(ch) && !ascii_digit(ch) && ch != '_') {
            return 0;
        }
    }
    return 1;
}

static int add_code(
    operator_code_t *codes,
    size_t *count,
    const char *code,
    size_t line_number,
    const char *kind,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
    if (!valid_operator_code(code)) {
        snprintf(message, sizeof(message), "invalid operator %s %s at line %zu", kind, code,
            line_number);
        return set_error(error_out, error_out_size, message);
    }
    for (index = 0u; index < *count; ++index) {
        if (strcmp(codes[index].value, code) == 0) {
            snprintf(message, sizeof(message), "duplicate operator %s %s at lines %zu and %zu",
                kind, code, codes[index].line_number, line_number);
            return set_error(error_out, error_out_size, message);
        }
    }
    if (*count >= MAX_OPERATOR_CODES || strlen(code) >= sizeof(codes[*count].value)) {
        return set_error(error_out, error_out_size, "operator code capacity exceeded");
    }
    memcpy(codes[*count].value, code, strlen(code) + 1u);
    codes[*count].line_number = line_number;
    ++(*count);
    return 0;
}

static int extract_context_references(
    line_view_t cell,
    projection_context_t *context,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    size_t before = context->reference_count;
    char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];

    for (index = 0u; index + 3u <= cell.len; ++index) {
        if (memcmp(cell.start + index, "OP_", 3u) == 0) {
            size_t end = index + 3u;
            char code[MAX_OPERATOR_CODE_LEN];
            size_t length;
            while (end < cell.len) {
                unsigned char ch = (unsigned char)cell.start[end];
                if (!ascii_upper(ch) && !ascii_digit(ch) && ch != '_') {
                    break;
                }
                ++end;
            }
            if (index == 0u || cell.start[index - 1u] != '`' || end >= cell.len
                || cell.start[end] != '`') {
                snprintf(message, sizeof(message), "operator reference must be backticked at line %zu",
                    cell.line_number);
                return set_error(error_out, error_out_size, message);
            }
            length = end - index;
            if (length >= sizeof(code)) {
                return set_error(error_out, error_out_size, "operator reference is too long");
            }
            memcpy(code, cell.start + index, length);
            code[length] = '\0';
            if (add_code(context->references, &context->reference_count, code, cell.line_number,
                    "reference", error_out, error_out_size)
                != 0) {
                return -1;
            }
            index = end;
        }
    }
    if (context->reference_count == before) {
        snprintf(message, sizeof(message), "projection context row has no operator reference at line %zu",
            cell.line_number);
        return set_error(error_out, error_out_size, message);
    }
    return 0;
}

static int parse_context_table(
    const document_lines_t *document,
    const section_range_t *section,
    projection_context_t *context,
    char *error_out,
    size_t error_out_size)
{
    static const char *const headers[] = {"Projection context", "Default Operator State"};
    size_t table_header;
    size_t index;
    if (find_table(document, section, headers, 2u, &table_header, error_out, error_out_size) != 0) {
        return -1;
    }
    for (index = table_header + 2u; index < section->end; ++index) {
        line_view_t cells[2];
        size_t count = split_table_cells(document->lines[index], cells, 2u);
        if (count == 0u) {
            break;
        }
        if (count != 2u || cells[0].len == 0u) {
            char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
            snprintf(message, sizeof(message), "malformed projection context row at line %zu",
                document->lines[index].line_number);
            return set_error(error_out, error_out_size, message);
        }
        if (extract_context_references(cells[1], context, error_out, error_out_size) != 0) {
            return -1;
        }
        ++context->context_rows;
    }
    if (context->context_rows == 0u) {
        return set_error(error_out, error_out_size, "projection context table has no rows");
    }
    return 0;
}

static int parse_state_code_cell(
    line_view_t cell,
    char *code_out,
    size_t code_out_size,
    char *error_out,
    size_t error_out_size)
{
    size_t length;
    cell = trim_both(cell);
    if (cell.len < 3u || cell.start[0] != '`' || cell.start[cell.len - 1u] != '`') {
        return set_error(error_out, error_out_size, "operator code cell must be one backticked code");
    }
    length = cell.len - 2u;
    if (length >= code_out_size) {
        return set_error(error_out, error_out_size, "operator state code is too long");
    }
    memcpy(code_out, cell.start + 1u, length);
    code_out[length] = '\0';
    return 0;
}

static int parse_state_table(
    const document_lines_t *document,
    const section_range_t *section,
    projection_context_t *context,
    char *error_out,
    size_t error_out_size)
{
    static const char *const headers[] = {"Operator code", "利用者向け意味", "主な内部根拠",
        "安全な次操作", "禁止する表示・操作", "Default owner / timeout"};
    size_t table_header;
    size_t index;
    if (find_table(document, section, headers, 6u, &table_header, error_out, error_out_size) != 0) {
        return -1;
    }
    for (index = table_header + 2u; index < section->end; ++index) {
        line_view_t cells[6];
        size_t count = split_table_cells(document->lines[index], cells, 6u);
        char code[MAX_OPERATOR_CODE_LEN];
        if (count == 0u) {
            break;
        }
        if (count != 6u) {
            char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
            snprintf(message, sizeof(message), "malformed operator state row at line %zu",
                document->lines[index].line_number);
            return set_error(error_out, error_out_size, message);
        }
        if (parse_state_code_cell(cells[0], code, sizeof(code), error_out, error_out_size) != 0
            || add_code(context->states, &context->state_count, code,
                   document->lines[index].line_number, "state", error_out, error_out_size)
                != 0) {
            return -1;
        }
    }
    if (context->state_count == 0u) {
        return set_error(error_out, error_out_size, "operator state table has no rows");
    }
    return 0;
}

static int find_code(const operator_code_t *codes, size_t count, const char *value)
{
    size_t index;
    for (index = 0u; index < count; ++index) {
        if (strcmp(codes[index].value, value) == 0) {
            return 1;
        }
    }
    return 0;
}

static int validate_projection_bijection(
    const projection_context_t *context,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
    for (index = 0u; index < context->reference_count; ++index) {
        if (!find_code(context->states, context->state_count, context->references[index].value)) {
            snprintf(message, sizeof(message), "unknown operator state reference %s at line %zu",
                context->references[index].value, context->references[index].line_number);
            return set_error(error_out, error_out_size, message);
        }
    }
    for (index = 0u; index < context->state_count; ++index) {
        if (!find_code(context->references, context->reference_count, context->states[index].value)) {
            snprintf(message, sizeof(message), "operator state %s has no projection reference",
                context->states[index].value);
            return set_error(error_out, error_out_size, message);
        }
    }
    return 0;
}

static int validate_reason_projection(
    const ninlil_reason_registry_yaml_t *registry,
    size_t *out_hint_count,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
    if (registry == NULL) {
        return set_error(error_out, error_out_size, "missing reason registry");
    }
    if (strcmp(registry->operator_projection_contract, NINLIL_OPERATOR_PROJECTION_LINK) != 0) {
        return set_error(error_out, error_out_size, "operator projection contract link mismatch");
    }
    if (registry->code_count == 0u || registry->code_count > NINLIL_REASON_REGISTRY_MAX_CODES) {
        return set_error(error_out, error_out_size, "invalid reason registry code count");
    }
    for (index = 0u; index < registry->code_count; ++index) {
        if (registry->codes[index].operator_state_hint[0] == '\0') {
            snprintf(message, sizeof(message), "empty operator_state_hint for reason %s",
                registry->codes[index].symbol);
            return set_error(error_out, error_out_size, message);
        }
    }
    *out_hint_count = registry->code_count;
    return 0;
}

int ninlil_operator_projection_check_content(
    const char *markdown_content,
    const ninlil_reason_registry_yaml_t *reason_registry,
    ninlil_operator_projection_result_t *out_result,
    char *error_out,
    size_t error_out_size)
{
    if (markdown_content == NULL) {
        return set_error(error_out, error_out_size, "invalid operator projection input");
    }
    return ninlil_operator_projection_check_bytes(markdown_content, strlen(markdown_content),
        reason_registry, out_result, error_out, error_out_size);
}

int ninlil_operator_projection_check_bytes(
    const char *markdown_bytes,
    size_t markdown_length,
    const ninlil_reason_registry_yaml_t *reason_registry,
    ninlil_operator_projection_result_t *out_result,
    char *error_out,
    size_t error_out_size)
{
    document_lines_t document;
    section_range_t projection_section;
    section_range_t states_section;
    projection_context_t context;
    ninlil_operator_projection_result_t result;

    if (out_result != NULL) {
        memset(out_result, 0, sizeof(*out_result));
    }
    memset(&context, 0, sizeof(context));
    memset(&result, 0, sizeof(result));
    if (parse_lines(markdown_bytes, markdown_length, &document, error_out, error_out_size) != 0
        || find_section(&document, "## Projection contract", &projection_section, error_out,
               error_out_size)
            != 0
        || find_section(&document, "## 共通Operator State", &states_section, error_out,
               error_out_size)
            != 0
        || parse_context_table(&document, &projection_section, &context, error_out, error_out_size)
            != 0
        || parse_state_table(&document, &states_section, &context, error_out, error_out_size) != 0
        || validate_projection_bijection(&context, error_out, error_out_size) != 0
        || validate_reason_projection(
               reason_registry, &result.reason_hints, error_out, error_out_size)
            != 0) {
        return -1;
    }
    result.context_rows = context.context_rows;
    result.state_codes = context.state_count;
    result.references = context.reference_count;
    if (out_result != NULL) {
        *out_result = result;
    }
    return 0;
}

static char *read_file(
    const char *path,
    size_t *out_length,
    char *error_out,
    size_t error_out_size)
{
    FILE *file;
    long size;
    char *content;
    size_t read_size;
    char message[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
    if (path == NULL || out_length == NULL) {
        set_error(error_out, error_out_size, "invalid operator model read arguments");
        return NULL;
    }
    file = fopen(path, "rb");
    if (file == NULL) {
        snprintf(message, sizeof(message), "cannot open %s", path);
        set_error(error_out, error_out_size, message);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0
        || fseek(file, 0, SEEK_SET) != 0 || (uintmax_t)size > (uintmax_t)SIZE_MAX - 1u) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot size operator model");
        return NULL;
    }
    content = (char *)malloc((size_t)size + 1u);
    if (content == NULL) {
        fclose(file);
        set_error(error_out, error_out_size, "out of memory reading operator model");
        return NULL;
    }
    read_size = fread(content, 1u, (size_t)size, file);
    fclose(file);
    if (read_size != (size_t)size) {
        free(content);
        set_error(error_out, error_out_size, "short read on operator model");
        return NULL;
    }
    if (memchr(content, '\0', read_size) != NULL) {
        free(content);
        set_error(error_out, error_out_size, "operator model contains embedded NUL");
        return NULL;
    }
    content[read_size] = '\0';
    *out_length = read_size;
    return content;
}

int ninlil_operator_projection_run_repository_check(
    const char *repo_root,
    ninlil_operator_projection_result_t *out_result,
    FILE *error_stream)
{
    char document_path[MAX_REPOSITORY_PATH];
    char registry_path[MAX_REPOSITORY_PATH];
    char error[NINLIL_OPERATOR_PROJECTION_MAX_ERROR];
    char *content;
    size_t content_length;
    ninlil_reason_registry_yaml_t registry;
    int document_written;
    int registry_written;
    int result;

    if (repo_root == NULL) {
        return -1;
    }
    document_written = snprintf(document_path, sizeof(document_path), "%s/%s", repo_root,
        NINLIL_OPERATOR_PROJECTION_DOC_PATH);
    registry_written = snprintf(registry_path, sizeof(registry_path), "%s/%s", repo_root,
        NINLIL_OPERATOR_PROJECTION_REASON_PATH);
    if (document_written < 0 || (size_t)document_written >= sizeof(document_path)
        || registry_written < 0 || (size_t)registry_written >= sizeof(registry_path)) {
        if (error_stream != NULL) {
            fprintf(error_stream, "operator projection path is too long\n");
        }
        return -1;
    }
    if (ninlil_parse_reason_registry_yaml(registry_path, &registry) != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "operator projection reason registry validation failed\n");
        }
        return -1;
    }
    content = read_file(document_path, &content_length, error, sizeof(error));
    if (content == NULL) {
        if (error_stream != NULL) {
            fprintf(error_stream, "operator projection read error: %s\n", error);
        }
        return -1;
    }
    result = ninlil_operator_projection_check_bytes(
        content, content_length, &registry, out_result, error, sizeof(error));
    free(content);
    if (result != 0 && error_stream != NULL) {
        fprintf(error_stream, "operator projection check error: %s\n", error);
    }
    return result;
}
