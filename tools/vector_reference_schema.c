#include "vector_reference_schema.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct vector_key_entry {
    char key[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
    size_t definition_index;
} vector_key_entry_t;

typedef enum target_section {
    TARGET_SECTION_NONE = 0,
    TARGET_SECTION_MANDATORY = 1,
    TARGET_SECTION_PULL_REQUEST = 2
} target_section_t;

typedef enum mandatory_table_state {
    MANDATORY_TABLE_SEARCHING = 0,
    MANDATORY_TABLE_EXPECT_SEPARATOR = 1,
    MANDATORY_TABLE_ROWS = 2,
    MANDATORY_TABLE_DONE = 3
} mandatory_table_state_t;

typedef struct reference_context {
    const ninlil_vector_inventory_t *inventory;
    vector_key_entry_t keys[NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS];
    unsigned char mandatory[NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS];
    unsigned char pull_request[NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS];
    ninlil_vector_reference_result_t result;
} reference_context_t;

static int ascii_is_space(unsigned char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
        || ch == '\v';
}

static int ascii_is_upper(unsigned char ch)
{
    return ch >= 'A' && ch <= 'Z';
}

static int ascii_is_lower(unsigned char ch)
{
    return ch >= 'a' && ch <= 'z';
}

static int ascii_is_digit(unsigned char ch)
{
    return ch >= '0' && ch <= '9';
}

static int ascii_is_word(unsigned char ch)
{
    return ascii_is_upper(ch) || ascii_is_lower(ch) || ascii_is_digit(ch) || ch == '_';
}

static int set_error(char *error_out, size_t error_out_size, const char *message)
{
    if (error_out != NULL && error_out_size > 0u) {
        snprintf(error_out, error_out_size, "%s", message);
    }
    return -1;
}

static int set_prefixed_error(
    char *destination,
    size_t destination_size,
    const char *prefix,
    const char *detail)
{
    size_t prefix_length;
    size_t detail_length;
    size_t copy_length;

    if (destination == NULL || destination_size == 0u) {
        return -1;
    }

    prefix_length = strlen(prefix);
    copy_length = prefix_length < destination_size - 1u
        ? prefix_length
        : destination_size - 1u;
    memcpy(destination, prefix, copy_length);
    destination[copy_length] = '\0';
    if (copy_length != prefix_length) {
        return -1;
    }

    detail_length = strlen(detail);
    copy_length = detail_length < destination_size - prefix_length - 1u
        ? detail_length
        : destination_size - prefix_length - 1u;
    memcpy(destination + prefix_length, detail, copy_length);
    destination[prefix_length + copy_length] = '\0';
    return -1;
}

static line_view_t trim_both(line_view_t view)
{
    size_t leading = 0u;

    while (leading < view.len && ascii_is_space((unsigned char)view.start[leading])) {
        ++leading;
    }
    view.start += leading;
    view.len -= leading;
    while (view.len > 0u && ascii_is_space((unsigned char)view.start[view.len - 1u])) {
        --view.len;
    }
    return view;
}

static int read_next_line(line_reader_t *reader, line_view_t *out_view, size_t *out_line)
{
    size_t start;

    if (reader == NULL || out_view == NULL || out_line == NULL
        || reader->cursor >= reader->length) {
        return 0;
    }

    start = reader->cursor;
    *out_line = reader->next_line;
    while (reader->cursor < reader->length && reader->content[reader->cursor] != '\n'
           && reader->content[reader->cursor] != '\r') {
        ++reader->cursor;
    }
    out_view->start = reader->content + start;
    out_view->len = reader->cursor - start;

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

static int view_equals(line_view_t view, const char *text)
{
    size_t length = strlen(text);

    return view.len == length && memcmp(view.start, text, length) == 0;
}

static int view_starts_with(line_view_t view, const char *prefix)
{
    size_t length = strlen(prefix);

    return view.len >= length && memcmp(view.start, prefix, length) == 0;
}

static int markdown_heading_level(line_view_t view)
{
    size_t count = 0u;

    while (count < view.len && view.start[count] == '#') {
        ++count;
    }
    if (count == 0u || count > 6u || count >= view.len || view.start[count] != ' ') {
        return 0;
    }
    return (int)count;
}

static size_t split_table_cells(line_view_t view, line_view_t *cells, size_t capacity)
{
    size_t count = 0u;
    size_t index;
    size_t cell_start = 0u;
    int inside = 0;

    view = trim_both(view);
    if (view.len == 0u || view.start[0] != '|') {
        return 0u;
    }
    for (index = 0u; index < view.len; ++index) {
        if (view.start[index] == '|') {
            if (inside != 0 && count < capacity) {
                cells[count].start = view.start + cell_start;
                cells[count].len = index - cell_start;
                cells[count] = trim_both(cells[count]);
                ++count;
            }
            inside = 1;
            cell_start = index + 1u;
        }
    }
    return count;
}

static int is_table_separator(line_view_t view)
{
    size_t index;
    int saw_dash = 0;

    view = trim_both(view);
    if (view.len == 0u || view.start[0] != '|') {
        return 0;
    }
    for (index = 0u; index < view.len; ++index) {
        unsigned char ch = (unsigned char)view.start[index];
        if (ch == '-') {
            saw_dash = 1;
        } else if (ch != '|' && ch != ':' && !ascii_is_space(ch)) {
            return 0;
        }
    }
    return saw_dash;
}

static int is_mandatory_header_row(line_view_t view)
{
    line_view_t cells[4];
    size_t count = split_table_cells(view, cells, 4u);

    return count >= 2u && view_equals(cells[0], "Requirement set")
        && view_equals(cells[1], "Test evidence");
}

static void definition_key(const char *id, char *key_out)
{
    const char *underscore = strchr(id, '_');
    size_t length = underscore == NULL ? strlen(id) : (size_t)(underscore - id);

    memcpy(key_out, id, length);
    key_out[length] = '\0';
}

static int build_key_map(
    reference_context_t *context,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    size_t prior;
    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (context->inventory->count > NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS) {
        return set_error(error_out, error_out_size, "vector inventory exceeds reference capacity");
    }
    for (index = 0u; index < context->inventory->count; ++index) {
        const ninlil_vector_definition_t *definition = &context->inventory->definitions[index];

        if (!ninlil_vector_inventory_is_valid_id(definition->id)) {
            snprintf(
                message,
                sizeof(message),
                "invalid vector definition ID %s at line %zu",
                definition->id,
                definition->line_number);
            return set_error(error_out, error_out_size, message);
        }
        definition_key(definition->id, context->keys[index].key);
        context->keys[index].definition_index = index;
        for (prior = 0u; prior < index; ++prior) {
            if (strcmp(context->keys[prior].key, context->keys[index].key) == 0) {
                const ninlil_vector_definition_t *prior_definition =
                    &context->inventory->definitions[context->keys[prior].definition_index];
                snprintf(
                    message,
                    sizeof(message),
                    "duplicate vector reference key %s for definitions %s at line %zu and %s at line %zu",
                    context->keys[index].key,
                    prior_definition->id,
                    prior_definition->line_number,
                    definition->id,
                    definition->line_number);
                return set_error(error_out, error_out_size, message);
            }
        }
    }
    return 0;
}

static int find_key(const reference_context_t *context, const char *key, size_t *out_index)
{
    size_t index;

    for (index = 0u; index < context->inventory->count; ++index) {
        if (strcmp(context->keys[index].key, key) == 0) {
            *out_index = context->keys[index].definition_index;
            return 1;
        }
    }
    return 0;
}

static int find_definition_id(
    const reference_context_t *context,
    const char *id,
    size_t *out_index)
{
    size_t index;

    for (index = 0u; index < context->inventory->count; ++index) {
        if (strcmp(context->inventory->definitions[index].id, id) == 0) {
            *out_index = index;
            return 1;
        }
    }
    return 0;
}

static void mark_reference(
    reference_context_t *context,
    target_section_t section,
    size_t definition_index)
{
    if (section == TARGET_SECTION_MANDATORY) {
        context->mandatory[definition_index] = 1u;
        ++context->result.mandatory_occurrences;
    } else {
        context->pull_request[definition_index] = 1u;
        ++context->result.pull_request_occurrences;
    }
}

static int resolve_individual(
    reference_context_t *context,
    target_section_t section,
    const char *key,
    size_t line_number,
    char *error_out,
    size_t error_out_size)
{
    size_t definition_index;
    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (!find_definition_id(context, key, &definition_index)
        && !find_key(context, key, &definition_index)) {
        snprintf(
            message,
            sizeof(message),
            "undefined vector reference %s at line %zu",
            key,
            line_number);
        return set_error(error_out, error_out_size, message);
    }
    mark_reference(context, section, definition_index);
    return 0;
}

static int parse_numeric_suffix(
    const char *key,
    size_t *out_prefix_length,
    size_t *out_value)
{
    size_t length = strlen(key);
    size_t start = length;
    size_t value = 0u;
    size_t index;

    while (start > 0u && ascii_is_digit((unsigned char)key[start - 1u])) {
        --start;
    }
    if (start == length || start == 0u) {
        return 0;
    }
    if (length - start > 1u && key[start] == '0') {
        return 0;
    }
    for (index = start; index < length; ++index) {
        size_t digit = (size_t)(key[index] - '0');
        if (value > (SIZE_MAX - digit) / 10u) {
            return 0;
        }
        value = value * 10u + digit;
    }
    *out_prefix_length = start;
    *out_value = value;
    return 1;
}

static int parse_alpha_suffix(
    const char *key,
    size_t *out_base_length,
    unsigned char *out_suffix)
{
    size_t length = strlen(key);
    size_t index;
    int has_digit = 0;

    if (length < 2u || !ascii_is_upper((unsigned char)key[length - 1u])) {
        return 0;
    }
    for (index = 0u; index + 1u < length; ++index) {
        if (ascii_is_digit((unsigned char)key[index])) {
            has_digit = 1;
        }
    }
    if (!has_digit) {
        return 0;
    }
    *out_base_length = length - 1u;
    *out_suffix = (unsigned char)key[length - 1u];
    return 1;
}

static int range_error(
    const char *kind,
    const char *start,
    const char *end,
    size_t line_number,
    char *error_out,
    size_t error_out_size)
{
    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    snprintf(
        message,
        sizeof(message),
        "%s vector range %s〜%s at line %zu",
        kind,
        start,
        end,
        line_number);
    return set_error(error_out, error_out_size, message);
}

static int ensure_endpoint(
    const reference_context_t *context,
    const char *key,
    const char *start,
    const char *end,
    size_t line_number,
    char *error_out,
    size_t error_out_size)
{
    size_t unused;
    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (find_key(context, key, &unused)) {
        return 0;
    }
    snprintf(
        message,
        sizeof(message),
        "undefined vector range endpoint %s for %s〜%s at line %zu",
        key,
        start,
        end,
        line_number);
    return set_error(error_out, error_out_size, message);
}

static int resolve_range(
    reference_context_t *context,
    target_section_t section,
    const char *start,
    const char *end,
    size_t line_number,
    char *error_out,
    size_t error_out_size)
{
    size_t start_prefix;
    size_t end_prefix;
    size_t start_number;
    size_t end_number;
    size_t start_base;
    size_t end_base;
    unsigned char start_suffix;
    unsigned char end_suffix;
    int start_numeric;
    int end_numeric;
    int start_alpha;
    int end_alpha;
    char key[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
    size_t index;

    if (strchr(start, '_') != NULL || strchr(end, '_') != NULL) {
        char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
        snprintf(
            message,
            sizeof(message),
            "full definition ID is not allowed as vector range endpoint %s〜%s at line %zu",
            start,
            end,
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    if (ensure_endpoint(context, start, start, end, line_number, error_out, error_out_size)
            != 0
        || ensure_endpoint(context, end, start, end, line_number, error_out, error_out_size)
            != 0) {
        return -1;
    }

    start_numeric = parse_numeric_suffix(start, &start_prefix, &start_number);
    end_numeric = parse_numeric_suffix(end, &end_prefix, &end_number);
    start_alpha = parse_alpha_suffix(start, &start_base, &start_suffix);
    end_alpha = parse_alpha_suffix(end, &end_base, &end_suffix);

    if (start_numeric != 0 && end_numeric != 0) {
        if (start_prefix != end_prefix || memcmp(start, end, start_prefix) != 0) {
            return range_error(
                "cross-prefix",
                start,
                end,
                line_number,
                error_out,
                error_out_size);
        }
        if (start_number > end_number) {
            return range_error(
                "descending",
                start,
                end,
                line_number,
                error_out,
                error_out_size);
        }
        if (end_number - start_number >= NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS) {
            return range_error(
                "oversized",
                start,
                end,
                line_number,
                error_out,
                error_out_size);
        }
        for (index = start_number; index <= end_number; ++index) {
            int written = snprintf(key, sizeof(key), "%.*s%zu", (int)start_prefix, start, index);
            size_t definition_index;
            char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

            if (written < 0 || (size_t)written >= sizeof(key)) {
                return range_error(
                    "overlong",
                    start,
                    end,
                    line_number,
                    error_out,
                    error_out_size);
            }
            if (!find_key(context, key, &definition_index)) {
                snprintf(
                    message,
                    sizeof(message),
                    "missing intermediate vector reference %s for range %s〜%s at line %zu",
                    key,
                    start,
                    end,
                    line_number);
                return set_error(error_out, error_out_size, message);
            }
            mark_reference(context, section, definition_index);
            if (index == SIZE_MAX) {
                break;
            }
        }
        return 0;
    }

    if (start_alpha != 0 && end_alpha != 0) {
        if (start_base != end_base || memcmp(start, end, start_base) != 0) {
            return range_error(
                "cross-prefix",
                start,
                end,
                line_number,
                error_out,
                error_out_size);
        }
        if (start_suffix > end_suffix) {
            return range_error(
                "descending",
                start,
                end,
                line_number,
                error_out,
                error_out_size);
        }
        for (index = (size_t)start_suffix; index <= (size_t)end_suffix; ++index) {
            size_t definition_index;
            char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

            memcpy(key, start, start_base);
            key[start_base] = (char)index;
            key[start_base + 1u] = '\0';
            if (!find_key(context, key, &definition_index)) {
                snprintf(
                    message,
                    sizeof(message),
                    "missing intermediate vector reference %s for range %s〜%s at line %zu",
                    key,
                    start,
                    end,
                    line_number);
                return set_error(error_out, error_out_size, message);
            }
            mark_reference(context, section, definition_index);
        }
        return 0;
    }

    return range_error(
        "malformed",
        start,
        end,
        line_number,
        error_out,
        error_out_size);
}

static int is_explicit_exclusion(const char *word)
{
    return strcmp(word, "C11") == 0 || strcmp(word, "UINT64_MAX") == 0
        || strncmp(word, "NINLIL_", 7u) == 0;
}

static int word_is_reference_candidate(const char *word)
{
    size_t index;
    int has_digit = 0;

    if (!ascii_is_upper((unsigned char)word[0])) {
        return 0;
    }
    for (index = 0u; word[index] != '\0'; ++index) {
        unsigned char ch = (unsigned char)word[index];
        if (ascii_is_upper(ch) || ch == '_') {
            continue;
        }
        if (ascii_is_digit(ch)) {
            has_digit = 1;
            continue;
        }
        return 0;
    }
    return has_digit;
}

static int read_ascii_word(
    line_view_t view,
    size_t start,
    char *word,
    size_t word_size,
    size_t *out_end)
{
    size_t end = start;
    size_t length;

    while (end < view.len && ascii_is_word((unsigned char)view.start[end])) {
        ++end;
    }
    length = end - start;
    if (length == 0u || length >= word_size) {
        return 0;
    }
    memcpy(word, view.start + start, length);
    word[length] = '\0';
    *out_end = end;
    return 1;
}

static int is_range_separator_at(line_view_t view, size_t offset)
{
    static const unsigned char separator[] = {0xe3u, 0x80u, 0x9cu};

    return offset + sizeof(separator) <= view.len
        && memcmp(view.start + offset, separator, sizeof(separator)) == 0;
}

static int extract_references(
    line_view_t view,
    size_t line_number,
    target_section_t section,
    reference_context_t *context,
    char *error_out,
    size_t error_out_size)
{
    size_t cursor = 0u;

    while (cursor < view.len) {
        unsigned char ch = (unsigned char)view.start[cursor];

        if (ascii_is_upper(ch)
            && (cursor == 0u || !ascii_is_word((unsigned char)view.start[cursor - 1u]))) {
            char start[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
            size_t start_end;

            if (!read_ascii_word(view, cursor, start, sizeof(start), &start_end)) {
                char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
                snprintf(
                    message,
                    sizeof(message),
                    "overlong reference token at line %zu",
                    line_number);
                return set_error(error_out, error_out_size, message);
            }
            if (is_explicit_exclusion(start)) {
                ++context->result.excluded_tokens;
                cursor = start_end;
                continue;
            }
            if (!word_is_reference_candidate(start)) {
                cursor = start_end;
                continue;
            }
            if (is_range_separator_at(view, start_end)) {
                char end[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
                size_t end_start = start_end + 3u;
                size_t end_end;

                if (end_start >= view.len || !ascii_is_upper((unsigned char)view.start[end_start])
                    || !read_ascii_word(view, end_start, end, sizeof(end), &end_end)
                    || !word_is_reference_candidate(end) || is_explicit_exclusion(end)) {
                    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
                    snprintf(
                        message,
                        sizeof(message),
                        "malformed vector range beginning %s〜 at line %zu",
                        start,
                        line_number);
                    return set_error(error_out, error_out_size, message);
                }
                if (is_range_separator_at(view, end_end)) {
                    return range_error(
                        "malformed",
                        start,
                        end,
                        line_number,
                        error_out,
                        error_out_size);
                }
                if (resolve_range(
                        context,
                        section,
                        start,
                        end,
                        line_number,
                        error_out,
                        error_out_size)
                    != 0) {
                    return -1;
                }
                cursor = end_end;
                continue;
            }
            if (resolve_individual(
                    context,
                    section,
                    start,
                    line_number,
                    error_out,
                    error_out_size)
                != 0) {
                return -1;
            }
            cursor = start_end;
            continue;
        }
        ++cursor;
    }
    return 0;
}

static int finish_mandatory_section(
    mandatory_table_state_t state,
    size_t heading_line,
    size_t table_header_line,
    size_t row_count,
    char *error_out,
    size_t error_out_size)
{
    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (state == MANDATORY_TABLE_SEARCHING) {
        snprintf(
            message,
            sizeof(message),
            "missing mandatory Test evidence table in section at line %zu",
            heading_line);
        return set_error(error_out, error_out_size, message);
    }
    if (state == MANDATORY_TABLE_EXPECT_SEPARATOR) {
        snprintf(
            message,
            sizeof(message),
            "incomplete mandatory table at header line %zu: missing separator row",
            table_header_line);
        return set_error(error_out, error_out_size, message);
    }
    if (state == MANDATORY_TABLE_ROWS && row_count == 0u) {
        snprintf(
            message,
            sizeof(message),
            "incomplete mandatory table at header line %zu: missing data row",
            table_header_line);
        return set_error(error_out, error_out_size, message);
    }
    return 0;
}

static int process_mandatory_line(
    line_view_t view,
    size_t line_number,
    mandatory_table_state_t *state,
    size_t *table_header_line,
    size_t *row_count,
    reference_context_t *context,
    char *error_out,
    size_t error_out_size)
{
    if (*state != MANDATORY_TABLE_SEARCHING && is_mandatory_header_row(view)) {
        char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
        snprintf(
            message,
            sizeof(message),
            "duplicate mandatory Test evidence headers at lines %zu and %zu",
            *table_header_line,
            line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (*state == MANDATORY_TABLE_SEARCHING) {
        if (is_mandatory_header_row(view)) {
            *state = MANDATORY_TABLE_EXPECT_SEPARATOR;
            *table_header_line = line_number;
        }
        return 0;
    }
    if (*state == MANDATORY_TABLE_EXPECT_SEPARATOR) {
        if (!is_table_separator(view)) {
            char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
            snprintf(
                message,
                sizeof(message),
                "incomplete mandatory table at header line %zu: expected separator at line %zu",
                *table_header_line,
                line_number);
            return set_error(error_out, error_out_size, message);
        }
        *state = MANDATORY_TABLE_ROWS;
        return 0;
    }
    if (*state == MANDATORY_TABLE_ROWS) {
        line_view_t cells[4];
        size_t cell_count;

        if (trim_both(view).len == 0u || trim_both(view).start[0] != '|') {
            if (*row_count == 0u) {
                char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
                snprintf(
                    message,
                    sizeof(message),
                    "incomplete mandatory table at header line %zu: expected data row before line %zu",
                    *table_header_line,
                    line_number);
                return set_error(error_out, error_out_size, message);
            }
            *state = MANDATORY_TABLE_DONE;
            return 0;
        }
        if (is_table_separator(view)) {
            char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
            snprintf(
                message,
                sizeof(message),
                "malformed mandatory table separator at line %zu",
                line_number);
            return set_error(error_out, error_out_size, message);
        }
        cell_count = split_table_cells(view, cells, 4u);
        if (cell_count < 2u) {
            char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
            snprintf(
                message,
                sizeof(message),
                "malformed mandatory Test evidence row at line %zu",
                line_number);
            return set_error(error_out, error_out_size, message);
        }
        if (extract_references(
                cells[1],
                line_number,
                TARGET_SECTION_MANDATORY,
                context,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
        ++(*row_count);
        ++context->result.mandatory_rows;
    }
    return 0;
}

static int finalize_coverage(
    reference_context_t *context,
    ninlil_vector_reference_result_t *out_result,
    char *error_out,
    size_t error_out_size)
{
    size_t index;
    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    context->result.definition_count = context->inventory->count;
    for (index = 0u; index < context->inventory->count; ++index) {
        if (context->mandatory[index] != 0u) {
            ++context->result.mandatory_unique;
        }
        if (context->pull_request[index] != 0u) {
            ++context->result.pull_request_unique;
        }
        if (context->mandatory[index] != 0u || context->pull_request[index] != 0u) {
            ++context->result.union_unique;
        } else {
            const ninlil_vector_definition_t *definition =
                &context->inventory->definitions[index];
            snprintf(
                message,
                sizeof(message),
                "orphan vector definition %s at line %zu",
                definition->id,
                definition->line_number);
            return set_error(error_out, error_out_size, message);
        }
    }
    if (out_result != NULL) {
        *out_result = context->result;
    }
    return 0;
}

int ninlil_vector_reference_check_content(
    const char *content,
    const ninlil_vector_inventory_t *inventory,
    ninlil_vector_reference_result_t *out_result,
    char *error_out,
    size_t error_out_size)
{
    static const char mandatory_heading[] = "### M1a mandatory suites";
    static const char pull_request_heading[] = "### Pull request gate";
    reference_context_t context;
    line_reader_t reader;
    line_view_t view;
    size_t line_number;
    size_t mandatory_heading_line = 0u;
    size_t pull_request_heading_line = 0u;
    size_t mandatory_table_header_line = 0u;
    size_t mandatory_row_count = 0u;
    size_t mandatory_heading_count = 0u;
    size_t pull_request_heading_count = 0u;
    target_section_t section = TARGET_SECTION_NONE;
    mandatory_table_state_t mandatory_state = MANDATORY_TABLE_SEARCHING;
    char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (out_result != NULL) {
        memset(out_result, 0, sizeof(*out_result));
    }
    if (content == NULL || inventory == NULL) {
        return set_error(error_out, error_out_size, "invalid vector reference arguments");
    }
    memset(&context, 0, sizeof(context));
    context.inventory = inventory;
    if (build_key_map(&context, error_out, error_out_size) != 0) {
        return -1;
    }

    reader.content = content;
    reader.length = strlen(content);
    reader.cursor = 0u;
    reader.next_line = 1u;
    while (read_next_line(&reader, &view, &line_number)) {
        int heading_level;
        int is_mandatory;
        int is_pull_request;

        if (view.len >= NINLIL_VECTOR_REFERENCE_MAX_LINE_LEN) {
            snprintf(
                message,
                sizeof(message),
                "vector reference line too long at line %zu",
                line_number);
            return set_error(error_out, error_out_size, message);
        }

        heading_level = markdown_heading_level(view);
        is_mandatory = view_equals(view, mandatory_heading);
        is_pull_request = view_equals(view, pull_request_heading);
        if (is_mandatory) {
            ++mandatory_heading_count;
            if (mandatory_heading_count > 1u) {
                snprintf(
                    message,
                    sizeof(message),
                    "duplicate exact heading %s at lines %zu and %zu",
                    mandatory_heading,
                    mandatory_heading_line,
                    line_number);
                return set_error(error_out, error_out_size, message);
            }
        }
        if (is_pull_request) {
            ++pull_request_heading_count;
            if (pull_request_heading_count > 1u) {
                snprintf(
                    message,
                    sizeof(message),
                    "duplicate exact heading %s at lines %zu and %zu",
                    pull_request_heading,
                    pull_request_heading_line,
                    line_number);
                return set_error(error_out, error_out_size, message);
            }
        }

        if (heading_level > 0 && heading_level <= 3) {
            if (section == TARGET_SECTION_MANDATORY
                && finish_mandatory_section(
                       mandatory_state,
                       mandatory_heading_line,
                       mandatory_table_header_line,
                       mandatory_row_count,
                       error_out,
                       error_out_size)
                    != 0) {
                return -1;
            }
            if (section == TARGET_SECTION_PULL_REQUEST
                && context.result.pull_request_bullets == 0u) {
                snprintf(
                    message,
                    sizeof(message),
                    "missing Pull request gate bullet in section at line %zu",
                    pull_request_heading_line);
                return set_error(error_out, error_out_size, message);
            }
            section = TARGET_SECTION_NONE;
            if (is_mandatory) {
                mandatory_heading_line = line_number;
                mandatory_state = MANDATORY_TABLE_SEARCHING;
                mandatory_table_header_line = 0u;
                mandatory_row_count = 0u;
                section = TARGET_SECTION_MANDATORY;
            } else if (is_pull_request) {
                pull_request_heading_line = line_number;
                section = TARGET_SECTION_PULL_REQUEST;
            }
            continue;
        }

        if (section == TARGET_SECTION_MANDATORY) {
            if (process_mandatory_line(
                    view,
                    line_number,
                    &mandatory_state,
                    &mandatory_table_header_line,
                    &mandatory_row_count,
                    &context,
                    error_out,
                    error_out_size)
                != 0) {
                return -1;
            }
        } else if (section == TARGET_SECTION_PULL_REQUEST && view_starts_with(view, "- ")) {
            line_view_t bullet;
            bullet.start = view.start + 2u;
            bullet.len = view.len - 2u;
            if (extract_references(
                    bullet,
                    line_number,
                    TARGET_SECTION_PULL_REQUEST,
                    &context,
                    error_out,
                    error_out_size)
                != 0) {
                return -1;
            }
            ++context.result.pull_request_bullets;
        }
    }

    if (section == TARGET_SECTION_MANDATORY
        && finish_mandatory_section(
               mandatory_state,
               mandatory_heading_line,
               mandatory_table_header_line,
               mandatory_row_count,
               error_out,
               error_out_size)
            != 0) {
        return -1;
    }
    if (section == TARGET_SECTION_PULL_REQUEST && context.result.pull_request_bullets == 0u) {
        snprintf(
            message,
            sizeof(message),
            "missing Pull request gate bullet in section at line %zu",
            pull_request_heading_line);
        return set_error(error_out, error_out_size, message);
    }
    if (mandatory_heading_count != 1u) {
        return set_error(
            error_out,
            error_out_size,
            "missing exact heading ### M1a mandatory suites");
    }
    if (pull_request_heading_count != 1u) {
        return set_error(error_out, error_out_size, "missing exact heading ### Pull request gate");
    }
    return finalize_coverage(&context, out_result, error_out, error_out_size);
}

int ninlil_vector_reference_check_repository_content(
    const char *content,
    ninlil_vector_reference_result_t *out_result,
    char *error_out,
    size_t error_out_size)
{
    ninlil_vector_inventory_t inventory;
    char inventory_error[NINLIL_VECTOR_REFERENCE_MAX_ERROR];

    if (out_result != NULL) {
        memset(out_result, 0, sizeof(*out_result));
    }
    if (content == NULL) {
        return set_error(error_out, error_out_size, "invalid repository reference content");
    }
    if (ninlil_vector_inventory_parse_markdown_content(
            content,
            &inventory,
            inventory_error,
            sizeof(inventory_error))
        != 0) {
        return set_prefixed_error(
            error_out,
            error_out_size,
            "vector inventory parse error: ",
            inventory_error);
    }
    if (ninlil_vector_inventory_validate(
            &inventory,
            inventory_error,
            sizeof(inventory_error))
        != 0) {
        return set_prefixed_error(
            error_out,
            error_out_size,
            "vector inventory validation error: ",
            inventory_error);
    }
    return ninlil_vector_reference_check_content(
        content,
        &inventory,
        out_result,
        error_out,
        error_out_size);
}

static char *read_file(const char *path, char *error_out, size_t error_out_size)
{
    FILE *file;
    long size;
    char *content;
    size_t read_size;

    file = fopen(path, "rb");
    if (file == NULL) {
        char message[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
        snprintf(message, sizeof(message), "cannot open %s", path);
        set_error(error_out, error_out_size, message);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0
        || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot size vector reference markdown file");
        return NULL;
    }
    if ((uintmax_t)size > (uintmax_t)SIZE_MAX - 1u) {
        fclose(file);
        set_error(error_out, error_out_size, "vector reference markdown file is too large");
        return NULL;
    }
    content = (char *)malloc((size_t)size + 1u);
    if (content == NULL) {
        fclose(file);
        set_error(error_out, error_out_size, "out of memory reading vector reference markdown file");
        return NULL;
    }
    read_size = fread(content, 1u, (size_t)size, file);
    fclose(file);
    if (read_size != (size_t)size) {
        free(content);
        set_error(error_out, error_out_size, "short read on vector reference markdown file");
        return NULL;
    }
    content[read_size] = '\0';
    return content;
}

int ninlil_vector_reference_run_repository_check(
    const char *repo_root,
    ninlil_vector_reference_result_t *out_result,
    FILE *error_stream)
{
    char path[NINLIL_VECTOR_INVENTORY_MAX_PATH_LEN];
    char error[NINLIL_VECTOR_REFERENCE_MAX_ERROR];
    char *content;
    int result;

    if (out_result != NULL) {
        memset(out_result, 0, sizeof(*out_result));
    }
    if (ninlil_vector_inventory_build_doc14_path(
            repo_root,
            path,
            sizeof(path),
            error,
            sizeof(error))
        != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "vector reference path error: %s\n", error);
        }
        return -1;
    }
    content = read_file(path, error, sizeof(error));
    if (content == NULL) {
        if (error_stream != NULL) {
            fprintf(error_stream, "vector reference read error: %s\n", error);
        }
        return -1;
    }
    result = ninlil_vector_reference_check_repository_content(
        content,
        out_result,
        error,
        sizeof(error));
    free(content);
    if (result != 0 && error_stream != NULL) {
        fprintf(error_stream, "vector reference check error: %s\n", error);
    }
    return result;
}
