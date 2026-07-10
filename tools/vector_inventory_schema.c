#include "vector_inventory_schema.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *start;
    size_t len;
} line_view_t;

typedef struct {
    const char *content;
    size_t content_length;
    size_t cursor;
    size_t next_line_number;
} line_reader_t;

static int ascii_is_space(unsigned char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f'
        || ch == '\v';
}

static int set_error(char *error_out, size_t error_out_size, const char *message)
{
    if (error_out != NULL && error_out_size > 0u) {
        snprintf(error_out, error_out_size, "%s", message);
    }
    return -1;
}

static line_view_t line_view_trim_trailing(line_view_t view)
{
    while (view.len > 0u) {
        unsigned char ch = (unsigned char)view.start[view.len - 1u];
        if (!ascii_is_space(ch)) {
            break;
        }
        --view.len;
    }
    return view;
}

static line_view_t line_view_trim_leading(line_view_t view)
{
    size_t offset = 0u;

    while (offset < view.len && ascii_is_space((unsigned char)view.start[offset])) {
        ++offset;
    }
    view.start += offset;
    view.len -= offset;
    return view;
}

static line_view_t line_view_trim_both(line_view_t view)
{
    return line_view_trim_trailing(line_view_trim_leading(view));
}

static int read_next_line_view(
    line_reader_t *reader,
    line_view_t *out_view,
    size_t *out_line_number)
{
    size_t start;

    if (reader == NULL || reader->content == NULL || out_view == NULL
        || out_line_number == NULL) {
        return 0;
    }

    if (reader->cursor >= reader->content_length) {
        return 0;
    }

    start = reader->cursor;
    *out_line_number = reader->next_line_number;

    while (reader->cursor < reader->content_length
           && reader->content[reader->cursor] != '\n'
           && reader->content[reader->cursor] != '\r') {
        ++reader->cursor;
    }

    out_view->start = reader->content + start;
    out_view->len = reader->cursor - start;

    if (reader->cursor < reader->content_length) {
        if (reader->content[reader->cursor] == '\r') {
            ++reader->cursor;
            if (reader->cursor < reader->content_length
                && reader->content[reader->cursor] == '\n') {
                ++reader->cursor;
            }
        } else {
            ++reader->cursor;
        }
        ++reader->next_line_number;
    }
    return 1;
}

static int line_view_is_blank(line_view_t view)
{
    view = line_view_trim_both(view);
    return view.len == 0u;
}

static int line_view_starts_with_table_row(line_view_t view)
{
    view = line_view_trim_leading(view);
    return view.len > 0u && view.start[0] == '|';
}

static int line_view_is_table_separator_row(line_view_t view)
{
    size_t i;
    int saw_dash = 0;

    view = line_view_trim_both(view);
    if (view.len == 0u || view.start[0] != '|') {
        return 0;
    }

    for (i = 0u; i < view.len; ++i) {
        unsigned char ch = (unsigned char)view.start[i];
        if (ch == '-') {
            saw_dash = 1;
        } else if (ch != '|' && ch != ':' && !ascii_is_space(ch)) {
            return 0;
        }
    }
    return saw_dash != 0;
}

static size_t split_table_cells(line_view_t view, line_view_t *cells, size_t max_cells)
{
    size_t cell_count = 0u;
    size_t i = 0u;
    size_t cell_start = 0u;
    int in_cell = 0;

    view = line_view_trim_both(view);
    if (view.len == 0u || view.start[0] != '|') {
        return 0u;
    }

    for (i = 0u; i < view.len; ++i) {
        if (view.start[i] == '|') {
            if (in_cell != 0 && cell_count < max_cells) {
                cells[cell_count].start = view.start + cell_start;
                cells[cell_count].len = i - cell_start;
                cells[cell_count] = line_view_trim_both(cells[cell_count]);
                ++cell_count;
            }
            in_cell = 1;
            cell_start = i + 1u;
        }
    }

    return cell_count;
}

static int parse_backtick_token(
    line_view_t cell,
    char *id_out,
    size_t id_out_size,
    char *error_out,
    size_t error_out_size,
    size_t line_number,
    const char *context)
{
    size_t i = 0u;
    size_t id_len = 0u;
    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    cell = line_view_trim_both(cell);
    if (cell.len < 3u || cell.start[0] != '`') {
        snprintf(
            message,
            sizeof(message),
            "malformed vector table row at line %zu: %s",
            line_number,
            context);
        return set_error(error_out, error_out_size, message);
    }

    for (i = 1u; i < cell.len; ++i) {
        if (cell.start[i] == '`') {
            id_len = i - 1u;
            if (i + 1u != cell.len) {
                snprintf(
                    message,
                    sizeof(message),
                    "malformed vector table row at line %zu: first cell must contain exactly one backticked vector ID",
                    line_number);
                return set_error(error_out, error_out_size, message);
            }
            break;
        }
    }
    if (id_len == 0u) {
        snprintf(
            message,
            sizeof(message),
            "unterminated backtick at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (id_len >= id_out_size) {
        snprintf(
            message,
            sizeof(message),
            "vector ID too long at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    memcpy(id_out, cell.start + 1u, id_len);
    id_out[id_len] = '\0';
    return 0;
}

static const ninlil_vector_definition_t *inventory_find(
    const ninlil_vector_inventory_t *inventory,
    const char *id)
{
    size_t i;

    for (i = 0; i < inventory->count; ++i) {
        if (strcmp(inventory->definitions[i].id, id) == 0) {
            return &inventory->definitions[i];
        }
    }
    return NULL;
}

static int append_definition(
    ninlil_vector_inventory_t *inventory,
    const char *id,
    size_t line_number,
    ninlil_vector_definition_kind_t kind,
    char *error_out,
    size_t error_out_size)
{
    const ninlil_vector_definition_t *existing;
    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (!ninlil_vector_inventory_is_valid_id(id)) {
        snprintf(
            message,
            sizeof(message),
            "malformed vector ID at line %zu: %s",
            line_number,
            id);
        return set_error(error_out, error_out_size, message);
    }

    existing = inventory_find(inventory, id);
    if (existing != NULL) {
        snprintf(
            message,
            sizeof(message),
            "duplicate vector definition %s at lines %zu and %zu",
            id,
            existing->line_number,
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    if (inventory->count >= NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS) {
        return set_error(error_out, error_out_size, "vector inventory exceeds maximum capacity");
    }
    if (strlen(id) >= NINLIL_VECTOR_INVENTORY_MAX_ID_LEN) {
        snprintf(
            message,
            sizeof(message),
            "vector ID too long at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    memcpy(inventory->definitions[inventory->count].id, id, strlen(id) + 1u);
    inventory->definitions[inventory->count].line_number = line_number;
    inventory->definitions[inventory->count].kind = kind;
    inventory->count += 1u;
    return 0;
}

int ninlil_vector_inventory_is_valid_id(const char *id)
{
    size_t i;
    int has_digit = 0;

    if (id == NULL || id[0] == '\0') {
        return 0;
    }
    if (strncmp(id, "NINLIL_", 7) == 0 || strncmp(id, "NIN_FND_", 8) == 0) {
        return 0;
    }
    if (id[0] < 'A' || id[0] > 'Z') {
        return 0;
    }

    for (i = 0u; id[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)id[i];
        if (ch >= 'A' && ch <= 'Z') {
            /* ok */
        } else if (ch >= '0' && ch <= '9') {
            has_digit = 1;
        } else if (ch == '_') {
            /* ok */
        } else {
            return 0;
        }
    }

    return has_digit != 0;
}

static int parse_vector_table_row(
    line_view_t view,
    size_t line_number,
    ninlil_vector_inventory_t *inventory,
    char *error_out,
    size_t error_out_size)
{
    line_view_t cells[8];
    size_t cell_count;
    char id[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];

    if (line_view_is_table_separator_row(view)) {
        return 0;
    }

    cell_count = split_table_cells(view, cells, 8u);
    if (cell_count == 0u) {
        char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];
        snprintf(
            message,
            sizeof(message),
            "malformed vector table row at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    if (parse_backtick_token(
            cells[0],
            id,
            sizeof(id),
            error_out,
            error_out_size,
            line_number,
            "expected backticked vector ID in first cell")
        != 0) {
        return -1;
    }

    return append_definition(
        inventory,
        id,
        line_number,
        NINLIL_VECTOR_DEFINITION_TABLE,
        error_out,
        error_out_size);
}

static int parse_explicit_vector_line(
    line_view_t view,
    size_t line_number,
    ninlil_vector_inventory_t *inventory,
    char *error_out,
    size_t error_out_size)
{
    static const char k_prefix[] = "Vector `";
    char id[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
    size_t i;
    size_t id_len = 0u;
    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    view = line_view_trim_both(view);
    if (view.len < sizeof(k_prefix) - 1u
        || memcmp(view.start, k_prefix, sizeof(k_prefix) - 1u) != 0) {
        return 0;
    }

    for (i = sizeof(k_prefix) - 1u; i < view.len; ++i) {
        if (view.start[i] == '`') {
            id_len = i - (sizeof(k_prefix) - 1u);
            break;
        }
    }
    if (id_len == 0u) {
        snprintf(
            message,
            sizeof(message),
            "unterminated backtick at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (id_len >= sizeof(id)) {
        snprintf(
            message,
            sizeof(message),
            "vector ID too long at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    memcpy(id, view.start + (sizeof(k_prefix) - 1u), id_len);
    id[id_len] = '\0';

    return append_definition(
        inventory,
        id,
        line_number,
        NINLIL_VECTOR_DEFINITION_EXPLICIT,
        error_out,
        error_out_size);
}

static int parse_bullet_definition_line(
    line_view_t view,
    size_t line_number,
    ninlil_vector_inventory_t *inventory,
    char *error_out,
    size_t error_out_size)
{
    static const char k_prefix[] = "- `";
    char id[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
    size_t i;
    size_t id_len = 0u;
    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    view = line_view_trim_both(view);
    if (view.len < sizeof(k_prefix) + 2u
        || memcmp(view.start, k_prefix, sizeof(k_prefix) - 1u) != 0) {
        return 0;
    }

    for (i = sizeof(k_prefix) - 1u; i < view.len; ++i) {
        if (view.start[i] == '`') {
            id_len = i - (sizeof(k_prefix) - 1u);
            break;
        }
    }
    if (id_len == 0u) {
        snprintf(
            message,
            sizeof(message),
            "unterminated backtick at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }
    if (i + 1u >= view.len || view.start[i + 1u] != ':') {
        return 0;
    }
    if (id_len >= sizeof(id)) {
        snprintf(
            message,
            sizeof(message),
            "vector ID too long at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    memcpy(id, view.start + (sizeof(k_prefix) - 1u), id_len);
    id[id_len] = '\0';

    return append_definition(
        inventory,
        id,
        line_number,
        NINLIL_VECTOR_DEFINITION_BULLET,
        error_out,
        error_out_size);
}

static int parse_canonical_heading_line(
    line_view_t view,
    size_t line_number,
    ninlil_vector_inventory_t *inventory,
    char *error_out,
    size_t error_out_size)
{
    static const char k_prefix[] = "### Vector ";
    char id[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
    size_t i;
    size_t id_start;
    size_t id_len = 0u;
    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    view = line_view_trim_both(view);
    if (view.len < sizeof(k_prefix) + 2u
        || memcmp(view.start, k_prefix, sizeof(k_prefix) - 1u) != 0) {
        return 0;
    }

    id_start = sizeof(k_prefix) - 1u;
    for (i = id_start; i < view.len; ++i) {
        if (view.start[i] == ':') {
            id_len = i - id_start;
            break;
        }
    }
    if (id_len == 0u) {
        return 0;
    }
    if (id_len >= sizeof(id)) {
        snprintf(
            message,
            sizeof(message),
            "vector ID too long at line %zu",
            line_number);
        return set_error(error_out, error_out_size, message);
    }

    memcpy(id, view.start + id_start, id_len);
    id[id_len] = '\0';

    if (!ninlil_vector_inventory_is_valid_id(id)) {
        return 0;
    }

    return append_definition(
        inventory,
        id,
        line_number,
        NINLIL_VECTOR_DEFINITION_CANONICAL_HEADING,
        error_out,
        error_out_size);
}

static int first_table_cell_equals(line_view_t view, const char *expected)
{
    line_view_t cells[4];
    line_view_t first;
    size_t expected_len;

    if (!line_view_starts_with_table_row(view)) {
        return 0;
    }
    if (split_table_cells(view, cells, 4u) == 0u) {
        return 0;
    }
    first = cells[0];
    expected_len = strlen(expected);
    if (first.len != expected_len) {
        return 0;
    }
    return memcmp(first.start, expected, expected_len) == 0;
}

static int set_incomplete_vector_table_error(
    size_t header_line,
    const char *expected,
    const char *boundary,
    size_t boundary_line,
    char *error_out,
    size_t error_out_size)
{
    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (boundary_line == 0u) {
        snprintf(
            message,
            sizeof(message),
            "incomplete Vector table at header line %zu: expected %s before EOF",
            header_line,
            expected);
    } else {
        snprintf(
            message,
            sizeof(message),
            "incomplete Vector table at header line %zu: expected %s before %s line %zu",
            header_line,
            expected,
            boundary,
            boundary_line);
    }
    return set_error(error_out, error_out_size, message);
}

int ninlil_vector_inventory_parse_markdown_content(
    const char *content,
    ninlil_vector_inventory_t *out_inventory,
    char *error_out,
    size_t error_out_size)
{
    line_reader_t reader;
    line_view_t view;
    size_t line_number;
    size_t vector_table_header_line = 0u;
    int in_vector_table = 0;
    int saw_separator = 0;
    int saw_data_row = 0;

    if (content == NULL || out_inventory == NULL) {
        return set_error(error_out, error_out_size, "invalid vector inventory parse arguments");
    }

    memset(out_inventory, 0, sizeof(*out_inventory));
    reader.content = content;
    reader.content_length = strlen(content);
    reader.cursor = 0u;
    reader.next_line_number = 1u;

    while (read_next_line_view(&reader, &view, &line_number) != 0) {
        if (view.len >= NINLIL_VECTOR_INVENTORY_MAX_LINE_LEN) {
            char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];
            snprintf(
                message,
                sizeof(message),
                "vector inventory line too long at line %zu",
                line_number);
            return set_error(error_out, error_out_size, message);
        }

        if (in_vector_table != 0) {
            if (line_view_is_blank(view)) {
                if (saw_separator == 0) {
                    return set_incomplete_vector_table_error(
                        vector_table_header_line,
                        "separator row",
                        "blank",
                        line_number,
                        error_out,
                        error_out_size);
                }
                if (saw_data_row == 0) {
                    return set_incomplete_vector_table_error(
                        vector_table_header_line,
                        "at least one data row",
                        "blank",
                        line_number,
                        error_out,
                        error_out_size);
                }
                in_vector_table = 0;
                saw_separator = 0;
                saw_data_row = 0;
                vector_table_header_line = 0u;
                continue;
            }
            if (!line_view_starts_with_table_row(view)) {
                if (saw_separator == 0) {
                    return set_incomplete_vector_table_error(
                        vector_table_header_line,
                        "separator row",
                        "boundary",
                        line_number,
                        error_out,
                        error_out_size);
                }
                if (saw_data_row == 0) {
                    return set_incomplete_vector_table_error(
                        vector_table_header_line,
                        "at least one data row",
                        "boundary",
                        line_number,
                        error_out,
                        error_out_size);
                }
                in_vector_table = 0;
                saw_separator = 0;
                saw_data_row = 0;
                vector_table_header_line = 0u;
            } else if (line_view_is_table_separator_row(view)) {
                if (saw_separator != 0) {
                    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];
                    snprintf(
                        message,
                        sizeof(message),
                        "malformed vector table row at line %zu",
                        line_number);
                    return set_error(error_out, error_out_size, message);
                }
                saw_separator = 1;
                continue;
            } else {
                if (saw_separator == 0) {
                    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];
                    snprintf(
                        message,
                        sizeof(message),
                        "malformed vector table at line %zu: missing separator row",
                        line_number);
                    return set_error(error_out, error_out_size, message);
                }
                if (parse_vector_table_row(
                        view,
                        line_number,
                        out_inventory,
                        error_out,
                        error_out_size)
                    != 0) {
                    return -1;
                }
                saw_data_row = 1;
                continue;
            }
        }

        if (line_view_is_blank(view)) {
            continue;
        }

        if (first_table_cell_equals(view, "Vector")) {
            in_vector_table = 1;
            saw_separator = 0;
            saw_data_row = 0;
            vector_table_header_line = line_number;
            continue;
        }

        if (parse_explicit_vector_line(
                view,
                line_number,
                out_inventory,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
        if (parse_bullet_definition_line(
                view,
                line_number,
                out_inventory,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
        if (parse_canonical_heading_line(
                view,
                line_number,
                out_inventory,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
    }

    if (in_vector_table != 0 && saw_separator == 0) {
        return set_incomplete_vector_table_error(
            vector_table_header_line,
            "separator row",
            "EOF",
            0u,
            error_out,
            error_out_size);
    }
    if (in_vector_table != 0 && saw_data_row == 0) {
        return set_incomplete_vector_table_error(
            vector_table_header_line,
            "at least one data row",
            "EOF",
            0u,
            error_out,
            error_out_size);
    }

    return ninlil_vector_inventory_sort(out_inventory);
}

static char *read_file_contents(const char *path, char *error_out, size_t error_out_size)
{
    FILE *file;
    char *buffer;
    long file_size;
    size_t read_size;

    file = fopen(path, "rb");
    if (file == NULL) {
        char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];
        snprintf(message, sizeof(message), "cannot open %s", path);
        set_error(error_out, error_out_size, message);
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot seek vector inventory markdown file");
        return NULL;
    }
    file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot size vector inventory markdown file");
        return NULL;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        set_error(error_out, error_out_size, "cannot rewind vector inventory markdown file");
        return NULL;
    }

    if ((uintmax_t)file_size > (uintmax_t)SIZE_MAX - 1u) {
        fclose(file);
        set_error(error_out, error_out_size, "vector inventory markdown file is too large");
        return NULL;
    }

    buffer = (char *)malloc((size_t)file_size + 1u);
    if (buffer == NULL) {
        fclose(file);
        set_error(error_out, error_out_size, "out of memory reading vector inventory markdown file");
        return NULL;
    }

    read_size = fread(buffer, 1u, (size_t)file_size, file);
    fclose(file);
    if (read_size != (size_t)file_size) {
        free(buffer);
        set_error(error_out, error_out_size, "short read on vector inventory markdown file");
        return NULL;
    }
    buffer[read_size] = '\0';
    return buffer;
}

int ninlil_vector_inventory_parse_markdown_file(
    const char *path,
    ninlil_vector_inventory_t *out_inventory,
    char *error_out,
    size_t error_out_size)
{
    char *content;
    int result;

    content = read_file_contents(path, error_out, error_out_size);
    if (content == NULL) {
        return -1;
    }
    result = ninlil_vector_inventory_parse_markdown_content(
        content,
        out_inventory,
        error_out,
        error_out_size);
    free(content);
    return result;
}

static int compare_definitions(const void *left, const void *right)
{
    const ninlil_vector_definition_t *a = (const ninlil_vector_definition_t *)left;
    const ninlil_vector_definition_t *b = (const ninlil_vector_definition_t *)right;
    int cmp = strcmp(a->id, b->id);

    if (cmp != 0) {
        return cmp;
    }
    if (a->line_number < b->line_number) {
        return -1;
    }
    if (a->line_number > b->line_number) {
        return 1;
    }
    return 0;
}

int ninlil_vector_inventory_sort(ninlil_vector_inventory_t *inventory)
{
    if (inventory == NULL) {
        return -1;
    }
    if (inventory->count > 1u) {
        qsort(
            inventory->definitions,
            inventory->count,
            sizeof(inventory->definitions[0]),
            compare_definitions);
    }
    return 0;
}

static size_t inventory_count_kind(
    const ninlil_vector_inventory_t *inventory,
    ninlil_vector_definition_kind_t kind)
{
    size_t i;
    size_t count = 0u;

    for (i = 0u; i < inventory->count; ++i) {
        if (inventory->definitions[i].kind == kind) {
            ++count;
        }
    }
    return count;
}

int ninlil_vector_inventory_validate(
    const ninlil_vector_inventory_t *inventory,
    char *error_out,
    size_t error_out_size)
{
    size_t i;
    size_t j;
    size_t table_count;
    size_t explicit_count;
    size_t bullet_count;
    size_t canonical_count;
    char message[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (inventory == NULL) {
        return set_error(error_out, error_out_size, "vector inventory is null");
    }
    if (inventory->count != NINLIL_VECTOR_INVENTORY_EXPECTED_DEFINITION_COUNT) {
        snprintf(
            message,
            sizeof(message),
            "vector definition count mismatch: expected %u, got %zu",
            NINLIL_VECTOR_INVENTORY_EXPECTED_DEFINITION_COUNT,
            inventory->count);
        return set_error(error_out, error_out_size, message);
    }

    table_count = inventory_count_kind(inventory, NINLIL_VECTOR_DEFINITION_TABLE);
    explicit_count = inventory_count_kind(inventory, NINLIL_VECTOR_DEFINITION_EXPLICIT);
    bullet_count = inventory_count_kind(inventory, NINLIL_VECTOR_DEFINITION_BULLET);
    canonical_count = inventory_count_kind(
        inventory,
        NINLIL_VECTOR_DEFINITION_CANONICAL_HEADING);
    if (table_count != NINLIL_VECTOR_INVENTORY_EXPECTED_TABLE_COUNT) {
        snprintf(
            message,
            sizeof(message),
            "vector table definition count mismatch: expected %u, got %zu",
            NINLIL_VECTOR_INVENTORY_EXPECTED_TABLE_COUNT,
            table_count);
        return set_error(error_out, error_out_size, message);
    }
    if (explicit_count != NINLIL_VECTOR_INVENTORY_EXPECTED_EXPLICIT_COUNT) {
        snprintf(
            message,
            sizeof(message),
            "vector explicit definition count mismatch: expected %u, got %zu",
            NINLIL_VECTOR_INVENTORY_EXPECTED_EXPLICIT_COUNT,
            explicit_count);
        return set_error(error_out, error_out_size, message);
    }
    if (bullet_count != NINLIL_VECTOR_INVENTORY_EXPECTED_BULLET_COUNT) {
        snprintf(
            message,
            sizeof(message),
            "vector bullet definition count mismatch: expected %u, got %zu",
            NINLIL_VECTOR_INVENTORY_EXPECTED_BULLET_COUNT,
            bullet_count);
        return set_error(error_out, error_out_size, message);
    }
    if (canonical_count != NINLIL_VECTOR_INVENTORY_EXPECTED_CANONICAL_HEADING_COUNT) {
        snprintf(
            message,
            sizeof(message),
            "vector canonical heading definition count mismatch: expected %u, got %zu",
            NINLIL_VECTOR_INVENTORY_EXPECTED_CANONICAL_HEADING_COUNT,
            canonical_count);
        return set_error(error_out, error_out_size, message);
    }

    for (i = 0; i < inventory->count; ++i) {
        if (!ninlil_vector_inventory_is_valid_id(inventory->definitions[i].id)) {
            snprintf(
                message,
                sizeof(message),
                "invalid vector ID at index %zu: %s",
                i,
                inventory->definitions[i].id);
            return set_error(error_out, error_out_size, message);
        }
        for (j = i + 1u; j < inventory->count; ++j) {
            if (strcmp(inventory->definitions[i].id, inventory->definitions[j].id) == 0) {
                snprintf(
                    message,
                    sizeof(message),
                    "duplicate vector definition %s at lines %zu and %zu",
                    inventory->definitions[i].id,
                    inventory->definitions[i].line_number,
                    inventory->definitions[j].line_number);
                return set_error(error_out, error_out_size, message);
            }
        }
        if (i + 1u < inventory->count
            && strcmp(inventory->definitions[i].id, inventory->definitions[i + 1u].id) > 0) {
            return set_error(error_out, error_out_size, "vector inventory is not sorted");
        }
    }

    return 0;
}

void ninlil_vector_inventory_count_kinds(
    const ninlil_vector_inventory_t *inventory,
    ninlil_vector_inventory_kind_counts_t *out_counts)
{
    if (out_counts == NULL) {
        return;
    }

    memset(out_counts, 0, sizeof(*out_counts));
    if (inventory == NULL) {
        return;
    }

    out_counts->total = inventory->count;
    out_counts->table = inventory_count_kind(inventory, NINLIL_VECTOR_DEFINITION_TABLE);
    out_counts->explicit = inventory_count_kind(inventory, NINLIL_VECTOR_DEFINITION_EXPLICIT);
    out_counts->bullet = inventory_count_kind(inventory, NINLIL_VECTOR_DEFINITION_BULLET);
    out_counts->canonical = inventory_count_kind(
        inventory,
        NINLIL_VECTOR_DEFINITION_CANONICAL_HEADING);
}

int ninlil_vector_inventory_build_doc14_path(
    const char *repo_root,
    char *path_out,
    size_t path_out_size,
    char *error_out,
    size_t error_out_size)
{
    int written;

    if (repo_root == NULL || path_out == NULL || path_out_size == 0u) {
        return set_error(error_out, error_out_size, "invalid vector inventory path arguments");
    }

    written = snprintf(
        path_out,
        path_out_size,
        "%s/%s",
        repo_root,
        NINLIL_VECTOR_INVENTORY_DOC14_PATH);
    if (written < 0 || (size_t)written >= path_out_size) {
        return set_error(error_out, error_out_size, "vector inventory path truncated");
    }
    return 0;
}

int ninlil_vector_run_repository_check(
    const char *repo_root,
    ninlil_vector_repository_check_result_t *out_result,
    FILE *error_stream)
{
    char doc_path[NINLIL_VECTOR_INVENTORY_MAX_PATH_LEN];
    ninlil_vector_inventory_t inventory;
    char error[NINLIL_VECTOR_INVENTORY_MAX_ERROR];

    if (out_result != NULL) {
        memset(out_result, 0, sizeof(*out_result));
    }

    if (repo_root == NULL) {
        if (error_stream != NULL) {
            fprintf(error_stream, "vector inventory check error: repo_root is null\n");
        }
        return -1;
    }

    if (ninlil_vector_inventory_build_doc14_path(
            repo_root,
            doc_path,
            sizeof(doc_path),
            error,
            sizeof(error))
        != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "vector inventory path error: %s\n", error);
        }
        return -1;
    }

    if (ninlil_vector_inventory_parse_markdown_file(
            doc_path,
            &inventory,
            error,
            sizeof(error))
        != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "vector inventory parse error: %s\n", error);
        }
        return -1;
    }
    if (ninlil_vector_inventory_validate(&inventory, error, sizeof(error)) != 0) {
        if (error_stream != NULL) {
            fprintf(error_stream, "vector inventory validation error: %s\n", error);
        }
        return -1;
    }

    if (out_result != NULL) {
        ninlil_vector_inventory_count_kinds(&inventory, &out_result->kinds);
    }
    return 0;
}
