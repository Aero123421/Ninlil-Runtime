#include "abi_drift_schema.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRUCT_HEADER_BODY "uint16_t abi_version; uint16_t struct_size"

static int set_error(char *error_out, size_t error_out_size, const char *message)
{
    if (error_out != NULL && error_out_size > 0u) {
        snprintf(error_out, error_out_size, "%s", message);
    }
    return -1;
}

static int is_ident_start(char c)
{
    return (c == '_') || isalpha((unsigned char)c);
}

static int is_ident_char(char c)
{
    return (c == '_') || isalnum((unsigned char)c);
}

static void trim_inplace(char *text)
{
    size_t start = 0;
    size_t end;
    size_t length;

    if (text == NULL) {
        return;
    }
    while (text[start] != '\0' && isspace((unsigned char)text[start])) {
        ++start;
    }
    if (start > 0u) {
        memmove(text, text + start, strlen(text + start) + 1u);
    }
    length = strlen(text);
    end = length;
    while (end > 0u && isspace((unsigned char)text[end - 1u])) {
        --end;
    }
    text[end] = '\0';
}

static void collapse_spaces(const char *input, char *output, size_t output_size)
{
    size_t out_i = 0;
    int in_space = 0;

    if (output_size == 0u) {
        return;
    }
    for (; *input != '\0'; ++input) {
        if (isspace((unsigned char)*input)) {
            if (!in_space && out_i + 1u < output_size) {
                output[out_i++] = ' ';
                in_space = 1;
            }
            continue;
        }
        in_space = 0;
        if (out_i + 1u < output_size) {
            output[out_i++] = *input;
        }
    }
    while (out_i > 0u && output[out_i - 1u] == ' ') {
        --out_i;
    }
    output[out_i] = '\0';
}

void ninlil_abi_normalize_type(const char *input, char *output, size_t output_size)
{
    char buffer[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];

    if (output_size == 0u) {
        return;
    }
    collapse_spaces(input, buffer, sizeof(buffer));
    trim_inplace(buffer);

    {
        char rebuilt[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
        size_t i = 0;
        size_t out_i = 0;
        int pending_const = 0;

        rebuilt[0] = '\0';
        while (buffer[i] != '\0' && out_i + 1u < sizeof(rebuilt)) {
            if (strncmp(buffer + i, "const", 5) == 0
                && (i == 0u || isspace((unsigned char)buffer[i - 1u]))
                && (buffer[i + 5] == '\0' || isspace((unsigned char)buffer[i + 5])
                    || buffer[i + 5] == '*')) {
                pending_const = 1;
                i += 5;
                continue;
            }
            if (buffer[i] == '*') {
                while (out_i > 0u && rebuilt[out_i - 1u] == ' ') {
                    --out_i;
                }
                if (out_i + 2u < sizeof(rebuilt)) {
                    rebuilt[out_i++] = ' ';
                    rebuilt[out_i++] = '*';
                }
                ++i;
                while (buffer[i] == ' ') {
                    ++i;
                }
                continue;
            }
            if (pending_const) {
                if (out_i > 0u) {
                    rebuilt[out_i++] = ' ';
                }
                memcpy(rebuilt + out_i, "const", 5u);
                out_i += 5u;
                pending_const = 0;
            }
            if (out_i + 1u < sizeof(rebuilt)) {
                rebuilt[out_i++] = buffer[i++];
            } else {
                break;
            }
        }
        rebuilt[out_i] = '\0';
        collapse_spaces(rebuilt, buffer, sizeof(buffer));
    }

    snprintf(output, output_size, "%s", buffer);
}

void ninlil_abi_normalize_value(const char *input, char *output, size_t output_size)
{
    char buffer[NINLIL_ABI_DRIFT_MAX_VALUE_LEN];
    collapse_spaces(input, buffer, sizeof(buffer));
    trim_inplace(buffer);
    snprintf(output, output_size, "%s", buffer);
}

void ninlil_abi_catalog_init(ninlil_abi_catalog_t *catalog)
{
    memset(catalog, 0, sizeof(*catalog));
}

static int read_file_to_buffer(const char *path, char *out, size_t out_size)
{
    FILE *in = fopen(path, "rb");
    long size;
    size_t read_size;

    if (in == NULL) {
        return -1;
    }
    if (fseek(in, 0, SEEK_END) != 0) {
        fclose(in);
        return -1;
    }
    size = ftell(in);
    if (size < 0 || (size_t)size + 1u > out_size) {
        fclose(in);
        return -1;
    }
    if (fseek(in, 0, SEEK_SET) != 0) {
        fclose(in);
        return -1;
    }
    read_size = fread(out, 1u, (size_t)size, in);
    fclose(in);
    if (read_size != (size_t)size) {
        return -1;
    }
    out[read_size] = '\0';
    return 0;
}

int ninlil_abi_extract_markdown_c_blocks(
    const char *markdown_path,
    char *out,
    size_t out_size)
{
    char file[NINLIL_ABI_DRIFT_MAX_SOURCE];
    const char *cursor;
    size_t out_len = 0;

    if (read_file_to_buffer(markdown_path, file, sizeof(file)) != 0) {
        return -1;
    }
    out[0] = '\0';
    cursor = file;
    while (*cursor != '\0') {
        const char *fence = strstr(cursor, "```c");
        const char *end;
        const char *line_end;
        size_t chunk_len;

        if (fence == NULL) {
            break;
        }
        line_end = fence;
        while (line_end > cursor && line_end[-1] != '\n') {
            --line_end;
        }
        if (line_end != fence) {
            return -1;
        }
        cursor = fence + 4;
        if (*cursor == '\r') {
            ++cursor;
        }
        if (*cursor != '\n') {
            return -1;
        }
        ++cursor;
        end = strstr(cursor, "```");
        if (end == NULL) {
            return -1;
        }
        chunk_len = (size_t)(end - cursor);
        if (out_len + chunk_len + 2u >= out_size) {
            return -1;
        }
        memcpy(out + out_len, cursor, chunk_len);
        out_len += chunk_len;
        out[out_len++] = '\n';
        out[out_len] = '\0';
        cursor = end + 3;
    }
    if (out_len == 0u) {
        return -1;
    }
    return 0;
}

static void strip_comments(char *text)
{
    char *dst = text;
    const char *src = text;
    int in_line_comment = 0;
    int in_block_comment = 0;

    while (*src != '\0') {
        if (in_line_comment) {
            if (*src == '\n') {
                in_line_comment = 0;
                *dst++ = *src++;
            } else {
                ++src;
            }
            continue;
        }
        if (in_block_comment) {
            if (src[0] == '*' && src[1] == '/') {
                in_block_comment = 0;
                src += 2;
            } else {
                ++src;
            }
            continue;
        }
        if (src[0] == '/' && src[1] == '/') {
            in_line_comment = 1;
            src += 2;
            continue;
        }
        if (src[0] == '/' && src[1] == '*') {
            in_block_comment = 1;
            src += 2;
            continue;
        }
        *dst++ = *src++;
    }
    *dst = '\0';
}

static void expand_struct_header_macro(char *text)
{
    const char *needle = "NINLIL_STRUCT_HEADER;";
    const char *replacement = "uint16_t abi_version; uint16_t struct_size;";
    size_t needle_len = strlen(needle);
    size_t replacement_len = strlen(replacement);

    for (;;) {
        char *cursor = strstr(text, needle);
        size_t tail_len;
        if (cursor == NULL) {
            break;
        }
        tail_len = strlen(cursor + needle_len) + 1u;
        memmove(cursor + replacement_len, cursor + needle_len, tail_len);
        memcpy(cursor, replacement, replacement_len);
    }
}

static int is_include_guard_name(const char *name)
{
    size_t len = strlen(name);
    return len >= 3u && strcmp(name + len - 2u, "_H") == 0;
}

static int skip_line(const char *text, size_t *pos)
{
    while (text[*pos] != '\0' && text[*pos] != '\n') {
        ++(*pos);
    }
    if (text[*pos] == '\n') {
        ++(*pos);
    }
    return 0;
}

static int is_function_like_macro_params(const char *text, size_t pos)
{
    size_t p = pos + 1u;

    while (text[p] != '\0' && isspace((unsigned char)text[p])) {
        ++p;
    }
    if (text[p] == ')') {
        return 1;
    }
    if (!is_ident_start(text[p])) {
        return 0;
    }
    while (is_ident_char(text[p])) {
        ++p;
    }
    while (text[p] != '\0' && isspace((unsigned char)text[p])) {
        ++p;
    }
    return text[p] == ')' || text[p] == ',';
}

static int read_macro_value(
    const char *text,
    size_t *pos,
    char *out,
    size_t out_size)
{
    size_t out_i = 0;

    for (;;) {
        while (text[*pos] != '\0' && text[*pos] != '\n') {
            if (out_i + 1u < out_size) {
                out[out_i++] = text[*pos];
            }
            ++(*pos);
        }
        if (text[*pos] == '\0') {
            break;
        }
        if (out_i > 0u && out[out_i - 1u] == '\\') {
            --out_i;
            ++(*pos);
            while (text[*pos] != '\0' && isspace((unsigned char)text[*pos])) {
                ++(*pos);
            }
            continue;
        }
        ++(*pos);
        break;
    }
    if (out_i == 0u) {
        return -1;
    }
    out[out_i] = '\0';
    trim_inplace(out);
    return 0;
}

static int is_skippable_preprocessor_line(const char *line)
{
    if (strncmp(line, "#include", 8) == 0) {
        return 1;
    }
    if (strncmp(line, "#ifndef", 7) == 0) {
        return 1;
    }
    if (strncmp(line, "#endif", 6) == 0) {
        return 1;
    }
    if (strncmp(line, "#ifdef __cplusplus", 18) == 0) {
        return 1;
    }
    if (strcmp(line, "extern \"C\" {") == 0) {
        return 1;
    }
    if (strcmp(line, "}") == 0) {
        return 1;
    }
    if (strncmp(line, "#define ", 8) == 0) {
        char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
        size_t i = 8u;
        size_t name_i = 0;

        while (line[i] != '\0' && isspace((unsigned char)line[i])) {
            ++i;
        }
        while (line[i] != '\0' && !isspace((unsigned char)line[i])) {
            if (name_i + 1u < sizeof(name)) {
                name[name_i++] = line[i];
            }
            ++i;
        }
        name[name_i] = '\0';
        while (line[i] != '\0' && isspace((unsigned char)line[i])) {
            ++i;
        }
        if (line[i] == '\0' && is_include_guard_name(name)) {
            return 1;
        }
    }
    return 0;
}

static int read_logical_line(
    const char *text,
    size_t *pos,
    char *line,
    size_t line_size)
{
    size_t line_i = 0;

    for (;;) {
        while (text[*pos] != '\0' && text[*pos] != '\n') {
            if (line_i + 1u < line_size) {
                line[line_i++] = text[*pos];
            }
            ++(*pos);
        }
        if (text[*pos] == '\0') {
            break;
        }
        if (line_i > 0u && line[line_i - 1u] == '\\') {
            --line_i;
            ++(*pos);
            while (text[*pos] != '\0' && isspace((unsigned char)text[*pos])) {
                ++(*pos);
            }
            continue;
        }
        ++(*pos);
        break;
    }
    line[line_i] = '\0';
    trim_inplace(line);
    if (line_i == 0u && text[*pos] == '\0') {
        return -1;
    }
    return 0;
}

static void preprocess_source(char *text)
{
    char *lines = (char *)malloc(NINLIL_ABI_DRIFT_MAX_SOURCE);
    char *dst;
    size_t pos = 0;
    char line[4096];

    if (lines == NULL) {
        return;
    }

    strip_comments(text);
    expand_struct_header_macro(text);

    dst = lines;
    lines[0] = '\0';
    while (text[pos] != '\0') {
        if (read_logical_line(text, &pos, line, sizeof(line)) != 0) {
            break;
        }
        if (line[0] == '\0') {
            continue;
        }
        if (is_skippable_preprocessor_line(line)) {
            continue;
        }
        dst += snprintf(dst, (size_t)(lines + NINLIL_ABI_DRIFT_MAX_SOURCE - dst), "%s\n", line);
        if ((size_t)(dst - lines) + 1u >= NINLIL_ABI_DRIFT_MAX_SOURCE) {
            break;
        }
    }
    snprintf(text, NINLIL_ABI_DRIFT_MAX_SOURCE, "%s", lines);
    free(lines);
}

static int find_symbol_index(
    const char *name,
    const char names[][NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN],
    size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        if (strcmp(names[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int catalog_find_macro(const ninlil_abi_catalog_t *catalog, const char *name)
{
    size_t i;
    for (i = 0; i < catalog->macro_count; ++i) {
        if (strcmp(catalog->macros[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int catalog_find_typedef(const ninlil_abi_catalog_t *catalog, const char *name)
{
    size_t i;
    for (i = 0; i < catalog->typedef_count; ++i) {
        if (strcmp(catalog->typedefs[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int catalog_find_struct(const ninlil_abi_catalog_t *catalog, const char *name)
{
    size_t i;
    for (i = 0; i < catalog->struct_count; ++i) {
        if (strcmp(catalog->structs[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int catalog_find_callback(const ninlil_abi_catalog_t *catalog, const char *name)
{
    size_t i;
    for (i = 0; i < catalog->callback_count; ++i) {
        if (strcmp(catalog->callbacks[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int catalog_find_function(const ninlil_abi_catalog_t *catalog, const char *name)
{
    size_t i;
    for (i = 0; i < catalog->function_count; ++i) {
        if (strcmp(catalog->functions[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int skip_ws(const char *text, size_t *pos)
{
    while (text[*pos] != '\0' && isspace((unsigned char)text[*pos])) {
        ++(*pos);
    }
    return text[*pos] != '\0';
}

static int read_identifier(
    const char *text,
    size_t *pos,
    char *out,
    size_t out_size)
{
    size_t out_i = 0;
    if (!is_ident_start(text[*pos])) {
        return -1;
    }
    while (is_ident_char(text[*pos])) {
        if (out_i + 1u < out_size) {
            out[out_i++] = text[*pos];
        }
        ++(*pos);
    }
    if (out_i == 0u) {
        return -1;
    }
    out[out_i] = '\0';
    return 0;
}

static int read_until_semicolon(
    const char *text,
    size_t *pos,
    char *out,
    size_t out_size)
{
    size_t out_i = 0;
    int depth_paren = 0;
    int depth_brace = 0;
    int depth_bracket = 0;

    while (text[*pos] != '\0') {
        char c = text[*pos];
        if (c == '(') {
            ++depth_paren;
        } else if (c == ')') {
            --depth_paren;
        } else if (c == '{') {
            ++depth_brace;
        } else if (c == '}') {
            --depth_brace;
        } else if (c == '[') {
            ++depth_bracket;
        } else if (c == ']') {
            --depth_bracket;
        } else if (c == ';' && depth_paren == 0 && depth_brace == 0 && depth_bracket == 0) {
            ++(*pos);
            break;
        }
        if (out_i + 1u < out_size) {
            out[out_i++] = c;
        }
        ++(*pos);
    }
    out[out_i] = '\0';
    trim_inplace(out);
    return out_i > 0u ? 0 : -1;
}

static int split_function_decl(
    const char *decl,
    char *type_out,
    size_t type_size,
    char *name_out,
    size_t name_size)
{
    const char *open = strchr(decl, '(');
    size_t end;
    size_t start;

    if (open == NULL) {
        return -1;
    }
    end = (size_t)(open - decl);
    while (end > 0u && isspace((unsigned char)decl[end - 1u])) {
        --end;
    }
    start = end;
    while (start > 0u && is_ident_char(decl[start - 1u])) {
        --start;
    }
    if (start == end) {
        return -1;
    }
    snprintf(name_out, name_size, "%.*s", (int)(end - start), decl + start);
    trim_inplace(name_out);
    snprintf(type_out, type_size, "%.*s", (int)start, decl);
    trim_inplace(type_out);
    ninlil_abi_normalize_type(type_out, type_out, type_size);
    return is_ident_start(name_out[0]) ? 0 : -1;
}

static int split_field_decl(const char *decl, char *type_out, size_t type_size, char *name_out, size_t name_size)
{
    const char *fn = strstr(decl, "(*");
    char array_suffix[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
    size_t len = strlen(decl);
    size_t end = len;
    size_t name_start;
    size_t name_end;
    size_t suffix_start = len;

    array_suffix[0] = '\0';

    while (end > 0u && isspace((unsigned char)decl[end - 1u])) {
        --end;
    }
    if (end == 0u) {
        return -1;
    }

    if (fn != NULL) {
        const char *name_begin = fn + 2;
        const char *name_close = strchr(name_begin, ')');
        if (name_close == NULL) {
            return -1;
        }
        snprintf(name_out, name_size, "%.*s", (int)(name_close - name_begin), name_begin);
        trim_inplace(name_out);
        snprintf(
            type_out,
            type_size,
            "%.*s%s",
            (int)(fn - decl),
            decl,
            name_close + 1);
        trim_inplace(type_out);
        ninlil_abi_normalize_type(type_out, type_out, type_size);
        return is_ident_start(name_out[0]) ? 0 : -1;
    }

    while (suffix_start > 0u && decl[suffix_start - 1u] == ']') {
        size_t i = suffix_start - 1u;
        int depth = 0;
        while (i > 0u) {
            if (decl[i] == ']') {
                ++depth;
            } else if (decl[i] == '[') {
                --depth;
                if (depth == 0) {
                    suffix_start = i;
                    break;
                }
            }
            --i;
        }
        if (i == 0u) {
            return -1;
        }
    }
    if (suffix_start < len) {
        snprintf(array_suffix, sizeof(array_suffix), "%s", decl + suffix_start);
    }

    end = suffix_start;
    while (end > 0u && isspace((unsigned char)decl[end - 1u])) {
        --end;
    }
    name_end = end;
    name_start = end;
    while (name_start > 0u && is_ident_char(decl[name_start - 1u])) {
        --name_start;
    }
    if (name_start == name_end) {
        return -1;
    }

    snprintf(name_out, name_size, "%.*s", (int)(name_end - name_start), decl + name_start);
    trim_inplace(name_out);
    snprintf(type_out, type_size, "%.*s%s", (int)name_start, decl, array_suffix);
    trim_inplace(type_out);
    ninlil_abi_normalize_type(type_out, type_out, type_size);
    return is_ident_start(name_out[0]) ? 0 : -1;
}

static int add_macro(
    ninlil_abi_catalog_t *catalog,
    const char *name,
    ninlil_abi_macro_kind_t kind,
    const char *value,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    char norm_value[NINLIL_ABI_DRIFT_MAX_VALUE_LEN];
    int existing = catalog_find_macro(catalog, name);

    ninlil_abi_normalize_value(value, norm_value, sizeof(norm_value));
    if (existing >= 0) {
        if (catalog->macros[existing].kind != kind
            || strcmp(catalog->macros[existing].value, norm_value) != 0) {
            snprintf(
                error_out,
                error_out_size,
                "%s: duplicate macro %s with conflicting definition",
                label,
                name);
            return -1;
        }
        return 0;
    }
    if (catalog->macro_count >= NINLIL_ABI_DRIFT_MAX_MACROS) {
        return set_error(error_out, error_out_size, "macro table overflow");
    }
    snprintf(catalog->macros[catalog->macro_count].name, sizeof(catalog->macros[0].name), "%s", name);
    catalog->macros[catalog->macro_count].kind = kind;
    snprintf(catalog->macros[catalog->macro_count].value, sizeof(catalog->macros[0].value), "%s", norm_value);
    ++catalog->macro_count;
    return 0;
}

static int add_typedef(
    ninlil_abi_catalog_t *catalog,
    const char *name,
    const char *type,
    int is_opaque_struct,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    char norm_type[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
    int existing = catalog_find_typedef(catalog, name);

    ninlil_abi_normalize_type(type, norm_type, sizeof(norm_type));
    if (existing >= 0) {
        if (catalog->typedefs[existing].is_opaque_struct != is_opaque_struct
            || strcmp(catalog->typedefs[existing].type, norm_type) != 0) {
            snprintf(
                error_out,
                error_out_size,
                "%s: duplicate typedef %s with conflicting definition",
                label,
                name);
            return -1;
        }
        return 0;
    }
    if (catalog->typedef_count >= NINLIL_ABI_DRIFT_MAX_TYPEDEFS) {
        return set_error(error_out, error_out_size, "typedef table overflow");
    }
    snprintf(catalog->typedefs[catalog->typedef_count].name, sizeof(catalog->typedefs[0].name), "%s", name);
    snprintf(catalog->typedefs[catalog->typedef_count].type, sizeof(catalog->typedefs[0].type), "%s", norm_type);
    catalog->typedefs[catalog->typedef_count].is_opaque_struct = is_opaque_struct;
    ++catalog->typedef_count;
    return 0;
}

static int add_struct(
    ninlil_abi_catalog_t *catalog,
    const ninlil_abi_struct_entry_t *entry,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    int existing = catalog_find_struct(catalog, entry->name);
    size_t i;

    if (existing >= 0) {
        ninlil_abi_struct_entry_t *dst = &catalog->structs[existing];
        if (dst->field_count != entry->field_count) {
            snprintf(
                error_out,
                error_out_size,
                "%s: duplicate struct %s with conflicting field count",
                label,
                entry->name);
            return -1;
        }
        for (i = 0; i < entry->field_count; ++i) {
            if (strcmp(dst->fields[i].name, entry->fields[i].name) != 0
                || strcmp(dst->fields[i].type, entry->fields[i].type) != 0) {
                snprintf(
                    error_out,
                    error_out_size,
                    "%s: duplicate struct %s with conflicting fields",
                    label,
                    entry->name);
                return -1;
            }
        }
        return 0;
    }
    if (catalog->struct_count >= NINLIL_ABI_DRIFT_MAX_STRUCTS) {
        return set_error(error_out, error_out_size, "struct table overflow");
    }
    catalog->structs[catalog->struct_count] = *entry;
    ++catalog->struct_count;
    return 0;
}

static int add_callback(
    ninlil_abi_catalog_t *catalog,
    const char *name,
    const char *signature,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    char norm_sig[NINLIL_ABI_DRIFT_MAX_SIG_LEN];
    int existing = catalog_find_callback(catalog, name);

    collapse_spaces(signature, norm_sig, sizeof(norm_sig));
    trim_inplace(norm_sig);
    if (existing >= 0) {
        if (strcmp(catalog->callbacks[existing].signature, norm_sig) != 0) {
            snprintf(
                error_out,
                error_out_size,
                "%s: duplicate callback typedef %s with conflicting signature",
                label,
                name);
            return -1;
        }
        return 0;
    }
    if (catalog->callback_count >= NINLIL_ABI_DRIFT_MAX_CALLBACKS) {
        return set_error(error_out, error_out_size, "callback table overflow");
    }
    snprintf(catalog->callbacks[catalog->callback_count].name, sizeof(catalog->callbacks[0].name), "%s", name);
    snprintf(
        catalog->callbacks[catalog->callback_count].signature,
        sizeof(catalog->callbacks[0].signature),
        "%s",
        norm_sig);
    ++catalog->callback_count;
    return 0;
}

static int add_function(
    ninlil_abi_catalog_t *catalog,
    const char *name,
    const char *signature,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    char norm_sig[NINLIL_ABI_DRIFT_MAX_SIG_LEN];
    int existing = catalog_find_function(catalog, name);

    collapse_spaces(signature, norm_sig, sizeof(norm_sig));
    trim_inplace(norm_sig);
    if (existing >= 0) {
        if (strcmp(catalog->functions[existing].signature, norm_sig) != 0) {
            snprintf(
                error_out,
                error_out_size,
                "%s: duplicate function %s with conflicting signature",
                label,
                name);
            return -1;
        }
        return 0;
    }
    if (catalog->function_count >= NINLIL_ABI_DRIFT_MAX_FUNCTIONS) {
        return set_error(error_out, error_out_size, "function table overflow");
    }
    snprintf(catalog->functions[catalog->function_count].name, sizeof(catalog->functions[0].name), "%s", name);
    snprintf(
        catalog->functions[catalog->function_count].signature,
        sizeof(catalog->functions[0].signature),
        "%s",
        norm_sig);
    ++catalog->function_count;
    return 0;
}

static int parse_define(
    const char *text,
    size_t *pos,
    ninlil_abi_catalog_t *catalog,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    char value[NINLIL_ABI_DRIFT_MAX_VALUE_LEN];
    ninlil_abi_macro_kind_t kind = NINLIL_ABI_MACRO_OBJECT;

    *pos += 7;
    if (!skip_ws(text, pos)) {
        return set_error(error_out, error_out_size, "expected macro name after #define");
    }
    if (read_identifier(text, pos, name, sizeof(name)) != 0) {
        return set_error(error_out, error_out_size, "invalid macro name");
    }
    if (is_include_guard_name(name)) {
        return skip_line(text, pos);
    }
    if (!skip_ws(text, pos)) {
        return set_error(error_out, error_out_size, "expected macro value");
    }
    if (text[*pos] == '(' && is_function_like_macro_params(text, *pos)) {
        size_t value_i = 0;
        int depth = 0;

        kind = NINLIL_ABI_MACRO_FUNCTION;
        do {
            char c = text[*pos];
            if (c == '\0') {
                return set_error(error_out, error_out_size, "unterminated function-like macro");
            }
            if (value_i + 1u < sizeof(value)) {
                value[value_i++] = c;
            }
            ++(*pos);
            if (c == '(') {
                ++depth;
            } else if (c == ')') {
                --depth;
            }
        } while (depth > 0);
        value[value_i] = '\0';
        if (skip_ws(text, pos)) {
            char body[NINLIL_ABI_DRIFT_MAX_VALUE_LEN];
            size_t save = *pos;
            if (read_macro_value(text, pos, body, sizeof(body)) == 0) {
                if (value_i + 1u < sizeof(value)) {
                    value[value_i++] = ' ';
                }
                snprintf(value + value_i, sizeof(value) - value_i, "%s", body);
            } else {
                *pos = save;
            }
        }
    } else if (read_macro_value(text, pos, value, sizeof(value)) != 0) {
        return set_error(error_out, error_out_size, "invalid macro value");
    }
    return add_macro(catalog, name, kind, value, label, error_out, error_out_size);
}

static int is_callback_typedef_decl(const char *decl, char *name_out, size_t name_out_size)
{
    const char *star_paren = strstr(decl, "(*");
    const char *close;
    const char *open_params;

    if (star_paren == NULL) {
        return 0;
    }
    close = strchr(star_paren + 2, ')');
    if (close == NULL) {
        return 0;
    }
    open_params = close + 1;
    while (*open_params != '\0' && isspace((unsigned char)*open_params)) {
        ++open_params;
    }
    if (*open_params != '(') {
        return 0;
    }
    snprintf(name_out, name_out_size, "%.*s", (int)(close - (star_paren + 2)), star_paren + 2);
    trim_inplace(name_out);
    return is_ident_start(name_out[0]) ? 1 : 0;
}

static int parse_struct_body(
    const char *text,
    size_t *pos,
    const char *tag,
    ninlil_abi_struct_entry_t *entry,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    int depth = 0;

    if (text[*pos] != '{') {
        return set_error(error_out, error_out_size, "expected struct body");
    }
    ++(*pos);
    snprintf(entry->name, sizeof(entry->name), "%s", tag);
    entry->field_count = 0;
    depth = 1;
    while (text[*pos] != '\0' && depth > 0) {
        char decl[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
        char type[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
        char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];

        if (!skip_ws(text, pos)) {
            return set_error(error_out, error_out_size, "unterminated struct body");
        }
        if (text[*pos] == '}') {
            --depth;
            ++(*pos);
            continue;
        }
        if (text[*pos] == '{') {
            return set_error(error_out, error_out_size, "nested struct body not supported");
        }
        if (read_until_semicolon(text, pos, decl, sizeof(decl)) != 0) {
            return set_error(error_out, error_out_size, "invalid struct field");
        }
        if (split_field_decl(decl, type, sizeof(type), name, sizeof(name)) != 0) {
            snprintf(
                error_out,
                error_out_size,
                "%s: unparseable struct field in %s: %s",
                label,
                entry->name,
                decl);
            return -1;
        }
        if (entry->field_count >= NINLIL_ABI_DRIFT_MAX_FIELDS) {
            return set_error(error_out, error_out_size, "struct field overflow");
        }
        snprintf(entry->fields[entry->field_count].name, sizeof(entry->fields[0].name), "%s", name);
        snprintf(entry->fields[entry->field_count].type, sizeof(entry->fields[0].type), "%s", type);
        ++entry->field_count;
    }
    return 0;
}

static int parse_typedef(
    const char *text,
    size_t *pos,
    ninlil_abi_catalog_t *catalog,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    char first[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    char second[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    ninlil_abi_struct_entry_t *entry;
    char tag[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];

    *pos += 7;
    if (!skip_ws(text, pos)) {
        return set_error(error_out, error_out_size, "expected tokens after typedef");
    }

    if (strncmp(text + *pos, "struct", 6) == 0 && isspace((unsigned char)text[*pos + 6])) {
        *pos += 6;
        if (!skip_ws(text, pos)) {
            return set_error(error_out, error_out_size, "expected struct tag");
        }
        if (read_identifier(text, pos, tag, sizeof(tag)) != 0) {
            return set_error(error_out, error_out_size, "invalid struct tag");
        }
        if (!skip_ws(text, pos)) {
            return set_error(error_out, error_out_size, "expected struct body or alias");
        }
        if (text[*pos] == '{') {
            entry = (ninlil_abi_struct_entry_t *)calloc(1, sizeof(*entry));
            if (entry == NULL) {
                return set_error(error_out, error_out_size, "out of memory");
            }
            if (parse_struct_body(text, pos, tag, entry, label, error_out, error_out_size) != 0) {
                free(entry);
                return -1;
            }
            if (!skip_ws(text, pos)) {
                free(entry);
                return set_error(error_out, error_out_size, "expected struct typedef name");
            }
            if (read_identifier(text, pos, entry->name, sizeof(entry->name)) != 0) {
                free(entry);
                return set_error(error_out, error_out_size, "invalid struct typedef name");
            }
            if (text[*pos] == ';') {
                ++(*pos);
            }
            if (add_struct(catalog, entry, label, error_out, error_out_size) != 0) {
                free(entry);
                return -1;
            }
            free(entry);
            return 0;
        }
        {
            char type[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
            char decl[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
            if (read_until_semicolon(text, pos, decl, sizeof(decl)) != 0) {
                return set_error(error_out, error_out_size, "unterminated opaque struct typedef");
            }
            snprintf(type, sizeof(type), "struct %s", tag);
            return add_typedef(catalog, decl, type, 1, label, error_out, error_out_size);
        }
    }

    {
        char decl[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
        if (read_until_semicolon(text, pos, decl, sizeof(decl)) != 0) {
            return set_error(error_out, error_out_size, "unterminated typedef");
        }
        if (is_callback_typedef_decl(decl, second, sizeof(second))) {
            return add_callback(catalog, second, decl, label, error_out, error_out_size);
        }
        if (split_field_decl(decl, first, sizeof(first), second, sizeof(second)) != 0) {
            snprintf(
                error_out,
                error_out_size,
                "%s: unparseable typedef: %s",
                label,
                decl);
            return -1;
        }
        return add_typedef(catalog, second, first, 0, label, error_out, error_out_size);
    }
}

static int parse_function(
    const char *text,
    size_t *pos,
    ninlil_abi_catalog_t *catalog,
    const char *label,
    char *error_out,
    size_t error_out_size)
{
    char decl[NINLIL_ABI_DRIFT_MAX_SIG_LEN];
    char type[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];

    if (read_until_semicolon(text, pos, decl, sizeof(decl)) != 0) {
        return set_error(error_out, error_out_size, "invalid function declaration");
    }
    if (strstr(decl, "ninlil_") == NULL || strchr(decl, '(') == NULL) {
        return 0;
    }
    if (split_function_decl(decl, type, sizeof(type), name, sizeof(name)) != 0) {
        snprintf(
            error_out,
            error_out_size,
            "%s: unparseable function declaration: %s",
            label,
            decl);
        return -1;
    }
    if (strncmp(name, "ninlil_", 7) != 0) {
        return 0;
    }
    return add_function(catalog, name, decl, label, error_out, error_out_size);
}

int ninlil_abi_parse_translation_unit(
    const char *source,
    const char *label,
    ninlil_abi_catalog_t *out,
    char *error_out,
    size_t error_out_size)
{
    char *buffer;
    size_t pos = 0;
    size_t source_len = strlen(source);

    if (source_len + 1u > NINLIL_ABI_DRIFT_MAX_SOURCE) {
        return set_error(error_out, error_out_size, "source too large");
    }
    buffer = (char *)malloc(NINLIL_ABI_DRIFT_MAX_SOURCE);
    if (buffer == NULL) {
        return set_error(error_out, error_out_size, "out of memory");
    }
    snprintf(buffer, NINLIL_ABI_DRIFT_MAX_SOURCE, "%s", source);
    preprocess_source(buffer);

    while (buffer[pos] != '\0') {
        if (!skip_ws(buffer, &pos)) {
            break;
        }
        if (strncmp(buffer + pos, "#define", 7) == 0) {
            if (parse_define(buffer, &pos, out, label, error_out, error_out_size) != 0) {
                goto fail;
            }
            continue;
        }
        if (strncmp(buffer + pos, "typedef", 7) == 0) {
            if (parse_typedef(buffer, &pos, out, label, error_out, error_out_size) != 0) {
                goto fail;
            }
            continue;
        }
        if (strncmp(buffer + pos, "ninlil_status_t", 15) == 0
            && isspace((unsigned char)buffer[pos + 15])) {
            if (parse_function(buffer, &pos, out, label, error_out, error_out_size) != 0) {
                goto fail;
            }
            continue;
        }
        {
            char nearby[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
            size_t save = pos;
            if (read_identifier(buffer, &pos, nearby, sizeof(nearby)) == 0) {
                snprintf(
                    error_out,
                    error_out_size,
                    "%s: unparseable top-level declaration near '%s'",
                    label,
                    nearby);
            } else {
                snprintf(
                    error_out,
                    error_out_size,
                    "%s: unparseable top-level input at offset %zu",
                    label,
                    save);
            }
            goto fail;
        }
    }
    free(buffer);
    return 0;

fail:
    free(buffer);
    return -1;
}

int ninlil_abi_merge_catalog(
    ninlil_abi_catalog_t *dest,
    const ninlil_abi_catalog_t *src,
    const char *src_label,
    char *error_out,
    size_t error_out_size)
{
    size_t i;

    for (i = 0; i < src->macro_count; ++i) {
        if (add_macro(
                dest,
                src->macros[i].name,
                src->macros[i].kind,
                src->macros[i].value,
                src_label,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
    }
    for (i = 0; i < src->typedef_count; ++i) {
        if (add_typedef(
                dest,
                src->typedefs[i].name,
                src->typedefs[i].type,
                src->typedefs[i].is_opaque_struct,
                src_label,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
    }
    for (i = 0; i < src->struct_count; ++i) {
        if (add_struct(dest, &src->structs[i], src_label, error_out, error_out_size) != 0) {
            return -1;
        }
    }
    for (i = 0; i < src->callback_count; ++i) {
        if (add_callback(
                dest,
                src->callbacks[i].name,
                src->callbacks[i].signature,
                src_label,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
    }
    for (i = 0; i < src->function_count; ++i) {
        if (add_function(
                dest,
                src->functions[i].name,
                src->functions[i].signature,
                src_label,
                error_out,
                error_out_size)
            != 0) {
            return -1;
        }
    }
    return 0;
}

static int compare_macro_lists(
    const ninlil_abi_catalog_t *doc,
    const ninlil_abi_catalog_t *header,
    FILE *err)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < doc->macro_count; ++i) {
        int idx = catalog_find_macro(header, doc->macros[i].name);
        if (idx < 0) {
            fprintf(err, "abi drift: macro %s missing from header\n", doc->macros[i].name);
            failed = 1;
            continue;
        }
        if (header->macros[idx].kind != doc->macros[i].kind) {
            fprintf(
                err,
                "abi drift: macro %s kind mismatch (doc=%d header=%d)\n",
                doc->macros[i].name,
                (int)doc->macros[i].kind,
                (int)header->macros[idx].kind);
            failed = 1;
            continue;
        }
        if (strcmp(header->macros[idx].value, doc->macros[i].value) != 0) {
            fprintf(
                err,
                "abi drift: macro %s value mismatch\n  doc:    %s\n  header: %s\n",
                doc->macros[i].name,
                doc->macros[i].value,
                header->macros[idx].value);
            failed = 1;
        }
    }
    for (i = 0; i < header->macro_count; ++i) {
        if (catalog_find_macro(doc, header->macros[i].name) < 0) {
            fprintf(err, "abi drift: macro %s extra in header\n", header->macros[i].name);
            failed = 1;
        }
    }
    return failed ? -1 : 0;
}

static int compare_typedef_lists(
    const ninlil_abi_catalog_t *doc,
    const ninlil_abi_catalog_t *header,
    FILE *err)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < doc->typedef_count; ++i) {
        int idx = catalog_find_typedef(header, doc->typedefs[i].name);
        if (idx < 0) {
            fprintf(err, "abi drift: typedef %s missing from header\n", doc->typedefs[i].name);
            failed = 1;
            continue;
        }
        if (header->typedefs[idx].is_opaque_struct != doc->typedefs[i].is_opaque_struct
            || strcmp(header->typedefs[idx].type, doc->typedefs[i].type) != 0) {
            fprintf(
                err,
                "abi drift: typedef %s mismatch\n  doc:    %s\n  header: %s\n",
                doc->typedefs[i].name,
                doc->typedefs[i].type,
                header->typedefs[idx].type);
            failed = 1;
        }
    }
    for (i = 0; i < header->typedef_count; ++i) {
        if (catalog_find_typedef(doc, header->typedefs[i].name) < 0) {
            fprintf(err, "abi drift: typedef %s extra in header\n", header->typedefs[i].name);
            failed = 1;
        }
    }
    return failed ? -1 : 0;
}

static int compare_struct_lists(
    const ninlil_abi_catalog_t *doc,
    const ninlil_abi_catalog_t *header,
    FILE *err)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < doc->struct_count; ++i) {
        int idx = catalog_find_struct(header, doc->structs[i].name);
        size_t f;

        if (idx < 0) {
            fprintf(err, "abi drift: struct %s missing from header\n", doc->structs[i].name);
            failed = 1;
            continue;
        }
        if (header->structs[idx].field_count != doc->structs[i].field_count) {
            fprintf(
                err,
                "abi drift: struct %s field count mismatch (doc=%zu header=%zu)\n",
                doc->structs[i].name,
                doc->structs[i].field_count,
                header->structs[idx].field_count);
            failed = 1;
            continue;
        }
        for (f = 0; f < doc->structs[i].field_count; ++f) {
            if (strcmp(header->structs[idx].fields[f].name, doc->structs[i].fields[f].name) != 0) {
                fprintf(
                    err,
                    "abi drift: struct %s field[%zu] name mismatch (doc=%s header=%s)\n",
                    doc->structs[i].name,
                    f,
                    doc->structs[i].fields[f].name,
                    header->structs[idx].fields[f].name);
                failed = 1;
            } else if (strcmp(header->structs[idx].fields[f].type, doc->structs[i].fields[f].type) != 0) {
                fprintf(
                    err,
                    "abi drift: struct %s field %s type mismatch\n  doc:    %s\n  header: %s\n",
                    doc->structs[i].name,
                    doc->structs[i].fields[f].name,
                    doc->structs[i].fields[f].type,
                    header->structs[idx].fields[f].type);
                failed = 1;
            }
        }
    }
    for (i = 0; i < header->struct_count; ++i) {
        if (catalog_find_struct(doc, header->structs[i].name) < 0) {
            fprintf(err, "abi drift: struct %s extra in header\n", header->structs[i].name);
            failed = 1;
        }
    }
    return failed ? -1 : 0;
}

static int compare_callback_lists(
    const ninlil_abi_catalog_t *doc,
    const ninlil_abi_catalog_t *header,
    FILE *err)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < doc->callback_count; ++i) {
        int idx = catalog_find_callback(header, doc->callbacks[i].name);
        if (idx < 0) {
            fprintf(err, "abi drift: callback %s missing from header\n", doc->callbacks[i].name);
            failed = 1;
            continue;
        }
        if (strcmp(header->callbacks[idx].signature, doc->callbacks[i].signature) != 0) {
            fprintf(
                err,
                "abi drift: callback %s signature mismatch\n  doc:    %s\n  header: %s\n",
                doc->callbacks[i].name,
                doc->callbacks[i].signature,
                header->callbacks[idx].signature);
            failed = 1;
        }
    }
    for (i = 0; i < header->callback_count; ++i) {
        if (catalog_find_callback(doc, header->callbacks[i].name) < 0) {
            fprintf(err, "abi drift: callback %s extra in header\n", header->callbacks[i].name);
            failed = 1;
        }
    }
    return failed ? -1 : 0;
}

static int compare_function_lists(
    const ninlil_abi_catalog_t *doc,
    const ninlil_abi_catalog_t *header,
    FILE *err)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < doc->function_count; ++i) {
        int idx = catalog_find_function(header, doc->functions[i].name);
        if (idx < 0) {
            fprintf(err, "abi drift: function %s missing from header\n", doc->functions[i].name);
            failed = 1;
            continue;
        }
        if (strcmp(header->functions[idx].signature, doc->functions[i].signature) != 0) {
            fprintf(
                err,
                "abi drift: function %s signature mismatch\n  doc:    %s\n  header: %s\n",
                doc->functions[i].name,
                doc->functions[i].signature,
                header->functions[idx].signature);
            failed = 1;
        }
    }
    for (i = 0; i < header->function_count; ++i) {
        if (catalog_find_function(doc, header->functions[i].name) < 0) {
            fprintf(err, "abi drift: function %s extra in header\n", header->functions[i].name);
            failed = 1;
        }
    }
    return failed ? -1 : 0;
}

int ninlil_abi_compare_catalogs(
    const ninlil_abi_catalog_t *doc,
    const ninlil_abi_catalog_t *header,
    FILE *err)
{
    int result = 0;

    if (compare_macro_lists(doc, header, err) != 0) {
        result = -1;
    }
    if (compare_typedef_lists(doc, header, err) != 0) {
        result = -1;
    }
    if (compare_struct_lists(doc, header, err) != 0) {
        result = -1;
    }
    if (compare_callback_lists(doc, header, err) != 0) {
        result = -1;
    }
    if (compare_function_lists(doc, header, err) != 0) {
        result = -1;
    }
    return result;
}

int ninlil_abi_parse_manifest_inventory(
    const char *constants_inc_path,
    const char *structs_inc_path,
    ninlil_abi_manifest_inventory_t *out,
    char *error_out,
    size_t error_out_size)
{
    char constants[NINLIL_ABI_DRIFT_MAX_SOURCE];
    char structs[NINLIL_ABI_DRIFT_MAX_SOURCE];
    const char *cursor;

    memset(out, 0, sizeof(*out));
    if (read_file_to_buffer(constants_inc_path, constants, sizeof(constants)) != 0) {
        return set_error(error_out, error_out_size, "cannot read constants inventory");
    }
    if (read_file_to_buffer(structs_inc_path, structs, sizeof(structs)) != 0) {
        return set_error(error_out, error_out_size, "cannot read structs inventory");
    }

    cursor = constants;
    while ((cursor = strstr(cursor, "MANIFEST_CONST(")) != NULL) {
        const char *start = cursor + 15;
        const char *end = strchr(start, ')');
        if (end == NULL || (size_t)(end - start) >= NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN) {
            return set_error(error_out, error_out_size, "invalid MANIFEST_CONST entry");
        }
        if (out->constant_count >= NINLIL_ABI_DRIFT_MAX_MACROS) {
            return set_error(error_out, error_out_size, "manifest constant overflow");
        }
        snprintf(
            out->constants[out->constant_count],
            NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN,
            "%.*s",
            (int)(end - start),
            start);
        ++out->constant_count;
        cursor = end + 1;
    }

    cursor = structs;
    while ((cursor = strstr(cursor, "MANIFEST_STRUCT_BEGIN(")) != NULL) {
        const char *start = cursor + 22;
        const char *end = strchr(start, ')');
        if (end == NULL || (size_t)(end - start) >= NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN) {
            return set_error(error_out, error_out_size, "invalid MANIFEST_STRUCT_BEGIN entry");
        }
        if (out->struct_count >= NINLIL_ABI_DRIFT_MAX_STRUCTS) {
            return set_error(error_out, error_out_size, "manifest struct overflow");
        }
        snprintf(
            out->structs[out->struct_count],
            NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN,
            "%.*s",
            (int)(end - start),
            start);
        ++out->struct_count;
        cursor = end + 1;
    }

    cursor = structs;
    while ((cursor = strstr(cursor, "MANIFEST_FIELD(")) != NULL) {
        const char *start = cursor + 15;
        const char *comma = strchr(start, ',');
        const char *end = strchr(start, ')');
        if (comma == NULL || end == NULL || comma > end) {
            return set_error(error_out, error_out_size, "invalid MANIFEST_FIELD entry");
        }
        if (out->field_count >= NINLIL_ABI_DRIFT_MAX_STRUCTS * NINLIL_ABI_DRIFT_MAX_FIELDS) {
            return set_error(error_out, error_out_size, "manifest field overflow");
        }
        snprintf(
            out->fields[out->field_count].struct_name,
            NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN,
            "%.*s",
            (int)(comma - start),
            start);
        {
            const char *field_start = comma + 1;
            while (*field_start == ' ') {
                ++field_start;
            }
            snprintf(
                out->fields[out->field_count].field_name,
                NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN,
                "%.*s",
                (int)(end - field_start),
                field_start);
        }
        ++out->field_count;
        cursor = end + 1;
    }
    return 0;
}

static int is_manifest_constant_candidate(const ninlil_abi_macro_entry_t *macro)
{
    return macro->kind == NINLIL_ABI_MACRO_OBJECT
           && strncmp(macro->name, "NINLIL_", 7) == 0
           && strcmp(macro->name, "NINLIL_STRUCT_HEADER") != 0;
}

int ninlil_abi_count_header_manifest_symbols(
    const ninlil_abi_catalog_t *header,
    size_t *out_constants,
    size_t *out_structs,
    size_t *out_fields)
{
    size_t i;
    size_t constants = 0;
    size_t fields = 0;

    for (i = 0; i < header->macro_count; ++i) {
        if (is_manifest_constant_candidate(&header->macros[i])) {
            ++constants;
        }
    }
    for (i = 0; i < header->struct_count; ++i) {
        fields += header->structs[i].field_count;
    }
    *out_constants = constants;
    *out_structs = header->struct_count;
    *out_fields = fields;
    return 0;
}

int ninlil_abi_compare_header_manifest(
    const ninlil_abi_catalog_t *header,
    const ninlil_abi_manifest_inventory_t *manifest,
    FILE *err)
{
    size_t i;
    size_t f;
    int failed = 0;
    size_t expected_constants = 0;
    size_t expected_structs = 0;
    size_t expected_fields = 0;

    ninlil_abi_count_header_manifest_symbols(header, &expected_constants, &expected_structs, &expected_fields);

    if (expected_constants != NINLIL_ABI_MANIFEST_EXPECTED_CONSTANTS
        || expected_structs != NINLIL_ABI_MANIFEST_EXPECTED_STRUCTS
        || expected_fields != NINLIL_ABI_MANIFEST_EXPECTED_FIELDS) {
        fprintf(
            err,
            "abi drift: header manifest symbol counts (%zu,%zu,%zu) != expected (%u,%u,%u)\n",
            expected_constants,
            expected_structs,
            expected_fields,
            NINLIL_ABI_MANIFEST_EXPECTED_CONSTANTS,
            NINLIL_ABI_MANIFEST_EXPECTED_STRUCTS,
            NINLIL_ABI_MANIFEST_EXPECTED_FIELDS);
        failed = 1;
    }
    if (manifest->constant_count != expected_constants) {
        fprintf(
            err,
            "abi drift: manifest constants.inc count %zu != header %zu\n",
            manifest->constant_count,
            expected_constants);
        failed = 1;
    }
    if (manifest->struct_count != expected_structs) {
        fprintf(
            err,
            "abi drift: manifest structs.inc struct count %zu != header %zu\n",
            manifest->struct_count,
            expected_structs);
        failed = 1;
    }
    if (manifest->field_count != expected_fields) {
        fprintf(
            err,
            "abi drift: manifest structs.inc field count %zu != header %zu\n",
            manifest->field_count,
            expected_fields);
        failed = 1;
    }

    for (i = 0; i < header->macro_count; ++i) {
        if (!is_manifest_constant_candidate(&header->macros[i])) {
            continue;
        }
        if (find_symbol_index(
                header->macros[i].name,
                manifest->constants,
                manifest->constant_count)
            < 0) {
            fprintf(
                err,
                "abi drift: manifest inventory missing constant %s\n",
                header->macros[i].name);
            failed = 1;
        }
    }
    for (i = 0; i < manifest->constant_count; ++i) {
        if (catalog_find_macro(header, manifest->constants[i]) < 0
            || !is_manifest_constant_candidate(
                &header->macros[catalog_find_macro(header, manifest->constants[i])])) {
            fprintf(
                err,
                "abi drift: manifest inventory extra constant %s\n",
                manifest->constants[i]);
            failed = 1;
        }
    }

    for (i = 0; i < header->struct_count; ++i) {
        if (find_symbol_index(
                header->structs[i].name,
                manifest->structs,
                manifest->struct_count)
            < 0) {
            fprintf(
                err,
                "abi drift: manifest inventory missing struct %s\n",
                header->structs[i].name);
            failed = 1;
        }
        for (f = 0; f < header->structs[i].field_count; ++f) {
            size_t j;
            int found = 0;
            for (j = 0; j < manifest->field_count; ++j) {
                if (strcmp(manifest->fields[j].struct_name, header->structs[i].name) == 0
                    && strcmp(manifest->fields[j].field_name, header->structs[i].fields[f].name) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(
                    err,
                    "abi drift: manifest inventory missing field %s.%s\n",
                    header->structs[i].name,
                    header->structs[i].fields[f].name);
                failed = 1;
            }
        }
    }

    for (i = 0; i < manifest->struct_count; ++i) {
        if (catalog_find_struct(header, manifest->structs[i]) < 0) {
            fprintf(
                err,
                "abi drift: manifest inventory extra struct %s\n",
                manifest->structs[i]);
            failed = 1;
        }
    }
    for (i = 0; i < manifest->field_count; ++i) {
        int struct_idx = catalog_find_struct(header, manifest->fields[i].struct_name);
        if (struct_idx < 0) {
            fprintf(
                err,
                "abi drift: manifest inventory extra field %s.%s\n",
                manifest->fields[i].struct_name,
                manifest->fields[i].field_name);
            failed = 1;
            continue;
        }
        {
            size_t j;
            int found = 0;
            for (j = 0; j < header->structs[struct_idx].field_count; ++j) {
                if (strcmp(header->structs[struct_idx].fields[j].name, manifest->fields[i].field_name) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(
                    err,
                    "abi drift: manifest inventory extra field %s.%s\n",
                    manifest->fields[i].struct_name,
                    manifest->fields[i].field_name);
                failed = 1;
            }
        }
    }

    return failed ? -1 : 0;
}

static int parse_header_file(
    const char *path,
    const char *label,
    ninlil_abi_catalog_t *catalog,
    char *error_out,
    size_t error_out_size)
{
    char *source;
    ninlil_abi_catalog_t *partial;
    int result = -1;

    source = (char *)malloc(NINLIL_ABI_DRIFT_MAX_SOURCE);
    if (source == NULL) {
        return set_error(error_out, error_out_size, "out of memory");
    }
    if (read_file_to_buffer(path, source, NINLIL_ABI_DRIFT_MAX_SOURCE) != 0) {
        snprintf(error_out, error_out_size, "cannot read %s", path);
        free(source);
        return -1;
    }
    partial = (ninlil_abi_catalog_t *)calloc(1, sizeof(*partial));
    if (partial == NULL) {
        set_error(error_out, error_out_size, "out of memory");
        free(source);
        return -1;
    }
    if (ninlil_abi_parse_translation_unit(source, label, partial, error_out, error_out_size) != 0) {
        goto cleanup;
    }
    if (ninlil_abi_merge_catalog(catalog, partial, label, error_out, error_out_size) != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    free(partial);
    free(source);
    return result;
}

int ninlil_abi_run_repository_check(
    const char *repo_root,
    ninlil_abi_catalog_counts_t *out_counts,
    FILE *err)
{
    static const char *const k_headers[] = {
        "include/ninlil/version.h",
        "include/ninlil/platform.h",
        "include/ninlil/service.h",
        "include/ninlil/transaction.h",
        "include/ninlil/runtime.h",
    };
    char doc_path[512];
    char constants_path[512];
    char structs_path[512];
    char header_path[512];
    char error[NINLIL_ABI_DRIFT_MAX_ERROR];
    ninlil_abi_catalog_t *doc;
    ninlil_abi_catalog_t *header;
    ninlil_abi_manifest_inventory_t manifest;
    size_t i;
    int result = -1;
    char *doc_source = NULL;

    doc = (ninlil_abi_catalog_t *)calloc(1, sizeof(*doc));
    header = (ninlil_abi_catalog_t *)calloc(1, sizeof(*header));
    if (doc == NULL || header == NULL) {
        fprintf(err, "abi drift: out of memory\n");
        free(doc);
        free(header);
        return -1;
    }

    snprintf(doc_path, sizeof(doc_path), "%s/docs/12-foundation-abi.md", repo_root);
    snprintf(constants_path, sizeof(constants_path), "%s/tools/abi_manifest_constants.inc", repo_root);
    snprintf(structs_path, sizeof(structs_path), "%s/tools/abi_manifest_structs.inc", repo_root);

    doc_source = (char *)malloc(NINLIL_ABI_DRIFT_MAX_SOURCE);
    if (doc_source == NULL) {
        fprintf(err, "abi drift: out of memory\n");
        goto cleanup;
    }

    if (ninlil_abi_extract_markdown_c_blocks(doc_path, doc_source, NINLIL_ABI_DRIFT_MAX_SOURCE) != 0) {
        fprintf(err, "abi drift: cannot extract markdown C blocks from %s\n", doc_path);
        goto cleanup;
    }
    if (ninlil_abi_parse_translation_unit(doc_source, "docs/12", doc, error, sizeof(error)) != 0) {
        fprintf(err, "abi drift: doc parse error: %s\n", error);
        goto cleanup;
    }

    for (i = 0; i < sizeof(k_headers) / sizeof(k_headers[0]); ++i) {
        snprintf(header_path, sizeof(header_path), "%s/%s", repo_root, k_headers[i]);
        if (parse_header_file(header_path, k_headers[i], header, error, sizeof(error)) != 0) {
            fprintf(err, "abi drift: header parse error: %s\n", error);
            goto cleanup;
        }
    }

    if (ninlil_abi_parse_manifest_inventory(
            constants_path,
            structs_path,
            &manifest,
            error,
            sizeof(error))
        != 0) {
        fprintf(err, "abi drift: manifest inventory parse error: %s\n", error);
        goto cleanup;
    }

    if (ninlil_abi_compare_catalogs(doc, header, err) != 0) {
        goto cleanup;
    }
    if (ninlil_abi_compare_header_manifest(header, &manifest, err) != 0) {
        goto cleanup;
    }

    if (out_counts != NULL) {
        memset(out_counts, 0, sizeof(*out_counts));
        out_counts->macros = doc->macro_count;
        out_counts->typedefs = doc->typedef_count;
        out_counts->structs = doc->struct_count;
        out_counts->fields = 0;
        for (i = 0; i < doc->struct_count; ++i) {
            out_counts->fields += doc->structs[i].field_count;
        }
        out_counts->callbacks = doc->callback_count;
        out_counts->functions = doc->function_count;
        out_counts->manifest_constants = manifest.constant_count;
        out_counts->manifest_structs = manifest.struct_count;
        out_counts->manifest_fields = manifest.field_count;
    }
    result = 0;

cleanup:
    free(doc_source);
    free(doc);
    free(header);
    return result;
}
