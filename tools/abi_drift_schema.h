#ifndef NINLIL_ABI_DRIFT_SCHEMA_H
#define NINLIL_ABI_DRIFT_SCHEMA_H

#include <stddef.h>
#include <stdio.h>

#define NINLIL_ABI_DRIFT_MAX_MACROS 400u
#define NINLIL_ABI_DRIFT_MAX_TYPEDEFS 96u
#define NINLIL_ABI_DRIFT_MAX_STRUCTS 64u
#define NINLIL_ABI_DRIFT_MAX_FIELDS 40u
#define NINLIL_ABI_DRIFT_MAX_CALLBACKS 16u
#define NINLIL_ABI_DRIFT_MAX_FUNCTIONS 24u
#define NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN 96u
#define NINLIL_ABI_DRIFT_MAX_TYPE_LEN 512u
#define NINLIL_ABI_DRIFT_MAX_VALUE_LEN 256u
#define NINLIL_ABI_DRIFT_MAX_SIG_LEN 1024u
#define NINLIL_ABI_DRIFT_MAX_SOURCE (2u * 1024u * 1024u)
#define NINLIL_ABI_DRIFT_MAX_ERROR 512u

#define NINLIL_ABI_MANIFEST_EXPECTED_CONSTANTS 278u
#define NINLIL_ABI_MANIFEST_EXPECTED_STRUCTS 53u
#define NINLIL_ABI_MANIFEST_EXPECTED_FIELDS 526u

typedef enum ninlil_abi_macro_kind {
    NINLIL_ABI_MACRO_OBJECT = 0,
    NINLIL_ABI_MACRO_FUNCTION = 1
} ninlil_abi_macro_kind_t;

typedef struct ninlil_abi_macro_entry {
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    ninlil_abi_macro_kind_t kind;
    char value[NINLIL_ABI_DRIFT_MAX_VALUE_LEN];
} ninlil_abi_macro_entry_t;

typedef struct ninlil_abi_typedef_entry {
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    char type[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
    int is_opaque_struct;
} ninlil_abi_typedef_entry_t;

typedef struct ninlil_abi_field_entry {
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    char type[NINLIL_ABI_DRIFT_MAX_TYPE_LEN];
} ninlil_abi_field_entry_t;

typedef struct ninlil_abi_struct_entry {
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    ninlil_abi_field_entry_t fields[NINLIL_ABI_DRIFT_MAX_FIELDS];
    size_t field_count;
} ninlil_abi_struct_entry_t;

typedef struct ninlil_abi_callback_entry {
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    char signature[NINLIL_ABI_DRIFT_MAX_SIG_LEN];
} ninlil_abi_callback_entry_t;

typedef struct ninlil_abi_function_entry {
    char name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    char signature[NINLIL_ABI_DRIFT_MAX_SIG_LEN];
} ninlil_abi_function_entry_t;

typedef struct ninlil_abi_catalog {
    ninlil_abi_macro_entry_t macros[NINLIL_ABI_DRIFT_MAX_MACROS];
    size_t macro_count;
    ninlil_abi_typedef_entry_t typedefs[NINLIL_ABI_DRIFT_MAX_TYPEDEFS];
    size_t typedef_count;
    ninlil_abi_struct_entry_t structs[NINLIL_ABI_DRIFT_MAX_STRUCTS];
    size_t struct_count;
    ninlil_abi_callback_entry_t callbacks[NINLIL_ABI_DRIFT_MAX_CALLBACKS];
    size_t callback_count;
    ninlil_abi_function_entry_t functions[NINLIL_ABI_DRIFT_MAX_FUNCTIONS];
    size_t function_count;
} ninlil_abi_catalog_t;

typedef struct ninlil_abi_manifest_inventory {
    char constants[NINLIL_ABI_DRIFT_MAX_MACROS][NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    size_t constant_count;
    char structs[NINLIL_ABI_DRIFT_MAX_STRUCTS][NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    size_t struct_count;
    struct {
        char struct_name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
        char field_name[NINLIL_ABI_DRIFT_MAX_SYMBOL_LEN];
    } fields[NINLIL_ABI_DRIFT_MAX_STRUCTS * NINLIL_ABI_DRIFT_MAX_FIELDS];
    size_t field_count;
} ninlil_abi_manifest_inventory_t;

typedef struct ninlil_abi_catalog_counts {
    size_t macros;
    size_t typedefs;
    size_t structs;
    size_t fields;
    size_t callbacks;
    size_t functions;
    size_t manifest_constants;
    size_t manifest_structs;
    size_t manifest_fields;
} ninlil_abi_catalog_counts_t;

void ninlil_abi_catalog_init(ninlil_abi_catalog_t *catalog);

int ninlil_abi_extract_markdown_c_blocks(
    const char *markdown_path,
    char *out,
    size_t out_size);

int ninlil_abi_parse_translation_unit(
    const char *source,
    const char *label,
    ninlil_abi_catalog_t *out,
    char *error_out,
    size_t error_out_size);

int ninlil_abi_merge_catalog(
    ninlil_abi_catalog_t *dest,
    const ninlil_abi_catalog_t *src,
    const char *src_label,
    char *error_out,
    size_t error_out_size);

int ninlil_abi_compare_catalogs(
    const ninlil_abi_catalog_t *doc,
    const ninlil_abi_catalog_t *header,
    FILE *err);

int ninlil_abi_parse_manifest_inventory(
    const char *constants_inc_path,
    const char *structs_inc_path,
    ninlil_abi_manifest_inventory_t *out,
    char *error_out,
    size_t error_out_size);

int ninlil_abi_compare_header_manifest(
    const ninlil_abi_catalog_t *header,
    const ninlil_abi_manifest_inventory_t *manifest,
    FILE *err);

int ninlil_abi_count_header_manifest_symbols(
    const ninlil_abi_catalog_t *header,
    size_t *out_constants,
    size_t *out_structs,
    size_t *out_fields);

int ninlil_abi_run_repository_check(
    const char *repo_root,
    ninlil_abi_catalog_counts_t *out_counts,
    FILE *err);

void ninlil_abi_normalize_type(const char *input, char *output, size_t output_size);
void ninlil_abi_normalize_value(const char *input, char *output, size_t output_size);

#endif /* NINLIL_ABI_DRIFT_SCHEMA_H */
