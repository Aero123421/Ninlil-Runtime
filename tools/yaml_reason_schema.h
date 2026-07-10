#ifndef NINLIL_YAML_REASON_SCHEMA_H
#define NINLIL_YAML_REASON_SCHEMA_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define NINLIL_REASON_REGISTRY_MAX_CODES 64u
#define NINLIL_REASON_REGISTRY_MAX_ZERO_SYMBOLS 16u
#define NINLIL_REASON_REGISTRY_MAX_RESERVED 8u
#define NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN 96u
#define NINLIL_REASON_REGISTRY_MAX_HINT_LEN 96u
#define NINLIL_REASON_REGISTRY_MAX_PATH_LEN 256u
#define NINLIL_REASON_REGISTRY_MAX_CATEGORY_LEN 64u
#define NINLIL_REASON_REGISTRY_MAX_MILESTONE_LEN 32u
#define NINLIL_YAML_MAX_LINE_LEN 2048u

typedef struct ninlil_reason_code_entry {
    char symbol[NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN];
    uint32_t value;
    char milestone[NINLIL_REASON_REGISTRY_MAX_MILESTONE_LEN];
    char category[NINLIL_REASON_REGISTRY_MAX_CATEGORY_LEN];
    char default_retry_guidance[NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN];
    char operator_state_hint[NINLIL_REASON_REGISTRY_MAX_HINT_LEN];
} ninlil_reason_code_entry_t;

typedef struct ninlil_reason_registry_yaml {
    uint32_t schema_version;
    char registry[NINLIL_REASON_REGISTRY_MAX_PATH_LEN];
    char integer_type[32];
    char normative_source[NINLIL_REASON_REGISTRY_MAX_PATH_LEN];
    char operator_projection_contract[NINLIL_REASON_REGISTRY_MAX_PATH_LEN];
    uint32_t reserved_values[NINLIL_REASON_REGISTRY_MAX_RESERVED];
    size_t reserved_value_count;
    char m1a_public_generated_zero[NINLIL_REASON_REGISTRY_MAX_ZERO_SYMBOLS]
                                    [NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN];
    size_t m1a_public_generated_zero_count;
    ninlil_reason_code_entry_t codes[NINLIL_REASON_REGISTRY_MAX_CODES];
    size_t code_count;
} ninlil_reason_registry_yaml_t;

typedef struct ninlil_header_reason_entry {
    char symbol[NINLIL_REASON_REGISTRY_MAX_SYMBOL_LEN];
    uint32_t value;
} ninlil_header_reason_entry_t;

typedef struct ninlil_header_reason_table {
    ninlil_header_reason_entry_t entries[NINLIL_REASON_REGISTRY_MAX_CODES];
    size_t count;
} ninlil_header_reason_table_t;

int ninlil_parse_reason_registry_yaml(
    const char *path,
    ninlil_reason_registry_yaml_t *out_registry);

int ninlil_parse_reason_registry_yaml_content(
    const char *content,
    ninlil_reason_registry_yaml_t *out_registry);

int ninlil_parse_reason_registry_yaml_content_ex(
    const char *content,
    ninlil_reason_registry_yaml_t *out_registry,
    char *error_out,
    size_t error_out_size);

int ninlil_validate_reason_registry(const ninlil_reason_registry_yaml_t *registry);

int ninlil_scan_header_reason_codes(
    const char *path,
    ninlil_header_reason_table_t *out_table);

int ninlil_markdown_anchor_exists(const char *markdown_path, const char *anchor);

int ninlil_validate_reason_registry_links(const char *repo_root);

int ninlil_compare_header_yaml(
    const ninlil_reason_registry_yaml_t *yaml_registry,
    const ninlil_header_reason_table_t *header_table);

int ninlil_emit_reason_registry_artifact(
    const ninlil_reason_registry_yaml_t *registry,
    FILE *out);

int ninlil_compare_reason_artifact_streams(FILE *expected, FILE *actual);

#endif /* NINLIL_YAML_REASON_SCHEMA_H */
