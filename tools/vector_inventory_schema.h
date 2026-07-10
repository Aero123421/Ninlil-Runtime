#ifndef NINLIL_VECTOR_INVENTORY_SCHEMA_H
#define NINLIL_VECTOR_INVENTORY_SCHEMA_H

#include <stddef.h>
#include <stdio.h>

#define NINLIL_VECTOR_INVENTORY_EXPECTED_DEFINITION_COUNT 282u
#define NINLIL_VECTOR_INVENTORY_EXPECTED_TABLE_COUNT 238u
#define NINLIL_VECTOR_INVENTORY_EXPECTED_EXPLICIT_COUNT 26u
#define NINLIL_VECTOR_INVENTORY_EXPECTED_BULLET_COUNT 16u
#define NINLIL_VECTOR_INVENTORY_EXPECTED_CANONICAL_HEADING_COUNT 2u
#define NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS 512u
#define NINLIL_VECTOR_INVENTORY_MAX_ID_LEN 64u
#define NINLIL_VECTOR_INVENTORY_MAX_LINE_LEN 2048u
#define NINLIL_VECTOR_INVENTORY_MAX_ERROR 512u
#define NINLIL_VECTOR_INVENTORY_MAX_PATH_LEN 256u
#define NINLIL_VECTOR_INVENTORY_DOC14_PATH "docs/14-foundation-ports-and-simulator.md"

typedef enum ninlil_vector_definition_kind {
    NINLIL_VECTOR_DEFINITION_TABLE = 0,
    NINLIL_VECTOR_DEFINITION_EXPLICIT = 1,
    NINLIL_VECTOR_DEFINITION_BULLET = 2,
    NINLIL_VECTOR_DEFINITION_CANONICAL_HEADING = 3
} ninlil_vector_definition_kind_t;

typedef struct ninlil_vector_definition {
    char id[NINLIL_VECTOR_INVENTORY_MAX_ID_LEN];
    size_t line_number;
    ninlil_vector_definition_kind_t kind;
} ninlil_vector_definition_t;

typedef struct ninlil_vector_inventory {
    ninlil_vector_definition_t definitions[NINLIL_VECTOR_INVENTORY_MAX_DEFINITIONS];
    size_t count;
} ninlil_vector_inventory_t;

typedef struct ninlil_vector_inventory_kind_counts {
    size_t total;
    size_t table;
    size_t explicit;
    size_t bullet;
    size_t canonical;
} ninlil_vector_inventory_kind_counts_t;

typedef struct ninlil_vector_repository_check_result {
    ninlil_vector_inventory_kind_counts_t kinds;
} ninlil_vector_repository_check_result_t;

int ninlil_vector_inventory_is_valid_id(const char *id);

int ninlil_vector_inventory_parse_markdown_content(
    const char *content,
    ninlil_vector_inventory_t *out_inventory,
    char *error_out,
    size_t error_out_size);

int ninlil_vector_inventory_parse_markdown_file(
    const char *path,
    ninlil_vector_inventory_t *out_inventory,
    char *error_out,
    size_t error_out_size);

int ninlil_vector_inventory_sort(ninlil_vector_inventory_t *inventory);

int ninlil_vector_inventory_validate(
    const ninlil_vector_inventory_t *inventory,
    char *error_out,
    size_t error_out_size);

void ninlil_vector_inventory_count_kinds(
    const ninlil_vector_inventory_t *inventory,
    ninlil_vector_inventory_kind_counts_t *out_counts);

int ninlil_vector_inventory_build_doc14_path(
    const char *repo_root,
    char *path_out,
    size_t path_out_size,
    char *error_out,
    size_t error_out_size);

int ninlil_vector_run_repository_check(
    const char *repo_root,
    ninlil_vector_repository_check_result_t *out_result,
    FILE *error_stream);

#endif /* NINLIL_VECTOR_INVENTORY_SCHEMA_H */
