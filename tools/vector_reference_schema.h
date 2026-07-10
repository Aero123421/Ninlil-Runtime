#ifndef NINLIL_VECTOR_REFERENCE_SCHEMA_H
#define NINLIL_VECTOR_REFERENCE_SCHEMA_H

#include "vector_inventory_schema.h"

#include <stddef.h>
#include <stdio.h>

#define NINLIL_VECTOR_REFERENCE_MAX_LINE_LEN 2048u
#define NINLIL_VECTOR_REFERENCE_MAX_ERROR 512u

typedef struct ninlil_vector_reference_result {
    size_t definition_count;
    size_t mandatory_unique;
    size_t pull_request_unique;
    size_t union_unique;
    size_t mandatory_occurrences;
    size_t pull_request_occurrences;
    size_t mandatory_rows;
    size_t pull_request_bullets;
    size_t excluded_tokens;
} ninlil_vector_reference_result_t;

int ninlil_vector_reference_check_content(
    const char *content,
    const ninlil_vector_inventory_t *inventory,
    ninlil_vector_reference_result_t *out_result,
    char *error_out,
    size_t error_out_size);

int ninlil_vector_reference_check_repository_content(
    const char *content,
    ninlil_vector_reference_result_t *out_result,
    char *error_out,
    size_t error_out_size);

int ninlil_vector_reference_run_repository_check(
    const char *repo_root,
    ninlil_vector_reference_result_t *out_result,
    FILE *error_stream);

#endif /* NINLIL_VECTOR_REFERENCE_SCHEMA_H */
