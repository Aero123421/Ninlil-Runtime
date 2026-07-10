#ifndef NINLIL_OPERATOR_PROJECTION_SCHEMA_H
#define NINLIL_OPERATOR_PROJECTION_SCHEMA_H

#include "yaml_reason_schema.h"

#include <stddef.h>
#include <stdio.h>

#define NINLIL_OPERATOR_PROJECTION_MAX_ERROR 512u
#define NINLIL_OPERATOR_PROJECTION_DOC_PATH "docs/11-operator-model.md"
#define NINLIL_OPERATOR_PROJECTION_REASON_PATH "schemas/foundation-m1a-reason-codes.yaml"
#define NINLIL_OPERATOR_PROJECTION_LINK "../docs/11-operator-model.md#共通operator-state"

typedef struct ninlil_operator_projection_result {
    size_t context_rows;
    size_t state_codes;
    size_t references;
    size_t reason_hints;
} ninlil_operator_projection_result_t;

int ninlil_operator_projection_check_content(
    const char *markdown_content,
    const ninlil_reason_registry_yaml_t *reason_registry,
    ninlil_operator_projection_result_t *out_result,
    char *error_out,
    size_t error_out_size);

int ninlil_operator_projection_check_bytes(
    const char *markdown_bytes,
    size_t markdown_length,
    const ninlil_reason_registry_yaml_t *reason_registry,
    ninlil_operator_projection_result_t *out_result,
    char *error_out,
    size_t error_out_size);

int ninlil_operator_projection_run_repository_check(
    const char *repo_root,
    ninlil_operator_projection_result_t *out_result,
    FILE *error_stream);

#endif /* NINLIL_OPERATOR_PROJECTION_SCHEMA_H */
