#ifndef NINLIL_TRACEABILITY_SCHEMA_H
#define NINLIL_TRACEABILITY_SCHEMA_H

#include <stddef.h>
#include <stdio.h>

#define NINLIL_TRACEABILITY_MAX_ENTRIES 64u
#define NINLIL_TRACEABILITY_MAX_TESTS_PER_ENTRY 32u
#define NINLIL_TRACEABILITY_MAX_ID_LEN 64u
#define NINLIL_TRACEABILITY_MAX_TITLE_LEN 160u
#define NINLIL_TRACEABILITY_MAX_PATH_LEN 256u
#define NINLIL_TRACEABILITY_MAX_HEADING_LEN 384u
#define NINLIL_TRACEABILITY_MAX_GAP_LEN 512u
#define NINLIL_TRACEABILITY_MAX_TEST_ID_LEN 64u
#define NINLIL_TRACEABILITY_MAX_LINE_LEN 2048u
#define NINLIL_TRACEABILITY_MAX_ERROR 512u
#define NINLIL_TRACEABILITY_MANIFEST_PATH "requirements-traceability.yaml"

/*
 * NINLIL_TRACEABILITY_V1 is a strict YAML subset:
 * - fixed top-level scalar keys followed by one `requirements` sequence;
 * - sequence items use exactly two-space indentation and fields use four spaces;
 * - title, heading, and gap are double-quoted UTF-8 scalars without escapes;
 * - tests is an inline sequence of literal CTest IDs; comments and aliases are rejected.
 */

typedef enum ninlil_traceability_status {
    NINLIL_TRACEABILITY_VERIFIED = 1,
    NINLIL_TRACEABILITY_PARTIAL = 2,
    NINLIL_TRACEABILITY_PLANNED = 3
} ninlil_traceability_status_t;

typedef struct ninlil_traceability_result {
    size_t entries;
    size_t verified;
    size_t partial;
    size_t planned;
    size_t test_links;
} ninlil_traceability_result_t;

typedef int (*ninlil_traceability_heading_resolver_fn)(
    void *user,
    const char *source_path,
    const char *heading,
    size_t *out_count,
    size_t *out_first_line,
    size_t *out_second_line,
    char *error_out,
    size_t error_out_size);

int ninlil_traceability_check_content(
    const char *manifest_content,
    const char *cmake_content,
    ninlil_traceability_heading_resolver_fn heading_resolver,
    void *resolver_user,
    ninlil_traceability_result_t *out_result,
    char *error_out,
    size_t error_out_size);

int ninlil_traceability_run_repository_check(
    const char *repo_root,
    ninlil_traceability_result_t *out_result,
    FILE *error_stream);

#endif /* NINLIL_TRACEABILITY_SCHEMA_H */
