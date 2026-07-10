#ifndef NINLIL_HOOK_REGISTRY_SCHEMA_H
#define NINLIL_HOOK_REGISTRY_SCHEMA_H

#include <stddef.h>
#include <stdio.h>

#define NINLIL_HOOK_REGISTRY_EXPECTED_COUNT 130u
#define NINLIL_HOOK_REGISTRY_MAX_HOOKS 130u
#define NINLIL_HOOK_REGISTRY_MAX_HOOK_NAME_LEN 96u
#define NINLIL_HOOK_REGISTRY_MAX_LINE_LEN 256u
#define NINLIL_HOOK_REGISTRY_MAX_ERROR 512u
#define NINLIL_HOOK_REGISTRY_MAX_PATH_LEN 256u

#define NINLIL_HOOK_REGISTRY_CH12_HEADING "## 17. Named fault hook registry"
#define NINLIL_HOOK_REGISTRY_CH14_HEADING "### Closed hook registry mirror"
#define NINLIL_HOOK_REGISTRY_CH12_PATH "docs/12-foundation-abi.md"
#define NINLIL_HOOK_REGISTRY_CH14_PATH "docs/14-foundation-ports-and-simulator.md"

typedef struct ninlil_hook_registry {
    char hooks[NINLIL_HOOK_REGISTRY_MAX_HOOKS][NINLIL_HOOK_REGISTRY_MAX_HOOK_NAME_LEN];
    size_t count;
} ninlil_hook_registry_t;

int ninlil_hook_registry_is_valid_hook_name(const char *name);

int ninlil_hook_registry_parse_markdown_content(
    const char *content,
    const char *heading,
    ninlil_hook_registry_t *out_registry,
    char *error_out,
    size_t error_out_size);

int ninlil_hook_registry_parse_markdown_file(
    const char *path,
    const char *heading,
    ninlil_hook_registry_t *out_registry,
    char *error_out,
    size_t error_out_size);

int ninlil_hook_registry_validate(
    const ninlil_hook_registry_t *registry,
    char *error_out,
    size_t error_out_size);

int ninlil_hook_registry_compare_ordered(
    const ninlil_hook_registry_t *left,
    const ninlil_hook_registry_t *right,
    const char *left_label,
    const char *right_label,
    FILE *error_stream);

int ninlil_hook_run_repository_check(const char *repo_root, size_t *out_count, FILE *error_stream);

#endif /* NINLIL_HOOK_REGISTRY_SCHEMA_H */
