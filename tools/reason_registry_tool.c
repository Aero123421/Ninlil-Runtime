#include "yaml_reason_schema.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(
        stderr,
        "usage:\n"
        "  %s generate <yaml> <header> <repo_root> <output>\n"
        "  %s check <yaml> <header> <repo_root> <expected_artifact>\n",
        argv0,
        argv0);
}

static int is_valid_retry_guidance(const char *value)
{
    return strcmp(value, "NINLIL_RETRY_NEVER") == 0
           || strcmp(value, "NINLIL_RETRY_SAME_AFTER") == 0
           || strcmp(value, "NINLIL_RETRY_MODIFIED") == 0
           || strcmp(value, "NINLIL_RETRY_OPERATOR_ACTION") == 0;
}

static int validate_retry_guidance(const ninlil_reason_registry_yaml_t *registry)
{
    size_t i;

    for (i = 0; i < registry->code_count; ++i) {
        if (!is_valid_retry_guidance(registry->codes[i].default_retry_guidance)) {
            fprintf(
                stderr,
                "reason validation error: invalid default_retry_guidance for %s: %s\n",
                registry->codes[i].symbol,
                registry->codes[i].default_retry_guidance);
            return -1;
        }
    }
    return 0;
}

static int load_and_validate(
    const char *yaml_path,
    const char *header_path,
    const char *repo_root,
    ninlil_reason_registry_yaml_t *registry,
    ninlil_header_reason_table_t *header_table)
{
    if (ninlil_parse_reason_registry_yaml(yaml_path, registry) != 0) {
        return -1;
    }
    if (validate_retry_guidance(registry) != 0) {
        return -1;
    }
    if (ninlil_validate_reason_registry_links(repo_root) != 0) {
        return -1;
    }
    if (ninlil_scan_header_reason_codes(header_path, header_table) != 0) {
        return -1;
    }
    if (ninlil_compare_header_yaml(registry, header_table) != 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    ninlil_reason_registry_yaml_t registry;
    ninlil_header_reason_table_t header_table;
    const char *mode;
    const char *yaml_path;
    const char *header_path;
    const char *repo_root;
    const char *artifact_path;
    FILE *expected;
    FILE *actual;

    if (argc != 6) {
        usage(argv[0]);
        return 2;
    }

    mode = argv[1];
    yaml_path = argv[2];
    header_path = argv[3];
    repo_root = argv[4];
    artifact_path = argv[5];

    if (load_and_validate(yaml_path, header_path, repo_root, &registry, &header_table) != 0) {
        return 1;
    }

    if (strcmp(mode, "generate") == 0) {
        FILE *out = fopen(artifact_path, "wb");
        if (out == NULL) {
            fprintf(stderr, "cannot write %s\n", artifact_path);
            return 1;
        }
        if (ninlil_emit_reason_registry_artifact(&registry, out) != 0) {
            fclose(out);
            return 1;
        }
        fclose(out);
        return 0;
    }

    if (strcmp(mode, "check") == 0) {
        expected = fopen(artifact_path, "rb");
        if (expected == NULL) {
            fprintf(stderr, "cannot read %s\n", artifact_path);
            return 1;
        }
        actual = tmpfile();
        if (actual == NULL) {
            fprintf(stderr, "cannot create temporary artifact stream\n");
            fclose(expected);
            return 1;
        }
        if (ninlil_emit_reason_registry_artifact(&registry, actual) != 0) {
            fclose(expected);
            fclose(actual);
            return 1;
        }
        rewind(actual);
        if (ninlil_compare_reason_artifact_streams(expected, actual) != 0) {
            fclose(expected);
            fclose(actual);
            return 1;
        }
        fclose(expected);
        fclose(actual);
        return 0;
    }

    usage(argv[0]);
    return 2;
}
