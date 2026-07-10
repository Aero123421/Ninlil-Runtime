#include "abi_drift_schema.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *argv0)
{
    fprintf(
        stderr,
        "usage:\n"
        "  %s check <repo_root>\n",
        argv0);
}

int main(int argc, char **argv)
{
    ninlil_abi_catalog_counts_t counts;

    if (argc != 3 || strcmp(argv[1], "check") != 0) {
        usage(argv[0]);
        return 2;
    }

    if (ninlil_abi_run_repository_check(argv[2], &counts, stderr) != 0) {
        return 1;
    }

    fprintf(
        stdout,
        "abi drift ok: macros=%zu typedefs=%zu structs=%zu fields=%zu callbacks=%zu functions=%zu manifest=(%zu,%zu,%zu)\n",
        counts.macros,
        counts.typedefs,
        counts.structs,
        counts.fields,
        counts.callbacks,
        counts.functions,
        counts.manifest_constants,
        counts.manifest_structs,
        counts.manifest_fields);
    return 0;
}
