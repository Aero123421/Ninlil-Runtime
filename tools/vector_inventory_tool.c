#include "vector_inventory_schema.h"

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
    ninlil_vector_repository_check_result_t result;

    if (argc != 3 || strcmp(argv[1], "check") != 0) {
        usage(argv[0]);
        return 2;
    }

    if (ninlil_vector_run_repository_check(argv[2], &result, stderr) != 0) {
        return 1;
    }

    fprintf(
        stdout,
        "vector inventory ok: total=%zu table=%zu explicit=%zu bullet=%zu canonical=%zu\n",
        result.kinds.total,
        result.kinds.table,
        result.kinds.explicit,
        result.kinds.bullet,
        result.kinds.canonical);
    return 0;
}
