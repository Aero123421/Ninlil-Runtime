#include "traceability_schema.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *program)
{
    fprintf(stderr, "usage: %s check <repository-root>\n", program);
}

int main(int argc, char **argv)
{
    ninlil_traceability_result_t result;

    if (argc != 3 || strcmp(argv[1], "check") != 0) {
        usage(argv[0]);
        return 2;
    }
    if (ninlil_traceability_run_repository_check(argv[2], &result, stderr) != 0) {
        return 1;
    }
    printf(
        "traceability ok: entries=%zu verified=%zu partial=%zu planned=%zu test_links=%zu\n",
        result.entries,
        result.verified,
        result.partial,
        result.planned,
        result.test_links);
    return 0;
}
