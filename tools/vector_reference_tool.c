#include "vector_reference_schema.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *program)
{
    fprintf(stderr, "usage: %s check <repo_root>\n", program);
}

int main(int argc, char **argv)
{
    ninlil_vector_reference_result_t result;

    if (argc != 3 || strcmp(argv[1], "check") != 0) {
        usage(argv[0]);
        return 2;
    }
    if (ninlil_vector_reference_run_repository_check(argv[2], &result, stderr) != 0) {
        return 1;
    }
    fprintf(
        stdout,
        "vector references ok: definitions=%zu mandatory_unique=%zu pr_unique=%zu union=%zu "
        "mandatory_occurrences=%zu pr_occurrences=%zu mandatory_rows=%zu pr_bullets=%zu "
        "excluded=%zu\n",
        result.definition_count,
        result.mandatory_unique,
        result.pull_request_unique,
        result.union_unique,
        result.mandatory_occurrences,
        result.pull_request_occurrences,
        result.mandatory_rows,
        result.pull_request_bullets,
        result.excluded_tokens);
    return 0;
}
