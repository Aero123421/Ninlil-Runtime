#include "operator_projection_schema.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    ninlil_operator_projection_result_t result;
    if (argc != 3 || strcmp(argv[1], "check") != 0) {
        fprintf(stderr, "usage: %s check <repository-root>\n", argv[0]);
        return 2;
    }
    if (ninlil_operator_projection_run_repository_check(argv[2], &result, stderr) != 0) {
        return 1;
    }
    printf("operator projection ok: contexts=%zu states=%zu references=%zu reason_hints=%zu\n",
        result.context_rows, result.state_codes, result.references, result.reason_hints);
    return 0;
}
