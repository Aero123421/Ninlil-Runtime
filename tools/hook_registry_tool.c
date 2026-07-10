#include "hook_registry_schema.h"

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
    size_t count = 0;

    if (argc != 3 || strcmp(argv[1], "check") != 0) {
        usage(argv[0]);
        return 2;
    }

    if (ninlil_hook_run_repository_check(argv[2], &count, stderr) != 0) {
        return 1;
    }

    fprintf(
        stdout,
        "hook registry mirror ok: count=%zu unique=%zu ch12=ch14 ordered\n",
        count,
        count);
    return 0;
}
