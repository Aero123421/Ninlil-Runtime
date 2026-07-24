/*
 * V1-LAB example: Cell Agent USB custody + radio TX (host simulation).
 */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "v1_lab_host_sim.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    char workdir[] = "/tmp/ninlil-v1-cell-XXXXXX";

    if (mkdtemp(workdir) == NULL) {
        return 1;
    }
    if (!v1_lab_host_sim_run_cell(workdir)) {
        (void)fprintf(stderr, "v1_lab_cell_custody failed\n");
        return 1;
    }
    (void)printf("v1_lab_cell_custody ok\n");
    return 0;
}
