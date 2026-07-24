/*
 * V1-LAB example: Cell Agent USB custody + radio TX (host simulation).
 */

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
