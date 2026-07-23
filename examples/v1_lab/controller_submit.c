/*
 * V1-LAB example: Site Controller downlink submit→delivery (host simulation).
 */

#include "v1_lab_host_sim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char workdir[] = "/tmp/ninlil-v1-ctrl-XXXXXX";

    if (mkdtemp(workdir) == NULL) {
        return 1;
    }
    if (!v1_lab_host_sim_run_controller(workdir)) {
        (void)fprintf(stderr, "v1_lab_controller_submit failed\n");
        return 1;
    }
    (void)printf("v1_lab_controller_submit ok\n");
    return 0;
}
