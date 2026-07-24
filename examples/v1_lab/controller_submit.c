/*
 * V1-LAB example: Site Controller downlink submit→delivery (host simulation).
 */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _XOPEN_SOURCE 700
#endif

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
