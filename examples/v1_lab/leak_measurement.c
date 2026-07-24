/*
 * V1-LAB example: Leak node uplink MeasurementBatch submit→delivery (loopback).
 */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#else
#define _XOPEN_SOURCE 700
#endif

#include "v1_lab_loopback_uplink.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char program_path[PATH_MAX];

    if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
        return v1_lab_loopback_uplink_child_main(argc, argv);
    }
    if (realpath(argv[0], program_path) == NULL) {
        (void)fprintf(stderr, "v1_lab_leak_measurement failed: realpath\n");
        return 1;
    }
    if (!v1_lab_loopback_uplink_run(
            program_path, NINLIL_FAMILY_MEASUREMENT_RESERVED, 0xB4E2E801ull)) {
        (void)fprintf(stderr, "v1_lab_leak_measurement failed\n");
        return 1;
    }
    (void)printf("v1_lab_leak_measurement ok\n");
    return 0;
}
