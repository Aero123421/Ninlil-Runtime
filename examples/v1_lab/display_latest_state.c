/*
 * V1-LAB example: Display node uplink submit→delivery (loopback).
 *
 * Product narrative: display snapshot event (EventFact).
 * M1a public family authority (docs/12 §14 / ADR-0024) is EventFact only —
 * LATEST_STATE_RESERVED remains service_register UNSUPPORTED (not first-class).
 *
 * Historical executable name ninlil_v1_lab_display_latest_state_example is
 * label-only compatibility; it does not enable the reserved public family.
 */

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
        (void)fprintf(stderr, "v1_lab_display_latest_state: realpath failed\n");
        return 1;
    }
    if (!v1_lab_loopback_uplink_run(
            program_path, NINLIL_FAMILY_EVENT_FACT, 0xB4E2E701ull)) {
        (void)fprintf(stderr, "v1_lab_display_latest_state failed\n");
        return 1;
    }
    (void)printf("v1_lab_display_latest_state ok\n");
    return 0;
}
