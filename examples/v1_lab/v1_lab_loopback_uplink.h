#ifndef V1_LAB_LOOPBACK_UPLINK_H
#define V1_LAB_LOOPBACK_UPLINK_H

#include <ninlil/runtime.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 2-process POSIX loopback bearer uplink (Display / Leak node equivalents).
 * program_path must remain valid through the call (used for --child re-exec).
 */
int v1_lab_loopback_uplink_run(
    const char *program_path,
    ninlil_family_t family,
    uint64_t seed);

/* Child entry for re-exec; argv layout matches internal spawn_peer(). */
int v1_lab_loopback_uplink_child_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* V1_LAB_LOOPBACK_UPLINK_H */
