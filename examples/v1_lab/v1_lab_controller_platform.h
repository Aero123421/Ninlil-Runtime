/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_EXAMPLES_V1_LAB_CONTROLLER_PLATFORM_H
#define NINLIL_EXAMPLES_V1_LAB_CONTROLLER_PLATFORM_H

/*
 * Private Linux/macOS provider set for the V1 Controller diagnostic.
 *
 * It is intentionally not an installed SDK surface.  The object owns one
 * SQLite provider and exposes no bearer; Composition installs Fabric as the
 * Runtime bearer.  Progress remains on the creating thread.
 */

#include "ninlil/platform.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_v1_lab_controller_platform
    ninlil_v1_lab_controller_platform_t;

typedef struct ninlil_v1_lab_controller_platform_config {
    const char *database_path;
    uint8_t clock_epoch_id[16];
    uint64_t clock_anchor_ms;
} ninlil_v1_lab_controller_platform_config_t;

ninlil_v1_lab_controller_platform_t *
ninlil_v1_lab_controller_platform_create(
    const ninlil_v1_lab_controller_platform_config_t *config);

const ninlil_platform_ops_t *ninlil_v1_lab_controller_platform_ops(
    const ninlil_v1_lab_controller_platform_t *platform);

void ninlil_v1_lab_controller_platform_destroy(
    ninlil_v1_lab_controller_platform_t *platform);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_EXAMPLES_V1_LAB_CONTROLLER_PLATFORM_H */
