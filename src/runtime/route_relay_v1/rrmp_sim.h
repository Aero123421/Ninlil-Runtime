/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Simulator is a *driver only* for production private core SMs.
 * No fake forward/parent/split-brain outside core.
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_SIM_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_SIM_H

#include "rrmp_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RRMP_SIM_MAX_STEPS 32u

typedef struct ninlil_rrmp_sim_step {
    uint32_t t;
    uint32_t event_code;
    uint32_t status;
    uint32_t detail;
} ninlil_rrmp_sim_step_t;

typedef struct ninlil_rrmp_sim {
    ninlil_rrmp_owner_t *endpoint_relay; /* concurrent roles */
    ninlil_rrmp_owner_t *parent_a;
    ninlil_rrmp_owner_t *parent_b;
    ninlil_rrmp_sim_step_t steps[NINLIL_RRMP_SIM_MAX_STEPS];
    uint32_t step_count;
    uint8_t attempt_id16[16];
    uint8_t scope[16];
} ninlil_rrmp_sim_t;

int ninlil_rrmp_sim_run_bounded_driver(ninlil_rrmp_sim_t *sim);
void ninlil_rrmp_sim_fini(ninlil_rrmp_sim_t *sim);
uint32_t ninlil_rrmp_sim_step_count(const ninlil_rrmp_sim_t *sim);
const ninlil_rrmp_sim_step_t *ninlil_rrmp_sim_step_at(
    const ninlil_rrmp_sim_t *sim, uint32_t index);

#ifdef __cplusplus
}
#endif

#endif
