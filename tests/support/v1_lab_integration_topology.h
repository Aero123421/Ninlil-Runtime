#ifndef NINLIL_V1_LAB_INTEGRATION_TOPOLOGY_H
#define NINLIL_V1_LAB_INTEGRATION_TOPOLOGY_H

/*
 * V1-LAB item 10b: single-process integration topology (test-only).
 * Wires public runtime + POSIX SQLite + C4/C5/C3/C6/M4/R5 host simulation.
 * Not public ABI. Not installed.
 */

#include <ninlil/runtime.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define V1_LAB_IG_SCENARIO_HAPPY 1u
#define V1_LAB_IG_SCENARIO_ACK_LOSS 2u
#define V1_LAB_IG_SCENARIO_DATA_DUPLICATE 3u
#define V1_LAB_IG_SCENARIO_REORDER_REPLAY 4u
#define V1_LAB_IG_SCENARIO_TIMEOUT 5u
#define V1_LAB_IG_SCENARIO_RETRY_EXHAUSTED 6u
#define V1_LAB_IG_SCENARIO_CTRL_RESTART 7u
#define V1_LAB_IG_SCENARIO_END_RESTART 8u
#define V1_LAB_IG_SCENARIO_CRC_FAULT 9u
#define V1_LAB_IG_SCENARIO_AUTH_FAULT 10u
#define V1_LAB_IG_SCENARIO_STORAGE_FAULT 11u

typedef struct v1_lab_integration_topology v1_lab_integration_topology_t;

typedef struct v1_lab_integration_scenario_result {
    uint32_t scenario_id;
    uint32_t false_success;
    uint32_t bounded_termination;
    uint32_t fail_closed;
    uint32_t delivery_calls;
    uint32_t outcome_satisfied;
    uint32_t spi_tx_count;
    uint32_t usb_custody_ok;
    uint32_t rx_auth_fail;
    uint32_t rx_replay;
} v1_lab_integration_scenario_result_t;

typedef struct v1_lab_integration_structural_report {
    uint64_t bypass_call_sites;
    uint64_t bypass_attempt_count;
    uint64_t production_bypass_on_success;
} v1_lab_integration_structural_report_t;

int v1_lab_integration_topology_init(
    v1_lab_integration_topology_t **out_topology,
    const char *workdir);
void v1_lab_integration_topology_destroy(v1_lab_integration_topology_t *topology);

int v1_lab_integration_run_scenario(
    v1_lab_integration_topology_t *topology,
    uint32_t scenario_id,
    v1_lab_integration_scenario_result_t *out_result);

int v1_lab_integration_structural_check(
    v1_lab_integration_topology_t *topology,
    v1_lab_integration_structural_report_t *out_report);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_V1_LAB_INTEGRATION_TOPOLOGY_H */
