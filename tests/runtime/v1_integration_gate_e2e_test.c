/*
 * V1-LAB item 10b: integration E2E gate (single topology, single execution).
 */

#include "v1_lab_integration_topology.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "REQUIRE fail %s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int run_scenario(
    v1_lab_integration_topology_t *topo,
    uint32_t scenario_id,
    int expect_success)
{
    v1_lab_integration_scenario_result_t result;

    (void)memset(&result, 0, sizeof(result));
    REQUIRE(v1_lab_integration_run_scenario(topo, scenario_id, &result));
    REQUIRE(result.bounded_termination != 0u);
    REQUIRE(result.false_success == 0u);
    if (scenario_id == V1_LAB_IG_SCENARIO_REORDER_REPLAY) {
        REQUIRE(result.rx_replay > 0u || result.rx_auth_fail > 0u);
    }
    if (expect_success) {
        REQUIRE(result.outcome_satisfied != 0u);
        REQUIRE(result.delivery_calls >= 1u);
        REQUIRE(result.spi_tx_count >= 1u);
    } else {
        REQUIRE(result.fail_closed != 0u);
        REQUIRE(result.outcome_satisfied == 0u);
    }
    return 0;
}

static int test_structural_bypass(void)
{
    v1_lab_integration_topology_t *topo = NULL;
    v1_lab_integration_structural_report_t report;
    char workdir[512];

    REQUIRE(getcwd(workdir, sizeof(workdir)) != NULL);
    REQUIRE(v1_lab_integration_topology_init(&topo, workdir));
    REQUIRE(v1_lab_integration_structural_check(topo, &report));
    REQUIRE(report.bypass_attempt_count == 0u);
    REQUIRE(report.production_bypass_on_success == 0u);
    v1_lab_integration_topology_destroy(topo);
    (void)fprintf(stderr, "structural_check bypass_call_sites=%llu\n",
        (unsigned long long)report.bypass_call_sites);
    return 0;
}

int main(void)
{
    v1_lab_integration_topology_t *topo = NULL;
    char workdir[512];
    int rc = 0;

    REQUIRE(getcwd(workdir, sizeof(workdir)) != NULL);
    REQUIRE(v1_lab_integration_topology_init(&topo, workdir));

    if (run_scenario(topo, V1_LAB_IG_SCENARIO_HAPPY, 1) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_ACK_LOSS, 1) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_DATA_DUPLICATE, 1) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_REORDER_REPLAY, 1) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_CTRL_RESTART, 1) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_END_RESTART, 1) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_TIMEOUT, 0) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_RETRY_EXHAUSTED, 0) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_CRC_FAULT, 0) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_AUTH_FAULT, 0) != 0) {
        rc = 1;
    }
    if (run_scenario(topo, V1_LAB_IG_SCENARIO_STORAGE_FAULT, 0) != 0) {
        rc = 1;
    }
    if (test_structural_bypass() != 0) {
        rc = 1;
    }

    v1_lab_integration_topology_destroy(topo);
    if (rc != 0) {
        (void)fprintf(stderr, "v1_integration_gate_e2e_test failed\n");
        return 1;
    }
    (void)fprintf(stderr, "v1_integration_gate_e2e_test ok\n");
    return 0;
}
