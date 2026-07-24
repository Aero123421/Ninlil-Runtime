/*
 * V1-LAB item 10b: integration-topology helpers for Controller / Cell examples.
 */

#include "v1_lab_host_sim.h"

#include "v1_lab_integration_topology.h"

#include <stdio.h>
#include <string.h>

static int check_happy_delivery(
    const v1_lab_integration_scenario_result_t *result,
    const char *label)
{
    if (result == NULL) {
        return 0;
    }
    if (result->false_success != 0u) {
        (void)fprintf(stderr, "%s: false_success=%u\n", label, result->false_success);
        return 0;
    }
    if (result->outcome_satisfied == 0u || result->delivery_calls < 1u) {
        (void)fprintf(stderr,
            "%s: outcome=%u delivery=%u\n",
            label,
            result->outcome_satisfied,
            result->delivery_calls);
        return 0;
    }
    return 1;
}

int v1_lab_host_sim_run_controller(const char *workdir)
{
    v1_lab_integration_topology_t *topo = NULL;
    v1_lab_integration_scenario_result_t result;

    if (workdir == NULL) {
        return 0;
    }
    (void)memset(&result, 0, sizeof(result));
    if (!v1_lab_integration_topology_init(&topo, workdir)) {
        return 0;
    }
    if (!v1_lab_integration_run_scenario(
            topo, V1_LAB_IG_SCENARIO_HAPPY, &result)) {
        v1_lab_integration_topology_destroy(topo);
        return 0;
    }
    v1_lab_integration_topology_destroy(topo);
    return check_happy_delivery(&result, "controller");
}

int v1_lab_host_sim_run_cell(const char *workdir)
{
    v1_lab_integration_topology_t *topo = NULL;
    v1_lab_integration_scenario_result_t result;

    if (workdir == NULL) {
        return 0;
    }
    (void)memset(&result, 0, sizeof(result));
    if (!v1_lab_integration_topology_init(&topo, workdir)) {
        return 0;
    }
    if (!v1_lab_integration_run_scenario(
            topo, V1_LAB_IG_SCENARIO_HAPPY, &result)) {
        v1_lab_integration_topology_destroy(topo);
        return 0;
    }
    v1_lab_integration_topology_destroy(topo);
    if (!check_happy_delivery(&result, "cell")) {
        return 0;
    }
    if (result.spi_tx_count < 1u) {
        (void)fprintf(stderr, "cell: spi_tx=%u\n", result.spi_tx_count);
        return 0;
    }
    return 1;
}
