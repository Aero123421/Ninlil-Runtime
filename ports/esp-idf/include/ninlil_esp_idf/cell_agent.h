#ifndef NINLIL_ESP_IDF_CELL_AGENT_H
#define NINLIL_ESP_IDF_CELL_AGENT_H

#include "ninlil/platform.h"
#include "ninlil_esp_idf/owner_task.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_esp_idf_cell_agent_config {
    NINLIL_STRUCT_HEADER;
    /*
     * Nested owner config (inline layout): struct_size must be exact
     * sizeof(ninlil_esp_idf_owner_task_config_t). Fully contained in outer
     * declared range; must not overlap tx_gate field or outer tail.
     * Standalone owner_task_init still allows forward extension.
     */
    ninlil_esp_idf_owner_task_config_t owner;
    const ninlil_tx_gate_ops_t *tx_gate;
    uint32_t reserved_zero;
} ninlil_esp_idf_cell_agent_config_t;

/*
 * Storage embeds owner; no separate plain api_lifecycle.
 * Init: stage outer + nested owner (exact nested size) + ops proof before any
 * owner write; trusted initial publish stores original identity only
 * (post-write caller ops reread = 0). Public set_tx_gate remains independent.
 * See owner_task.h / docs/22.
 */
typedef struct ninlil_esp_idf_cell_agent ninlil_esp_idf_cell_agent_t;

int ninlil_esp_idf_cell_agent_init(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_esp_idf_cell_agent_config_t *config);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_start(
    ninlil_esp_idf_cell_agent_t *agent);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_stop(
    ninlil_esp_idf_cell_agent_t *agent);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_apply_assignment(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_esp_idf_cell_assignment_t *assignment);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_set_tx_gate(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_tx_gate_ops_t *tx_gate);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_acquire_tx_gate_lease(
    ninlil_esp_idf_cell_agent_t *agent,
    ninlil_esp_idf_tx_gate_lease_t *out_lease);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_release_tx_gate_lease(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_esp_idf_tx_gate_lease_t *lease);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_shutdown(
    ninlil_esp_idf_cell_agent_t *agent);

int ninlil_esp_idf_tx_gate_ops_validate(const ninlil_tx_gate_ops_t *ops);

#ifdef __cplusplus
}
#endif

#endif
