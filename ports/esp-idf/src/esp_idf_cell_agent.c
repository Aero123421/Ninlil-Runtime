#include "ninlil_esp_idf/cell_agent_storage.h"

#include "abi_header_stage_logic.h"
#include "cell_config_stage_logic.h"
#include "owner_tx_gate_trusted.h"

#include <string.h>

/* Fixed-size public arg vs cell storage. 1 = reject. */
static int cell_fixed_arg_rejects(
    const ninlil_esp_idf_cell_agent_t *agent,
    const void *arg,
    size_t arg_size)
{
    if (agent == NULL) {
        return 1;
    }
    return ninlil_esp_idf_fixed_arg_rejects(
        arg, arg_size, agent, sizeof(*agent));
}

int ninlil_esp_idf_cell_agent_init(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_esp_idf_cell_agent_config_t *config)
{
    ninlil_esp_idf_cell_agent_config_t local_cfg;
    ninlil_esp_idf_owner_task_config_t local_owner;
    ninlil_esp_idf_abi_header_t outer_hdr;
    ninlil_tx_gate_ops_t local_ops;
    const ninlil_tx_gate_ops_t *identity;
    int have_ops;

    if (agent == NULL || config == NULL) {
        return 1;
    }

    /*
     * Stack outs are zeroed only as defined pre-stage scratch. Failure still
     * does not commit staged content via the helper (temp→commit). Defined
     * zero avoids GCC -Wmaybe-uninitialized when the helper takes out
     * addresses for alias gates before writing them.
     */
    (void)memset(&local_cfg, 0, sizeof(local_cfg));
    (void)memset(&local_owner, 0, sizeof(local_owner));
    (void)memset(&outer_hdr, 0, sizeof(outer_hdr));

    /*
     * Stage outer + nested owner from original outer (exact nested size,
     * containment, no tx_gate-field overlap). All ops staging/validation
     * completes BEFORE any owner write.
     */
    if (ninlil_esp_idf_cell_config_stage_nested_owner(
            config,
            agent,
            sizeof(*agent),
            &local_cfg,
            &local_owner,
            &outer_hdr)
        != 0) {
        return 1;
    }
    (void)outer_hdr;

    identity = local_cfg.tx_gate;
    have_ops = 0;
    if (identity != NULL) {
        ninlil_esp_idf_abi_header_t ops_hdr;
        if (ninlil_esp_idf_abi_stage_known_prefix(
                identity,
                sizeof(local_ops),
                agent,
                sizeof(*agent),
                &local_ops,
                &ops_hdr)
            != 0) {
            return 1;
        }
        (void)ops_hdr;
        if (!ninlil_esp_idf_tx_gate_ops_validate(&local_ops)) {
            return 1;
        }
        have_ops = 1;
    }

    /* Owner write begins — never re-read/re-stage caller ops after this. */
    if (ninlil_esp_idf_owner_task_init(&agent->owner, &local_owner) != 0) {
        return 1;
    }
    if (have_ops != 0) {
        /*
         * Trusted seam: original identity + validated local proof only.
         * No public set_tx_gate, no registry re-stage, no identity re-read.
         * Stack local_ops is never stored.
         */
        if (ninlil_esp_idf_owner_task_publish_tx_gate_trusted(
                &agent->owner, identity, &local_ops)
            != NINLIL_ESP_IDF_OWNER_OK) {
            (void)ninlil_esp_idf_owner_task_shutdown(&agent->owner);
            return 1;
        }
    }
    return 0;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_start(
    ninlil_esp_idf_cell_agent_t *agent)
{
    if (agent == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    return ninlil_esp_idf_owner_task_start(&agent->owner);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_stop(
    ninlil_esp_idf_cell_agent_t *agent)
{
    if (agent == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    return ninlil_esp_idf_owner_task_stop(&agent->owner);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_apply_assignment(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_esp_idf_cell_assignment_t *assignment)
{
    if (agent == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (assignment != NULL
        && cell_fixed_arg_rejects(agent, assignment, sizeof(*assignment))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    return ninlil_esp_idf_owner_task_post_assignment(&agent->owner, assignment);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_set_tx_gate(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_tx_gate_ops_t *tx_gate)
{
    ninlil_tx_gate_ops_t local_ops;

    if (agent == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    /* Public set path remains independent (full stage + validate). */
    if (tx_gate != NULL) {
        ninlil_esp_idf_abi_header_t hdr;
        if (ninlil_esp_idf_abi_stage_known_prefix(
                tx_gate,
                sizeof(local_ops),
                agent,
                sizeof(*agent),
                &local_ops,
                &hdr)
            != 0) {
            return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
        }
        (void)hdr;
        if (!ninlil_esp_idf_tx_gate_ops_validate(&local_ops)) {
            return NINLIL_ESP_IDF_OWNER_POISON;
        }
    }
    return ninlil_esp_idf_owner_task_set_tx_gate(&agent->owner, tx_gate);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_acquire_tx_gate_lease(
    ninlil_esp_idf_cell_agent_t *agent,
    ninlil_esp_idf_tx_gate_lease_t *out_lease)
{
    if (agent == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (out_lease != NULL
        && cell_fixed_arg_rejects(agent, out_lease, sizeof(*out_lease))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    return ninlil_esp_idf_owner_task_acquire_tx_gate_lease(
        &agent->owner, out_lease);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_release_tx_gate_lease(
    ninlil_esp_idf_cell_agent_t *agent,
    const ninlil_esp_idf_tx_gate_lease_t *lease)
{
    if (agent == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (lease != NULL
        && cell_fixed_arg_rejects(agent, lease, sizeof(*lease))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    return ninlil_esp_idf_owner_task_release_tx_gate_lease(
        &agent->owner, lease);
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_cell_agent_shutdown(
    ninlil_esp_idf_cell_agent_t *agent)
{
    if (agent == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    return ninlil_esp_idf_owner_task_shutdown(&agent->owner);
}
