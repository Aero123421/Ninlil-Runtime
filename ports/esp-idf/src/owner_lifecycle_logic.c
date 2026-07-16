#include "owner_lifecycle_logic.h"

#include <string.h>

void ninlil_esp_idf_owner_stats_sat_inc(uint32_t *counter)
{
    if (counter != NULL && *counter < UINT32_MAX) {
        *counter += 1u;
    }
}

void ninlil_esp_idf_owner_core_clear(ninlil_esp_idf_owner_core_t *core)
{
    if (core != NULL) {
        (void)memset(core, 0, sizeof(*core));
        core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_STOPPED;
    }
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_begin_start(
    ninlil_esp_idf_owner_core_t *core)
{
    if (core == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPED
        && core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        return NINLIL_ESP_IDF_OWNER_DOUBLE_START;
    }
    if (core->generation == UINT32_MAX) {
        return NINLIL_ESP_IDF_OWNER_GENERATION_WRAP;
    }
    core->generation += 1u;
    core->owner_context_id = 0u;
    core->assignment_present = 0u;
    (void)memset(&core->assignment, 0, sizeof(core->assignment));
    (void)memset(&core->stats, 0, sizeof(core->stats));
    core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_STARTING;
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_complete_start(
    ninlil_esp_idf_owner_core_t *core,
    uint64_t owner_context_id)
{
    if (core == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_STARTING) {
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    if (owner_context_id == 0u) {
        ninlil_esp_idf_owner_stats_sat_inc(&core->stats.poison);
        core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED;
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    core->owner_context_id = owner_context_id;
    core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_RUNNING;
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_begin_stop(
    ninlil_esp_idf_owner_core_t *core)
{
    if (core == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (core->lifecycle == NINLIL_ESP_IDF_OWNER_LC_STOPPED
        || core->lifecycle == NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED) {
        return NINLIL_ESP_IDF_OWNER_DOUBLE_STOP;
    }
    if (core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_RUNNING
        && core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_STARTING) {
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_STOPPING;
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_mark_join_ack_core(
    ninlil_esp_idf_owner_core_t *core)
{
    if (core == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPING) {
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK;
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_complete_join(
    ninlil_esp_idf_owner_core_t *core)
{
    if (core == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK
        && core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPING) {
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    core->owner_context_id = 0u;
    core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_STOPPED;
    return NINLIL_ESP_IDF_OWNER_OK;
}

void ninlil_esp_idf_owner_fail_joined(ninlil_esp_idf_owner_core_t *core)
{
    if (core != NULL) {
        core->lifecycle = NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED;
        core->owner_context_id = 0u;
    }
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_check_confinement(
    const ninlil_esp_idf_owner_core_t *core,
    uint32_t token_generation,
    uint64_t current_context_id)
{
    if (core == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_RUNNING
        && core->lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPING) {
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    if (token_generation != core->generation) {
        return NINLIL_ESP_IDF_OWNER_STALE_GENERATION;
    }
    if (current_context_id == 0u
        || current_context_id != core->owner_context_id) {
        return NINLIL_ESP_IDF_OWNER_WRONG_CONTEXT;
    }
    return NINLIL_ESP_IDF_OWNER_OK;
}

static ninlil_esp_idf_owner_status_t apply_assignment(
    ninlil_esp_idf_owner_core_t *core,
    const uint8_t *payload,
    uint16_t payload_len)
{
    ninlil_esp_idf_cell_assignment_t a;

    if (payload_len != (uint16_t)sizeof(a)) {
        ninlil_esp_idf_owner_stats_sat_inc(&core->stats.poison);
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    (void)memcpy(&a, payload, sizeof(a));
    if (a.role != NINLIL_ROLE_CELL_AGENT_RESERVED || a.assignment_epoch == 0u
        || a.controller_term == 0u || a.reserved_zero != 0u) {
        ninlil_esp_idf_owner_stats_sat_inc(&core->stats.poison);
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
    if (core->assignment_present != 0u) {
        if (a.controller_term < core->assignment.controller_term
            || (a.controller_term == core->assignment.controller_term
                && a.assignment_epoch < core->assignment.assignment_epoch)) {
            ninlil_esp_idf_owner_stats_sat_inc(&core->stats.stale_apply);
            return NINLIL_ESP_IDF_OWNER_STALE_GENERATION;
        }
    }
    core->assignment = a;
    core->assignment_present = 1u;
    ninlil_esp_idf_owner_stats_sat_inc(&core->stats.assignments_applied);
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_apply_msg(
    ninlil_esp_idf_owner_core_t *core,
    const ninlil_esp_idf_owner_msg_t *msg,
    uint64_t current_context_id)
{
    ninlil_esp_idf_owner_status_t st;

    if (core == NULL || msg == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (msg->kind == NINLIL_ESP_IDF_OWNER_MSG_SELF_STOP_PROBE) {
        ninlil_esp_idf_owner_stats_sat_inc(&core->stats.self_stop_probes);
        return NINLIL_ESP_IDF_OWNER_SELF_STOP;
    }
    st = ninlil_esp_idf_owner_check_confinement(
        core, msg->generation, current_context_id);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        if (st == NINLIL_ESP_IDF_OWNER_STALE_GENERATION) {
            ninlil_esp_idf_owner_stats_sat_inc(&core->stats.stale_apply);
        } else if (st == NINLIL_ESP_IDF_OWNER_WRONG_CONTEXT) {
            ninlil_esp_idf_owner_stats_sat_inc(&core->stats.wrong_context);
        }
        return st;
    }
    switch (msg->kind) {
    case NINLIL_ESP_IDF_OWNER_MSG_TICK:
        ninlil_esp_idf_owner_stats_sat_inc(&core->stats.ticks_applied);
        return NINLIL_ESP_IDF_OWNER_OK;
    case NINLIL_ESP_IDF_OWNER_MSG_ASSIGNMENT:
        return apply_assignment(core, msg->payload, msg->payload_len);
    case NINLIL_ESP_IDF_OWNER_MSG_CONTROL_SUMMARY:
        if (msg->payload_len
            != (uint16_t)sizeof(ninlil_esp_idf_owner_control_summary_t)) {
            ninlil_esp_idf_owner_stats_sat_inc(&core->stats.poison);
            return NINLIL_ESP_IDF_OWNER_POISON;
        }
        ninlil_esp_idf_owner_stats_sat_inc(
            &core->stats.control_summaries_applied);
        return NINLIL_ESP_IDF_OWNER_OK;
    default:
        ninlil_esp_idf_owner_stats_sat_inc(&core->stats.poison);
        return NINLIL_ESP_IDF_OWNER_POISON;
    }
}
