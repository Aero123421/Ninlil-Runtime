#include "tx_gate_lease_logic.h"

#include "abi_header_stage_logic.h"
#include "pointer_range_logic.h"

#include <stdint.h>
#include <string.h>

void ninlil_esp_idf_tx_gate_lease_registry_clear(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg)
{
    if (reg != NULL) {
        (void)memset(reg, 0, sizeof(*reg));
        reg->next_token = 1u;
        reg->epoch = 0u;
    }
}

int ninlil_esp_idf_tx_gate_lease_registry_set_ops(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg,
    const ninlil_tx_gate_ops_t *ops)
{
    if (reg == NULL) {
        return 1;
    }
    if (reg->occupied_count != 0u) {
        return 1;
    }
    if (reg->epoch == UINT32_MAX) {
        return 1;
    }
    /*
     * ops: stage header then reject declared full-range overlap with registry
     * (fixed sizeof is insufficient — catches tail-only extended ops).
     */
    if (ops != NULL) {
        ninlil_esp_idf_abi_header_t hdr;
        ninlil_tx_gate_ops_t local;
        if (ninlil_esp_idf_abi_stage_known_prefix(
                ops, sizeof(local), reg, sizeof(*reg), &local, &hdr)
            != 0) {
            return 1;
        }
        (void)local;
        (void)hdr;
    }
    reg->current_ops = ops;
    reg->epoch += 1u;
    return 0;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_tx_gate_lease_registry_acquire(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg,
    ninlil_esp_idf_tx_gate_lease_t *out_lease)
{
    uint32_t i;
    ninlil_esp_idf_tx_gate_lease_slot_t *slot;

    if (reg == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (out_lease == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    /* Reject head/tail/partial/full overlap of out with registry. */
    if (ninlil_esp_idf_pointer_ranges_overlap(
            reg, sizeof(*reg), out_lease, sizeof(*out_lease))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    if (reg->current_ops == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_STATE;
    }
    if (reg->next_token == 0u || reg->next_token == UINT32_MAX) {
        return NINLIL_ESP_IDF_OWNER_TOKEN_EXHAUSTED;
    }
    slot = NULL;
    for (i = 0u; i < NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES; ++i) {
        if (reg->slots[i].occupied == 0u) {
            slot = &reg->slots[i];
            break;
        }
    }
    if (slot == NULL) {
        return NINLIL_ESP_IDF_OWNER_LEASE_FULL;
    }

    slot->occupied = 1u;
    slot->token = reg->next_token;
    slot->epoch = reg->epoch;
    slot->ops = reg->current_ops;
    reg->next_token += 1u; /* may become UINT32_MAX → next acquire exhausts */
    reg->occupied_count += 1u;

    out_lease->token = slot->token;
    out_lease->epoch = slot->epoch;
    out_lease->ops = slot->ops;
    return NINLIL_ESP_IDF_OWNER_OK;
}

ninlil_esp_idf_owner_status_t ninlil_esp_idf_tx_gate_lease_registry_release(
    ninlil_esp_idf_tx_gate_lease_registry_t *reg,
    const ninlil_esp_idf_tx_gate_lease_t *lease)
{
    uint32_t i;

    if (reg == NULL || lease == NULL) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    /* Reject lease input aliasing registry (would read through corrupt view). */
    if (ninlil_esp_idf_pointer_ranges_overlap(
            reg, sizeof(*reg), lease, sizeof(*lease))) {
        return NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES; ++i) {
        ninlil_esp_idf_tx_gate_lease_slot_t *slot = &reg->slots[i];
        if (slot->occupied == 0u) {
            continue;
        }
        if (slot->token == lease->token && slot->epoch == lease->epoch
            && slot->ops == lease->ops) {
            slot->occupied = 0u;
            slot->token = 0u;
            slot->epoch = 0u;
            slot->ops = NULL;
            if (reg->occupied_count > 0u) {
                reg->occupied_count -= 1u;
            }
            return NINLIL_ESP_IDF_OWNER_OK;
        }
    }
    /* Double release / forged token/epoch/ops: no mutation. */
    return NINLIL_ESP_IDF_OWNER_LEASE_STALE;
}
