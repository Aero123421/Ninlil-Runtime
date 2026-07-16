/*
 * Pure cell outer/nested owner config staging (docs/22).
 * Nested owner inline layout: exact sizeof(owner config) only.
 * Entire helper is static inline — no default global package symbol.
 * Failure atomicity: all outs staged to temps; commit only on full success.
 */

#ifndef NINLIL_ESP_IDF_CELL_CONFIG_STAGE_LOGIC_H
#define NINLIL_ESP_IDF_CELL_CONFIG_STAGE_LOGIC_H

#include "ninlil_esp_idf/cell_agent.h"

#include "abi_header_stage_logic.h"
#include "pointer_range_logic.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stage outer cell config known prefix vs storage.
 * Then stage nested owner from original outer's owner field:
 *  - header from original nested location
 *  - nested struct_size must equal exact sizeof(owner config) (inline layout)
 *  - nested declared range fully contained in outer declared range
 *  - nested must not overlap outer tx_gate field
 * Copies nested known prefix into out_owner_local for owner_task_init.
 *
 * Contract:
 *  - out_outer_local / out_owner_local required; out_outer_hdr optional NULL
 *  - storage (NULL,0) or both present; mixed NULL/size closed reject
 *  - outs must not alias each other or storage range
 *  - all failure paths leave outs/storage/caller bytes unchanged
 * Returns 0 ok.
 */
static inline int ninlil_esp_idf_cell_config_stage_nested_owner(
    const ninlil_esp_idf_cell_agent_config_t *outer_src,
    const void *storage,
    size_t storage_size,
    ninlil_esp_idf_cell_agent_config_t *out_outer_local,
    ninlil_esp_idf_owner_task_config_t *out_owner_local,
    ninlil_esp_idf_abi_header_t *out_outer_hdr)
{
    ninlil_esp_idf_abi_header_t outer_hdr;
    ninlil_esp_idf_abi_header_t owner_hdr;
    ninlil_esp_idf_cell_agent_config_t outer_tmp;
    ninlil_esp_idf_owner_task_config_t owner_tmp;
    const ninlil_esp_idf_owner_task_config_t *owner_src;
    const void *tx_gate_field;
    size_t owner_known;
    /* Address-only views: out contents may be uninitialized before commit. */
    const void *outer_out_addr;
    const void *owner_out_addr;
    const void *hdr_out_addr;

    if (outer_src == NULL || out_outer_local == NULL || out_owner_local == NULL) {
        return 1;
    }
    if ((storage == NULL) != (storage_size == 0u)) {
        return 1;
    }
    owner_known = sizeof(owner_tmp);

    /*
     * Capture addresses via uintptr_t so alias gates never imply a pointee
     * read of not-yet-written outs (portable vs GCC -Wmaybe-uninitialized).
     */
    outer_out_addr = (const void *)(uintptr_t)(void *)out_outer_local;
    owner_out_addr = (const void *)(uintptr_t)(void *)out_owner_local;

    /* Mutual / storage alias before any stage write into caller outs. */
    if (ninlil_esp_idf_pointer_ranges_overlap(
            outer_out_addr,
            sizeof(*out_outer_local),
            owner_out_addr,
            sizeof(*out_owner_local))) {
        return 1;
    }
    if (out_outer_hdr != NULL) {
        hdr_out_addr = (const void *)(uintptr_t)(void *)out_outer_hdr;
        if (ninlil_esp_idf_pointer_ranges_overlap(
                outer_out_addr,
                sizeof(*out_outer_local),
                hdr_out_addr,
                sizeof(*out_outer_hdr))
            || ninlil_esp_idf_pointer_ranges_overlap(
                owner_out_addr,
                sizeof(*out_owner_local),
                hdr_out_addr,
                sizeof(*out_outer_hdr))) {
            return 1;
        }
        if (storage_size != 0u
            && ninlil_esp_idf_pointer_ranges_overlap(
                hdr_out_addr,
                sizeof(*out_outer_hdr),
                storage,
                storage_size)) {
            return 1;
        }
    }
    if (storage_size != 0u) {
        if (ninlil_esp_idf_pointer_ranges_overlap(
                outer_out_addr,
                sizeof(*out_outer_local),
                storage,
                storage_size)
            || ninlil_esp_idf_pointer_ranges_overlap(
                owner_out_addr,
                sizeof(*out_owner_local),
                storage,
                storage_size)) {
            return 1;
        }
    }

    /*
     * Full pipeline into stack temps only. reserved_zero / nested exact-size /
     * containment / tx_gate overlap rejects must not poison caller outs.
     */
    if (ninlil_esp_idf_abi_stage_known_prefix(
            outer_src,
            sizeof(outer_tmp),
            storage,
            storage_size,
            &outer_tmp,
            &outer_hdr)
        != 0) {
        return 1;
    }
    if (outer_tmp.reserved_zero != 0u) {
        return 1;
    }

    owner_src = (const ninlil_esp_idf_owner_task_config_t *)(const void *)(
        (const uint8_t *)(const void *)outer_src
        + offsetof(ninlil_esp_idf_cell_agent_config_t, owner));

    if (ninlil_esp_idf_abi_stage_header(owner_src, owner_known, &owner_hdr)
        != 0) {
        return 1;
    }
    if (owner_hdr.struct_size != (uint16_t)owner_known) {
        return 1;
    }
    if (!ninlil_esp_idf_pointer_range_contains(
            outer_src,
            (size_t)outer_hdr.struct_size,
            owner_src,
            (size_t)owner_hdr.struct_size)) {
        return 1;
    }

    tx_gate_field = (const void *)((const uint8_t *)(const void *)outer_src
        + offsetof(ninlil_esp_idf_cell_agent_config_t, tx_gate));
    if (ninlil_esp_idf_pointer_ranges_overlap(
            owner_src,
            (size_t)owner_hdr.struct_size,
            tx_gate_field,
            sizeof(const ninlil_tx_gate_ops_t *))) {
        return 1;
    }

    if (!ninlil_esp_idf_pointer_range_representable(owner_src, owner_known)) {
        return 1;
    }
    (void)memcpy(&owner_tmp, owner_src, owner_known);
    owner_tmp.struct_size = (uint16_t)owner_known;

    /* Commit only after every validation succeeded. */
    *out_outer_local = outer_tmp;
    *out_owner_local = owner_tmp;
    if (out_outer_hdr != NULL) {
        *out_outer_hdr = outer_hdr;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif
