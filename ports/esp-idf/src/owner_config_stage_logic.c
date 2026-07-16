#include "owner_config_stage_logic.h"

#include "pointer_range_logic.h"

#include <stdint.h>

NINLIL_ESP_IDF_INTERNAL int ninlil_esp_idf_owner_config_stage(
    const ninlil_esp_idf_owner_task_config_t *cfg,
    const void *owner_storage,
    size_t owner_storage_size,
    ninlil_esp_idf_owner_task_config_t *out_local,
    ninlil_esp_idf_abi_header_t *out_hdr)
{
    ninlil_esp_idf_abi_header_t hdr_tmp;
    ninlil_esp_idf_owner_task_config_t local_tmp;
    const void *local_out_addr;
    const void *hdr_out_addr;

    if (cfg == NULL || out_local == NULL) {
        return 1;
    }
    /*
     * Storage contract: absent is (NULL, 0). Mixed forms are closed rejects
     * (NULL with non-zero size, or non-NULL with zero size).
     */
    if ((owner_storage == NULL) != (owner_storage_size == 0u)) {
        return 1;
    }
    /*
     * Output alias gates before any stage/commit. Success commit order is
     * out_local then optional out_hdr — mutual alias would corrupt.
     * outs must not overlap owner_storage declared range either.
     * Address via uintptr so not-yet-written outs are not treated as reads.
     */
    local_out_addr = (const void *)(uintptr_t)(void *)out_local;
    if (out_hdr != NULL) {
        hdr_out_addr = (const void *)(uintptr_t)(void *)out_hdr;
        if (ninlil_esp_idf_pointer_ranges_overlap(
                local_out_addr,
                sizeof(*out_local),
                hdr_out_addr,
                sizeof(*out_hdr))) {
            return 1;
        }
        if (owner_storage_size != 0u
            && ninlil_esp_idf_pointer_ranges_overlap(
                hdr_out_addr,
                sizeof(*out_hdr),
                owner_storage,
                owner_storage_size)) {
            return 1;
        }
    }
    if (owner_storage_size != 0u
        && ninlil_esp_idf_pointer_ranges_overlap(
            local_out_addr,
            sizeof(*out_local),
            owner_storage,
            owner_storage_size)) {
        return 1;
    }
    /*
     * Production owner_task_init uses this helper exclusively for config
     * ABI staging. Forward extension: declared struct_size may exceed known
     * sizeof(local_tmp); only known prefix is copied.
     *
     * Stage into stack temps first. reserved_zero / future semantic checks
     * must not poison caller out_local/out_hdr on failure — commit only
     * after every validation succeeds.
     */
    if (ninlil_esp_idf_abi_stage_known_prefix(
            cfg,
            sizeof(local_tmp),
            owner_storage,
            owner_storage_size,
            &local_tmp,
            &hdr_tmp)
        != 0) {
        return 1;
    }
    if (local_tmp.reserved_zero != 0u) {
        return 1;
    }
    *out_local = local_tmp;
    if (out_hdr != NULL) {
        *out_hdr = hdr_tmp;
    }
    return 0;
}
