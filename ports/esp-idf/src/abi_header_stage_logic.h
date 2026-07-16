/*
 * Pure ABI header staging + declared struct_size non-overlap (docs/22).
 * Stage minimal header first; only then inspect declared full range vs storage.
 * Never uses pointer relational operators (delegates to pointer_range_logic).
 */

#ifndef NINLIL_ESP_IDF_ABI_HEADER_STAGE_LOGIC_H
#define NINLIL_ESP_IDF_ABI_HEADER_STAGE_LOGIC_H

#include "ninlil/version.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Always-first two fields of NINLIL_STRUCT_HEADER. */
typedef struct ninlil_esp_idf_abi_header {
    uint16_t abi_version;
    uint16_t struct_size;
} ninlil_esp_idf_abi_header_t;

/*
 * Copy only the 4-byte ABI header from src (no declared-size walk yet).
 * Fails if src NULL, header range unrepresentable, abi_version mismatch,
 * or struct_size < known_min.
 * Returns 0 ok, non-zero fail. out_hdr only written on success.
 */
int ninlil_esp_idf_abi_stage_header(
    const void *src,
    size_t known_min,
    ninlil_esp_idf_abi_header_t *out_hdr);

/*
 * After header stage: reject if declared full range [src, struct_size)
 * is unrepresentable or overlaps storage [storage, storage_size).
 * Returns 1 if must reject (overlap/overflow), 0 if disjoint OK.
 */
int ninlil_esp_idf_abi_declared_range_rejects(
    const void *src,
    uint16_t declared_size,
    const void *storage,
    size_t storage_size);

/*
 * Full pipeline for a struct_size-bearing input:
 *  1) stage header
 *  2) declared full-range non-overlap vs storage (+ representable)
 *  3) copy only known_min bytes into out_local (never copies tail)
 * Returns 0 ok, non-zero fail. out_local/out_hdr untouched on fail.
 */
int ninlil_esp_idf_abi_stage_known_prefix(
    const void *src,
    size_t known_min,
    const void *storage,
    size_t storage_size,
    void *out_local,
    ninlil_esp_idf_abi_header_t *out_hdr);

/*
 * Output / fixed-size object non-overlap vs storage (no ABI header).
 * Returns 1 reject, 0 ok. NULL arg with size>0 rejects; size==0 ok.
 */
int ninlil_esp_idf_fixed_arg_rejects(
    const void *arg,
    size_t arg_size,
    const void *storage,
    size_t storage_size);

#ifdef __cplusplus
}
#endif

#endif
