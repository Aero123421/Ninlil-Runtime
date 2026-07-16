#include "abi_header_stage_logic.h"

#include "pointer_range_logic.h"

#include <string.h>

int ninlil_esp_idf_abi_stage_header(
    const void *src,
    size_t known_min,
    ninlil_esp_idf_abi_header_t *out_hdr)
{
    ninlil_esp_idf_abi_header_t hdr;

    if (src == NULL || out_hdr == NULL || known_min < sizeof(hdr)) {
        return 1;
    }
    /* Only the fixed 4-byte header is read first. */
    if (!ninlil_esp_idf_pointer_range_representable(src, sizeof(hdr))) {
        return 1;
    }
    (void)memcpy(&hdr, src, sizeof(hdr));
    if (hdr.abi_version != NINLIL_ABI_VERSION) {
        return 1;
    }
    if ((size_t)hdr.struct_size < known_min) {
        return 1;
    }
    *out_hdr = hdr;
    return 0;
}

int ninlil_esp_idf_abi_declared_range_rejects(
    const void *src,
    uint16_t declared_size,
    const void *storage,
    size_t storage_size)
{
    if (src == NULL || declared_size == 0u) {
        return 1;
    }
    if (!ninlil_esp_idf_pointer_range_representable(
            src, (size_t)declared_size)) {
        return 1;
    }
    if (storage == NULL || storage_size == 0u) {
        return 0;
    }
    return ninlil_esp_idf_pointer_ranges_overlap(
        src, (size_t)declared_size, storage, storage_size);
}

int ninlil_esp_idf_abi_stage_known_prefix(
    const void *src,
    size_t known_min,
    const void *storage,
    size_t storage_size,
    void *out_local,
    ninlil_esp_idf_abi_header_t *out_hdr)
{
    ninlil_esp_idf_abi_header_t hdr;

    if (out_local == NULL) {
        return 1;
    }
    if (ninlil_esp_idf_abi_stage_header(src, known_min, &hdr) != 0) {
        return 1;
    }
    if (ninlil_esp_idf_abi_declared_range_rejects(
            src, hdr.struct_size, storage, storage_size)
        != 0) {
        return 1;
    }
    /* Known prefix only — never memcpy declared tail into local. */
    if (!ninlil_esp_idf_pointer_range_representable(src, known_min)) {
        return 1;
    }
    (void)memcpy(out_local, src, known_min);
    if (out_hdr != NULL) {
        *out_hdr = hdr;
    }
    return 0;
}

int ninlil_esp_idf_fixed_arg_rejects(
    const void *arg,
    size_t arg_size,
    const void *storage,
    size_t storage_size)
{
    if (arg_size == 0u) {
        return 0;
    }
    if (arg == NULL) {
        return 1;
    }
    if (storage == NULL || storage_size == 0u) {
        return 0;
    }
    return ninlil_esp_idf_pointer_ranges_overlap(
        arg, arg_size, storage, storage_size);
}
