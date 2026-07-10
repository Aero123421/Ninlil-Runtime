#ifndef NINLIL_ABI_CONTRACT_H
#define NINLIL_ABI_CONTRACT_H

#include "ninlil/version.h"

#include <stddef.h>
#include <stdint.h>

/* Internal Foundation helper. This header is not part of the public ABI. */

typedef struct ninlil_contract_preserve_range {
    size_t offset;
    size_t length;
} ninlil_contract_preserve_range_t;

ninlil_status_t ninlil_contract_require_nonnull(const void *value);

ninlil_status_t ninlil_contract_validate_struct(
    const void *value,
    size_t required_size,
    size_t known_size);

/*
 * Validate the output header, then zero only the known caller-provided bytes.
 * The ABI header and each explicitly declared caller-owned range remain byte
 * identical. Preserve ranges must be non-empty, disjoint, outside the header,
 * and wholly contained in required_size. No bytes change on validation error.
 */
ninlil_status_t ninlil_contract_prepare_output(
    void *output,
    size_t required_size,
    size_t known_size,
    const ninlil_contract_preserve_range_t *preserve_ranges,
    size_t preserve_count);

/*
 * Return OK for a supported value, UNSUPPORTED for a named reserved value, and
 * INVALID_ARGUMENT for an unknown numeric value or an invalid value table.
 */
ninlil_status_t ninlil_contract_classify_u32(
    uint32_t value,
    const uint32_t *supported_values,
    size_t supported_count,
    const uint32_t *reserved_values,
    size_t reserved_count);

#endif /* NINLIL_ABI_CONTRACT_H */
