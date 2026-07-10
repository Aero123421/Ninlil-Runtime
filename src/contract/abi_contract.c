#include "abi_contract.h"

#include <limits.h>
#include <string.h>

typedef struct ninlil_contract_header {
    NINLIL_STRUCT_HEADER;
} ninlil_contract_header_t;

_Static_assert(sizeof(ninlil_contract_header_t) == 4u, "unexpected ABI header size");

static ninlil_status_t validate_layout(size_t required_size, size_t known_size)
{
    if (required_size < sizeof(ninlil_contract_header_t) || known_size < required_size
        || known_size > UINT16_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

static ninlil_status_t read_valid_header(
    const void *value,
    size_t required_size,
    size_t known_size,
    ninlil_contract_header_t *out_header)
{
    ninlil_status_t status;

    if (value == NULL || out_header == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = validate_layout(required_size, known_size);
    if (status != NINLIL_OK) {
        return status;
    }
    memcpy(out_header, value, sizeof(*out_header));
    if (out_header->abi_version != NINLIL_ABI_VERSION
        || (size_t)out_header->struct_size < required_size) {
        return NINLIL_E_ABI_MISMATCH;
    }
    return NINLIL_OK;
}

static int range_contains(const ninlil_contract_preserve_range_t *range, size_t offset)
{
    return offset >= range->offset && offset - range->offset < range->length;
}

static ninlil_status_t validate_preserve_ranges(
    const ninlil_contract_preserve_range_t *ranges,
    size_t count,
    size_t required_size)
{
    size_t index;

    if (count > 0u && ranges == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (index = 0u; index < count; ++index) {
        size_t prior;
        size_t end;
        if (ranges[index].length == 0u
            || ranges[index].offset < sizeof(ninlil_contract_header_t)
            || ranges[index].offset > required_size
            || ranges[index].length > required_size - ranges[index].offset) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        end = ranges[index].offset + ranges[index].length;
        for (prior = 0u; prior < index; ++prior) {
            size_t prior_end = ranges[prior].offset + ranges[prior].length;
            if (ranges[index].offset < prior_end && ranges[prior].offset < end) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
        }
    }
    return NINLIL_OK;
}

static int contains_u32(const uint32_t *values, size_t count, uint32_t value)
{
    size_t index;
    for (index = 0u; index < count; ++index) {
        if (values[index] == value) {
            return 1;
        }
    }
    return 0;
}

static int value_tables_are_disjoint(
    const uint32_t *supported_values,
    size_t supported_count,
    const uint32_t *reserved_values,
    size_t reserved_count)
{
    size_t index;
    size_t other;

    for (index = 0u; index < supported_count; ++index) {
        for (other = index + 1u; other < supported_count; ++other) {
            if (supported_values[index] == supported_values[other]) {
                return 0;
            }
        }
        for (other = 0u; other < reserved_count; ++other) {
            if (supported_values[index] == reserved_values[other]) {
                return 0;
            }
        }
    }
    for (index = 0u; index < reserved_count; ++index) {
        for (other = index + 1u; other < reserved_count; ++other) {
            if (reserved_values[index] == reserved_values[other]) {
                return 0;
            }
        }
    }
    return 1;
}

ninlil_status_t ninlil_contract_require_nonnull(const void *value)
{
    return value == NULL ? NINLIL_E_INVALID_ARGUMENT : NINLIL_OK;
}

ninlil_status_t ninlil_contract_validate_struct(
    const void *value,
    size_t required_size,
    size_t known_size)
{
    ninlil_contract_header_t header;
    return read_valid_header(value, required_size, known_size, &header);
}

ninlil_status_t ninlil_contract_prepare_output(
    void *output,
    size_t required_size,
    size_t known_size,
    const ninlil_contract_preserve_range_t *preserve_ranges,
    size_t preserve_count)
{
    ninlil_contract_header_t header;
    ninlil_status_t status;
    size_t write_size;
    size_t offset;
    uint8_t *bytes = (uint8_t *)output;

    status = read_valid_header(output, required_size, known_size, &header);
    if (status != NINLIL_OK) {
        return status;
    }
    status = validate_preserve_ranges(preserve_ranges, preserve_count, required_size);
    if (status != NINLIL_OK) {
        return status;
    }
    write_size = (size_t)header.struct_size < known_size ? (size_t)header.struct_size : known_size;
    for (offset = sizeof(header); offset < write_size; ++offset) {
        size_t range_index;
        int preserved = 0;
        for (range_index = 0u; range_index < preserve_count; ++range_index) {
            if (range_contains(&preserve_ranges[range_index], offset)) {
                preserved = 1;
                break;
            }
        }
        if (preserved == 0) {
            bytes[offset] = 0u;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_contract_classify_u32(
    uint32_t value,
    const uint32_t *supported_values,
    size_t supported_count,
    const uint32_t *reserved_values,
    size_t reserved_count)
{
    if ((supported_count > 0u && supported_values == NULL)
        || (reserved_count > 0u && reserved_values == NULL)
        || !value_tables_are_disjoint(
            supported_values, supported_count, reserved_values, reserved_count)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (contains_u32(supported_values, supported_count, value)) {
        return NINLIL_OK;
    }
    if (contains_u32(reserved_values, reserved_count, value)) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_E_INVALID_ARGUMENT;
}
