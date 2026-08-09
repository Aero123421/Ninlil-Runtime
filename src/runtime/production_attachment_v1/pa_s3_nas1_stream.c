/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s3_nas1_stream.h"

#include <stdint.h>
#include <string.h>

#define NAS1_STATE_EMPTY ((uint32_t)0u)
#define NAS1_STATE_OPEN ((uint32_t)1u)
#define NAS1_STATE_DELIVERED ((uint32_t)2u)
#define NAS1_STATE_TERMINAL ((uint32_t)3u)
#define NAS1_HEADER_BYTES ((uint32_t)12u)
#define NAC1_HEADER_BYTES ((uint32_t)88u)

static void secure_zero(void *pointer, size_t size)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    while (size > 0u) {
        *bytes = 0u;
        ++bytes;
        --size;
    }
}

static int any_nonzero(const uint8_t *bytes, size_t size)
{
    uint8_t result = 0u;
    size_t index;
    for (index = 0u; index < size; ++index) {
        result = (uint8_t)(result | bytes[index]);
    }
    return result != 0u;
}

static uint16_t get_u16_be(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | (uint16_t)bytes[1]);
}

static uint32_t get_u32_be(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u)
        | ((uint32_t)bytes[2] << 8u) | (uint32_t)bytes[3];
}

static uint64_t get_u64_be(const uint8_t *bytes)
{
    return ((uint64_t)get_u32_be(bytes) << 32u)
        | (uint64_t)get_u32_be(bytes + 4u);
}

static uint32_t crc32c_zeroed_field(
    const uint8_t *bytes, size_t size, size_t zero_offset, size_t zero_size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t index;
    for (index = 0u; index < size; ++index) {
        uint32_t bit;
        const uint8_t value =
            index >= zero_offset && index - zero_offset < zero_size
            ? 0u : bytes[index];
        crc ^= (uint32_t)value;
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1u)
                ^ (UINT32_C(0x82f63b78) & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static int spans_overlap(
    const void *left, size_t left_size, const void *right, size_t right_size)
{
    const uintptr_t left_begin = (uintptr_t)left;
    const uintptr_t right_begin = (uintptr_t)right;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left_size == 0u || right_size == 0u) {
        return 0;
    }
    if (left == NULL || right == NULL || left_begin > UINTPTR_MAX - left_size
        || right_begin > UINTPTR_MAX - right_size) {
        return 1;
    }
    left_end = left_begin + left_size;
    right_end = right_begin + right_size;
    return left_begin < right_end && right_begin < left_end;
}

static int span_outside_owner(const ninlil_pa_s3_nas1_owner_v1_t *owner,
    const void *pointer, size_t size)
{
    return !spans_overlap(owner, sizeof(*owner), pointer, size);
}

static int sequence_ok(uint32_t kind, uint32_t sequence)
{
    if (kind == 1u || kind == 2u) {
        return sequence == 0u;
    }
    if (kind == 3u) {
        return sequence >= 1u && sequence <= 8u;
    }
    return kind >= 4u && kind <= 11u && sequence == kind - 3u;
}

static int nac1_valid(const ninlil_pa_s3_nas1_owner_v1_t *owner,
    const uint8_t *record, size_t size)
{
    if (size < NAC1_HEADER_BYTES || size > NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX
        || memcmp(record, "NAC1", 4u) != 0
        || get_u16_be(record + 6u) != NAC1_HEADER_BYTES
        || get_u32_be(record + 8u) != size
        || get_u32_be(record + 12u) != size - NAC1_HEADER_BYTES
        || crc32c_zeroed_field(record, size, 84u, 4u)
            != get_u32_be(record + 84u)
        || get_u16_be(record + 4u) != 1u
        || record[16] < 1u || record[16] > 11u || record[17] != 0u
        || record[18] < 1u || record[18] > 3u || record[19] != 0u
        || !any_nonzero(record + 20u, 16u)
        || get_u64_be(record + 36u) == 0u
        || any_nonzero(record + 48u, 4u)
        || !any_nonzero(record + 52u, 32u)
        || !sequence_ok(record[16], get_u32_be(record + 44u))) {
        return 0;
    }
    return record[16] == owner->kind
        && record[18] == owner->carrier_class
        && get_u32_be(record + 44u) == owner->record_sequence
        && get_u64_be(record + 36u) == owner->exchange_generation
        && memcmp(record + 20u, owner->session_id, 16u) == 0
        && memcmp(record + 52u, owner->carrier_binding_digest, 32u) == 0;
}

static void terminal_close(ninlil_pa_s3_nas1_owner_v1_t *owner,
    ninlil_pa_s3_nas1_outcome_v1_t *out_outcome)
{
    secure_zero(owner->buffer, sizeof(owner->buffer));
    owner->buffered_bytes = 0u;
    owner->wrapper_bytes = 0u;
    owner->state = NAS1_STATE_TERMINAL;
    *out_outcome = NINLIL_PA_S3_NAS1_CLOSE;
}

ninlil_status_t ninlil_pa_s3_nas1_owner_v1_init(
    ninlil_pa_s3_nas1_owner_v1_t *owner,
    const ninlil_pa_s3_nas1_config_v1_t *config)
{
    if (owner == NULL || config == NULL
        || !span_outside_owner(owner, config, sizeof(*config))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (owner->state != NAS1_STATE_EMPTY) {
        return NINLIL_E_INVALID_STATE;
    }
    if (config->owner_context_id == 0u
        || (config->carrier_class != NINLIL_PA_S3_NAS1_USB_STREAM
            && config->carrier_class != NINLIL_PA_S3_NAS1_WIFI_STREAM)
        || !any_nonzero(config->session_id, sizeof(config->session_id))
        || !any_nonzero(config->carrier_binding_digest,
            sizeof(config->carrier_binding_digest))
        || config->exchange_generation == 0u
        || !sequence_ok(config->kind, config->record_sequence)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    secure_zero(owner, sizeof(*owner));
    owner->owner_context_id = config->owner_context_id;
    owner->exchange_generation = config->exchange_generation;
    owner->carrier_class = config->carrier_class;
    owner->kind = config->kind;
    owner->record_sequence = config->record_sequence;
    (void)memcpy(owner->session_id, config->session_id,
        sizeof(owner->session_id));
    (void)memcpy(owner->carrier_binding_digest,
        config->carrier_binding_digest,
        sizeof(owner->carrier_binding_digest));
    owner->state = NAS1_STATE_OPEN;
    return NINLIL_OK;
}

ninlil_status_t ninlil_pa_s3_nas1_owner_v1_feed(
    ninlil_pa_s3_nas1_owner_v1_t *owner,
    uint64_t owner_context_id,
    const uint8_t *bytes,
    size_t byte_count,
    uint32_t end_of_stream,
    uint8_t *out_record,
    size_t out_record_capacity,
    size_t *out_record_size,
    ninlil_pa_s3_nas1_outcome_v1_t *out_outcome)
{
    uint32_t inner_bytes;

    if (owner == NULL || out_record == NULL || out_record_size == NULL
        || out_outcome == NULL || out_record_capacity
            < NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX
        || (byte_count > 0u && bytes == NULL) || end_of_stream > 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (owner->state != NAS1_STATE_OPEN) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner->buffered_bytes > NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX
        || owner->wrapper_bytes > NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner_context_id == 0u || owner_context_id != owner->owner_context_id) {
        return NINLIL_E_WRONG_THREAD;
    }
    if (!span_outside_owner(owner, bytes, byte_count)
        || !span_outside_owner(owner, out_record,
            NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX)
        || !span_outside_owner(owner, out_record_size,
            sizeof(*out_record_size))
        || !span_outside_owner(owner, out_outcome, sizeof(*out_outcome))
        || spans_overlap(bytes, byte_count, out_record,
            NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX)
        || spans_overlap(bytes, byte_count, out_record_size,
            sizeof(*out_record_size))
        || spans_overlap(bytes, byte_count, out_outcome, sizeof(*out_outcome))
        || spans_overlap(out_record, NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX,
            out_record_size, sizeof(*out_record_size))
        || spans_overlap(out_record, NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX,
            out_outcome, sizeof(*out_outcome))
        || spans_overlap(out_record_size, sizeof(*out_record_size),
            out_outcome, sizeof(*out_outcome))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    owner->in_call = 1u;
    *out_record_size = 0u;
    *out_outcome = NINLIL_PA_S3_NAS1_NEED_MORE;
    if (byte_count > sizeof(owner->buffer) - owner->buffered_bytes) {
        terminal_close(owner, out_outcome);
        owner->in_call = 0u;
        return NINLIL_OK;
    }
    if (byte_count > 0u) {
        (void)memcpy(owner->buffer + owner->buffered_bytes, bytes, byte_count);
        owner->buffered_bytes += (uint32_t)byte_count;
    }

    if (owner->buffered_bytes < NAS1_HEADER_BYTES) {
        if (end_of_stream != 0u) {
            terminal_close(owner, out_outcome);
        }
        owner->in_call = 0u;
        return NINLIL_OK;
    }

    inner_bytes = get_u32_be(owner->buffer + 8u);
    if (memcmp(owner->buffer, "NAS1", 4u) != 0 || owner->buffer[4] != 1u
        || owner->buffer[5] != owner->carrier_class
        || get_u16_be(owner->buffer + 6u) != NAS1_HEADER_BYTES
        || inner_bytes < NAC1_HEADER_BYTES
        || inner_bytes > NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX) {
        terminal_close(owner, out_outcome);
        owner->in_call = 0u;
        return NINLIL_OK;
    }
    owner->wrapper_bytes = NAS1_HEADER_BYTES + inner_bytes;
    if (owner->buffered_bytes > owner->wrapper_bytes) {
        terminal_close(owner, out_outcome);
        owner->in_call = 0u;
        return NINLIL_OK;
    }
    if (owner->buffered_bytes < owner->wrapper_bytes) {
        if (end_of_stream != 0u) {
            terminal_close(owner, out_outcome);
        }
        owner->in_call = 0u;
        return NINLIL_OK;
    }
    if (!nac1_valid(owner, owner->buffer + NAS1_HEADER_BYTES, inner_bytes)) {
        terminal_close(owner, out_outcome);
        owner->in_call = 0u;
        return NINLIL_OK;
    }

    (void)memcpy(out_record, owner->buffer + NAS1_HEADER_BYTES, inner_bytes);
    *out_record_size = inner_bytes;
    *out_outcome = NINLIL_PA_S3_NAS1_DELIVERED;
    owner->state = NAS1_STATE_DELIVERED;
    owner->in_call = 0u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_pa_s3_nas1_owner_v1_close(
    ninlil_pa_s3_nas1_owner_v1_t *owner,
    uint64_t owner_context_id)
{
    if (owner == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (owner->state == NAS1_STATE_EMPTY) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner_context_id == 0u || owner_context_id != owner->owner_context_id) {
        return NINLIL_E_WRONG_THREAD;
    }
    secure_zero(owner, sizeof(*owner));
    return NINLIL_OK;
}
