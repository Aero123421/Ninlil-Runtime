/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s3_nar1_reassembly.h"

#include "domain_store_codec.h"

#include <stdint.h>
#include <string.h>

#define NAR1_STATE_EMPTY ((uint32_t)0u)
#define NAR1_STATE_OPEN ((uint32_t)1u)
#define NAR1_STATE_DELIVERED ((uint32_t)2u)
#define NAR1_STATE_TERMINAL ((uint32_t)3u)
#define NAR1_HEADER_BYTES ((uint32_t)68u)
#define NAR1_PAYLOAD_BYTES_MAX ((uint32_t)124u)
#define NAR1_FRAGMENT_COUNT_MAX ((uint32_t)5u)
#define NAC1_HEADER_BYTES ((uint32_t)88u)

typedef struct nar1_view {
    const uint8_t *payload;
    uint8_t session_id[16];
    uint8_t record_digest[16];
    uint64_t exchange_generation;
    uint32_t record_sequence;
    uint32_t complete_bytes;
    uint32_t payload_bytes;
    uint32_t fragment_index;
    uint32_t fragment_count;
    uint32_t offset;
} nar1_view_t;

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

static int span_outside_owner(const ninlil_pa_s3_nar1_owner_v1_t *owner,
    const void *pointer, size_t size)
{
    return !spans_overlap(owner, sizeof(*owner), pointer, size);
}

static uint32_t bit_count(uint32_t value)
{
    uint32_t count = 0u;
    while (value != 0u) {
        count += value & 1u;
        value >>= 1u;
    }
    return count;
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

static int nac1_structural_valid(const uint8_t *record, size_t size)
{
    if (size < NAC1_HEADER_BYTES || size > NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX
        || memcmp(record, "NAC1", 4u) != 0
        || get_u16_be(record + 4u) != 1u
        || get_u16_be(record + 6u) != NAC1_HEADER_BYTES
        || get_u32_be(record + 8u) != size
        || get_u32_be(record + 12u) != size - NAC1_HEADER_BYTES
        || record[17] != 0u
        || record[18] != 3u || record[19] != 0u
        || !any_nonzero(record + 20u, 16u)
        || get_u64_be(record + 36u) == 0u
        || !sequence_ok(record[16], get_u32_be(record + 44u))
        || any_nonzero(record + 48u, 4u)
        || !any_nonzero(record + 52u, 32u)
        || crc32c_zeroed_field(record, size, 84u, 4u)
            != get_u32_be(record + 84u)) {
        return 0;
    }
    return 1;
}

static int parse_packet(
    const uint8_t *packet, size_t packet_size, nar1_view_t *view)
{
    uint32_t expected_count;
    uint32_t expected_payload;

    if (packet == NULL || view == NULL || packet_size < NAR1_HEADER_BYTES
        || packet_size > NINLIL_PA_S3_NAR1_PACKET_BYTES_MAX
        || memcmp(packet, "NAR1", 4u) != 0 || packet[4] != 0x12u
        || packet[5] != 1u || get_u16_be(packet + 6u) != NAR1_HEADER_BYTES
        || get_u16_be(packet + 8u) != packet_size) {
        return 0;
    }
    view->payload_bytes = get_u16_be(packet + 10u);
    view->complete_bytes = get_u16_be(packet + 40u);
    view->fragment_index = packet[42];
    view->fragment_count = packet[43];
    view->offset = get_u32_be(packet + 60u);
    if (view->payload_bytes != packet_size - NAR1_HEADER_BYTES
        || view->complete_bytes < NAC1_HEADER_BYTES
        || view->complete_bytes > NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX
        || view->fragment_index >= view->fragment_count) {
        return 0;
    }
    expected_count = (view->complete_bytes + NAR1_PAYLOAD_BYTES_MAX - 1u)
        / NAR1_PAYLOAD_BYTES_MAX;
    expected_payload = view->fragment_index + 1u < view->fragment_count
        ? NAR1_PAYLOAD_BYTES_MAX
        : view->complete_bytes
            - view->fragment_index * NAR1_PAYLOAD_BYTES_MAX;
    if (view->fragment_count != expected_count
        || view->payload_bytes != expected_payload
        || view->offset != view->fragment_index * NAR1_PAYLOAD_BYTES_MAX
        || crc32c_zeroed_field(packet, packet_size, 64u, 4u)
            != get_u32_be(packet + 64u)) {
        return 0;
    }
    (void)memcpy(view->session_id, packet + 12u, sizeof(view->session_id));
    view->exchange_generation = get_u64_be(packet + 28u);
    view->record_sequence = get_u32_be(packet + 36u);
    (void)memcpy(view->record_digest, packet + 44u,
        sizeof(view->record_digest));
    view->payload = packet + NAR1_HEADER_BYTES;
    return 1;
}

static int owner_shape_valid(const ninlil_pa_s3_nar1_owner_v1_t *owner)
{
    const uint32_t valid_mask = owner->fragment_count >= 1u
            && owner->fragment_count <= NAR1_FRAGMENT_COUNT_MAX
        ? (UINT32_C(1) << owner->fragment_count) - 1u : 0u;
    if (owner->owner_context_id == 0u
        || !any_nonzero(owner->source_locator_digest,
            sizeof(owner->source_locator_digest))
        || owner->received_count > NAR1_FRAGMENT_COUNT_MAX
        || (owner->received_mask & ~UINT32_C(0x1f)) != 0u
        || bit_count(owner->received_mask) != owner->received_count) {
        return 0;
    }
    if (owner->received_count == 0u) {
        return owner->fragment_count == 0u && owner->complete_bytes == 0u
            && owner->received_mask == 0u;
    }
    return owner->fragment_count >= 1u
        && owner->fragment_count <= NAR1_FRAGMENT_COUNT_MAX
        && owner->received_count < owner->fragment_count
        && owner->complete_bytes >= NAC1_HEADER_BYTES
        && owner->complete_bytes <= NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX
        && owner->fragment_count
            == (owner->complete_bytes + NAR1_PAYLOAD_BYTES_MAX - 1u)
                / NAR1_PAYLOAD_BYTES_MAX
        && (owner->received_mask & ~valid_mask) == 0u;
}

static void terminal_wipe(ninlil_pa_s3_nar1_owner_v1_t *owner)
{
    const uint64_t context = owner->owner_context_id;
    secure_zero(owner, sizeof(*owner));
    owner->owner_context_id = context;
    owner->state = NAR1_STATE_TERMINAL;
}

static int tuple_matches(const ninlil_pa_s3_nar1_owner_v1_t *owner,
    const nar1_view_t *view)
{
    return owner->exchange_generation == view->exchange_generation
        && owner->record_sequence == view->record_sequence
        && owner->complete_bytes == view->complete_bytes
        && owner->fragment_count == view->fragment_count
        && memcmp(owner->session_id, view->session_id, 16u) == 0
        && memcmp(owner->record_digest, view->record_digest, 16u) == 0;
}

static int complete_valid(const ninlil_pa_s3_nar1_owner_v1_t *owner)
{
    ninlil_model_domain_digest_t digest;
    const int hashed = ninlil_model_domain_sha256(owner->record,
        owner->complete_bytes, &digest) == NINLIL_OK;
    const int valid = hashed
        && memcmp(digest.bytes, owner->record_digest, 16u) == 0
        && nac1_structural_valid(owner->record, owner->complete_bytes)
        && memcmp(owner->record + 20u, owner->session_id, 16u) == 0
        && get_u64_be(owner->record + 36u) == owner->exchange_generation
        && get_u32_be(owner->record + 44u) == owner->record_sequence;
    secure_zero(&digest, sizeof(digest));
    return valid;
}

ninlil_status_t ninlil_pa_s3_nar1_owner_v1_init(
    ninlil_pa_s3_nar1_owner_v1_t *owner,
    const ninlil_pa_s3_nar1_config_v1_t *config)
{
    if (owner == NULL || config == NULL
        || !span_outside_owner(owner, config, sizeof(*config))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (owner->state != NAR1_STATE_EMPTY) {
        return NINLIL_E_INVALID_STATE;
    }
    if (config->owner_context_id == 0u
        || !any_nonzero(config->source_locator_digest,
            sizeof(config->source_locator_digest))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    secure_zero(owner, sizeof(*owner));
    owner->owner_context_id = config->owner_context_id;
    (void)memcpy(owner->source_locator_digest,
        config->source_locator_digest,
        sizeof(owner->source_locator_digest));
    owner->state = NAR1_STATE_OPEN;
    return NINLIL_OK;
}

ninlil_status_t ninlil_pa_s3_nar1_owner_v1_feed(
    ninlil_pa_s3_nar1_owner_v1_t *owner,
    uint64_t owner_context_id,
    const uint8_t source_locator_digest[NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES],
    const uint8_t *packet,
    size_t packet_size,
    uint8_t *out_record,
    size_t out_record_capacity,
    size_t *out_record_size,
    ninlil_pa_s3_nar1_outcome_v1_t *out_outcome)
{
    nar1_view_t view;
    uint32_t bit;

    if (owner == NULL || source_locator_digest == NULL || packet == NULL
        || out_record == NULL || out_record_size == NULL || out_outcome == NULL
        || packet_size == 0u
        || out_record_capacity < NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (owner->state != NAR1_STATE_OPEN || !owner_shape_valid(owner)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner_context_id == 0u || owner_context_id != owner->owner_context_id) {
        return NINLIL_E_WRONG_THREAD;
    }
    if (!span_outside_owner(owner, source_locator_digest,
            NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES)
        || !span_outside_owner(owner, packet, packet_size)
        || !span_outside_owner(owner, out_record,
            NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX)
        || !span_outside_owner(owner, out_record_size,
            sizeof(*out_record_size))
        || !span_outside_owner(owner, out_outcome, sizeof(*out_outcome))
        || spans_overlap(source_locator_digest,
            NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES, packet, packet_size)
        || spans_overlap(source_locator_digest,
            NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES, out_record,
            NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX)
        || spans_overlap(source_locator_digest,
            NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES, out_record_size,
            sizeof(*out_record_size))
        || spans_overlap(source_locator_digest,
            NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES, out_outcome,
            sizeof(*out_outcome))
        || spans_overlap(packet, packet_size, out_record,
            NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX)
        || spans_overlap(packet, packet_size, out_record_size,
            sizeof(*out_record_size))
        || spans_overlap(packet, packet_size, out_outcome,
            sizeof(*out_outcome))
        || spans_overlap(out_record, NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX,
            out_record_size, sizeof(*out_record_size))
        || spans_overlap(out_record, NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX,
            out_outcome, sizeof(*out_outcome))
        || spans_overlap(out_record_size, sizeof(*out_record_size),
            out_outcome, sizeof(*out_outcome))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    secure_zero(&view, sizeof(view));
    if (!parse_packet(packet, packet_size, &view)) {
        terminal_wipe(owner);
        *out_record_size = 0u;
        *out_outcome = NINLIL_PA_S3_NAR1_TERMINAL;
        return NINLIL_OK;
    }

    owner->in_call = 1u;
    *out_record_size = 0u;
    *out_outcome = NINLIL_PA_S3_NAR1_PROGRESS;
    if (memcmp(source_locator_digest, owner->source_locator_digest,
            NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES) != 0) {
        terminal_wipe(owner);
        *out_outcome = NINLIL_PA_S3_NAR1_TERMINAL;
        return NINLIL_OK;
    }
    if (owner->received_count == 0u) {
        (void)memcpy(owner->session_id, view.session_id, 16u);
        (void)memcpy(owner->record_digest, view.record_digest, 16u);
        owner->exchange_generation = view.exchange_generation;
        owner->record_sequence = view.record_sequence;
        owner->complete_bytes = view.complete_bytes;
        owner->fragment_count = view.fragment_count;
    } else if (!tuple_matches(owner, &view)) {
        terminal_wipe(owner);
        *out_outcome = NINLIL_PA_S3_NAR1_TERMINAL;
        return NINLIL_OK;
    }

    bit = UINT32_C(1) << view.fragment_index;
    if ((owner->received_mask & bit) != 0u) {
        if (memcmp(owner->record + view.offset, view.payload,
                view.payload_bytes) != 0) {
            terminal_wipe(owner);
            *out_outcome = NINLIL_PA_S3_NAR1_TERMINAL;
            return NINLIL_OK;
        }
        owner->in_call = 0u;
        *out_outcome = NINLIL_PA_S3_NAR1_DUPLICATE;
        return NINLIL_OK;
    }

    (void)memcpy(owner->record + view.offset, view.payload,
        view.payload_bytes);
    owner->received_mask |= bit;
    owner->received_count += 1u;
    if (owner->received_count == owner->fragment_count) {
        const size_t complete_bytes = owner->complete_bytes;
        if (!complete_valid(owner)) {
            terminal_wipe(owner);
            *out_outcome = NINLIL_PA_S3_NAR1_TERMINAL;
            return NINLIL_OK;
        }
        (void)memcpy(out_record, owner->record, complete_bytes);
        *out_record_size = complete_bytes;
        *out_outcome = NINLIL_PA_S3_NAR1_DELIVERED;
        secure_zero(owner->record, sizeof(owner->record));
        owner->state = NAR1_STATE_DELIVERED;
    }
    owner->in_call = 0u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_pa_s3_nar1_owner_v1_close(
    ninlil_pa_s3_nar1_owner_v1_t *owner,
    uint64_t owner_context_id)
{
    if (owner == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (owner->state == NAR1_STATE_EMPTY) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner_context_id == 0u || owner_context_id != owner->owner_context_id) {
        return NINLIL_E_WRONG_THREAD;
    }
    secure_zero(owner, sizeof(*owner));
    return NINLIL_OK;
}
