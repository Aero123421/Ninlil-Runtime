/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s3_nar1_reassembly.h"

#include "domain_store_codec.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(expr) do { \
    if (!(expr)) { \
        (void)fprintf(stderr, "require failed: %s:%d: %s\n", \
            __FILE__, __LINE__, #expr); \
        return 0; \
    } \
} while (0)

#define HEADER_BYTES ((size_t)68u)
#define PAYLOAD_MAX ((size_t)124u)

typedef struct packet_set {
    uint8_t bytes[5][NINLIL_PA_S3_NAR1_PACKET_BYTES_MAX];
    size_t sizes[5];
    uint32_t count;
} packet_set_t;

static void put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8u);
    bytes[1] = (uint8_t)value;
}

static void put_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
}

static void put_u64(uint8_t *bytes, uint64_t value)
{
    put_u32(bytes, (uint32_t)(value >> 32u));
    put_u32(bytes + 4u, (uint32_t)value);
}

static uint32_t crc32c_zeroed(
    const uint8_t *bytes, size_t size, size_t offset, size_t zero_size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t index;
    for (index = 0u; index < size; ++index) {
        uint32_t bit;
        const uint8_t value = index >= offset && index - offset < zero_size
            ? 0u : bytes[index];
        crc ^= (uint32_t)value;
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1u)
                ^ (UINT32_C(0x82f63b78) & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static void make_source(uint8_t source[32], uint8_t seed)
{
    size_t index;
    for (index = 0u; index < 32u; ++index) {
        source[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static int all_zero(const void *value, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)value;
    size_t index;
    for (index = 0u; index < size; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static void make_record(uint8_t record[600], size_t size, uint8_t seed)
{
    size_t index;
    (void)memset(record, 0, 600u);
    (void)memcpy(record, "NAC1", 4u);
    put_u16(record + 4u, 1u);
    put_u16(record + 6u, 88u);
    put_u32(record + 8u, (uint32_t)size);
    put_u32(record + 12u, (uint32_t)(size - 88u));
    record[16] = 4u;
    record[18] = 3u;
    for (index = 0u; index < 16u; ++index) {
        record[20u + index] = (uint8_t)(seed + 1u + (uint8_t)index);
    }
    put_u64(record + 36u, (uint64_t)seed + 100u);
    put_u32(record + 44u, 1u);
    for (index = 0u; index < 32u; ++index) {
        record[52u + index] = (uint8_t)(seed + 33u + (uint8_t)index);
    }
    for (index = 88u; index < size; ++index) {
        record[index] = (uint8_t)(seed ^ (uint8_t)index);
    }
    put_u32(record + 84u, crc32c_zeroed(record, size, 84u, 4u));
}

static int make_packets(
    const uint8_t *record, size_t size, packet_set_t *packets)
{
    ninlil_model_domain_digest_t digest;
    uint32_t index;
    if (ninlil_model_domain_sha256(record, (uint32_t)size, &digest)
        != NINLIL_OK) {
        return 0;
    }
    (void)memset(packets, 0, sizeof(*packets));
    packets->count = (uint32_t)((size + PAYLOAD_MAX - 1u) / PAYLOAD_MAX);
    for (index = 0u; index < packets->count; ++index) {
        const size_t offset = (size_t)index * PAYLOAD_MAX;
        const size_t payload = size - offset < PAYLOAD_MAX
            ? size - offset : PAYLOAD_MAX;
        uint8_t *packet = packets->bytes[index];
        packets->sizes[index] = HEADER_BYTES + payload;
        (void)memcpy(packet, "NAR1", 4u);
        packet[4] = 0x12u;
        packet[5] = 1u;
        put_u16(packet + 6u, 68u);
        put_u16(packet + 8u, (uint16_t)packets->sizes[index]);
        put_u16(packet + 10u, (uint16_t)payload);
        (void)memcpy(packet + 12u, record + 20u, 16u);
        (void)memcpy(packet + 28u, record + 36u, 8u);
        (void)memcpy(packet + 36u, record + 44u, 4u);
        put_u16(packet + 40u, (uint16_t)size);
        packet[42] = (uint8_t)index;
        packet[43] = (uint8_t)packets->count;
        (void)memcpy(packet + 44u, digest.bytes, 16u);
        put_u32(packet + 60u, (uint32_t)offset);
        (void)memcpy(packet + HEADER_BYTES, record + offset, payload);
        put_u32(packet + 64u, crc32c_zeroed(packet,
            packets->sizes[index], 64u, 4u));
    }
    (void)memset(&digest, 0, sizeof(digest));
    return 1;
}

static void repair_packet_crc(uint8_t *packet, size_t size)
{
    put_u32(packet + 64u, crc32c_zeroed(packet, size, 64u, 4u));
}

static int owner_init(ninlil_pa_s3_nar1_owner_v1_t *owner,
    uint64_t context, const uint8_t source[32])
{
    ninlil_pa_s3_nar1_config_v1_t config;
    (void)memset(owner, 0, sizeof(*owner));
    (void)memset(&config, 0, sizeof(config));
    config.owner_context_id = context;
    (void)memcpy(config.source_locator_digest, source, 32u);
    return ninlil_pa_s3_nar1_owner_v1_init(owner, &config) == NINLIL_OK;
}

static int feed_expect_terminal(const packet_set_t *packets,
    const uint8_t source[32], uint64_t context)
{
    ninlil_pa_s3_nar1_owner_v1_t owner;
    uint8_t output[600];
    uint8_t expected[600];
    size_t output_size = 77u;
    ninlil_pa_s3_nar1_outcome_v1_t outcome = 77u;
    uint32_t index;

    REQUIRE(owner_init(&owner, context, source));
    (void)memset(output, 0xa5, sizeof(output));
    (void)memset(expected, 0xa5, sizeof(expected));
    for (index = 0u; index < packets->count; ++index) {
        REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, context, source,
            packets->bytes[index], packets->sizes[index], output,
            sizeof(output), &output_size, &outcome) == NINLIL_OK);
        if (outcome == NINLIL_PA_S3_NAR1_TERMINAL) {
            break;
        }
    }
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL);
    REQUIRE(output_size == 0u);
    REQUIRE(memcmp(output, expected, sizeof(output)) == 0);
    REQUIRE(owner.received_count == 0u
        && all_zero(owner.record, sizeof(owner.record))
        && all_zero(owner.session_id, sizeof(owner.session_id))
        && all_zero(owner.record_digest, sizeof(owner.record_digest)));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, context) == NINLIL_OK);
    return 1;
}

static int next_permutation(uint8_t *values, size_t count)
{
    size_t left;
    size_t right;
    uint8_t swap;
    if (count < 2u) {
        return 0;
    }
    left = count - 2u;
    while (values[left] >= values[left + 1u]) {
        if (left == 0u) {
            return 0;
        }
        --left;
    }
    right = count - 1u;
    while (values[right] <= values[left]) {
        --right;
    }
    swap = values[left];
    values[left] = values[right];
    values[right] = swap;
    for (right = count - 1u, ++left; left < right; ++left, --right) {
        swap = values[left];
        values[left] = values[right];
        values[right] = swap;
    }
    return 1;
}

static int deliver_order(const uint8_t *record, size_t record_size,
    const packet_set_t *packets, const uint8_t *order, const uint8_t source[32])
{
    ninlil_pa_s3_nar1_owner_v1_t owner;
    uint8_t output[600];
    size_t output_size = 99u;
    ninlil_pa_s3_nar1_outcome_v1_t outcome = 99u;
    uint32_t index;
    REQUIRE(owner_init(&owner, 41u, source));
    (void)memset(output, 0xa5, sizeof(output));
    for (index = 0u; index < packets->count; ++index) {
        const uint32_t packet_index = order[index];
        REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 41u, source,
            packets->bytes[packet_index], packets->sizes[packet_index],
            output, sizeof(output), &output_size, &outcome) == NINLIL_OK);
        if (index + 1u < packets->count) {
            REQUIRE(outcome == NINLIL_PA_S3_NAR1_PROGRESS);
            REQUIRE(output_size == 0u);
        }
    }
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_DELIVERED);
    REQUIRE(output_size == record_size);
    REQUIRE(memcmp(output, record, record_size) == 0);
    if (record_size < sizeof(output)) {
        uint8_t tail[600];
        (void)memset(tail, 0xa5, sizeof(tail));
        REQUIRE(memcmp(output + record_size, tail,
            sizeof(output) - record_size) == 0);
    }
    {
        uint8_t delivered[600];
        const size_t delivered_size = output_size;
        const ninlil_pa_s3_nar1_outcome_v1_t delivered_outcome = outcome;
        (void)memcpy(delivered, output, sizeof(delivered));
        REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 41u, source,
            packets->bytes[order[0]], packets->sizes[order[0]], output,
            sizeof(output), &output_size, &outcome)
            == NINLIL_E_INVALID_STATE);
        REQUIRE(output_size == delivered_size && outcome == delivered_outcome
            && memcmp(output, delivered, sizeof(output)) == 0);
    }
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 41u) == NINLIL_OK);
    {
        ninlil_pa_s3_nar1_owner_v1_t zero;
        (void)memset(&zero, 0, sizeof(zero));
        REQUIRE(memcmp(&owner, &zero, sizeof(owner)) == 0);
    }
    return 1;
}

static int test_boundaries_and_reorder(void)
{
    static const size_t lengths[] = {
        88u, 124u, 125u, 248u, 249u, 372u, 373u, 496u, 497u, 600u
    };
    uint8_t source[32];
    uint8_t record[600];
    packet_set_t packets;
    uint8_t order[5];
    size_t length_index;
    uint32_t index;
    make_source(source, 0x11u);
    for (length_index = 0u;
         length_index < sizeof(lengths) / sizeof(lengths[0]); ++length_index) {
        make_record(record, lengths[length_index],
            (uint8_t)(0x20u + length_index));
        REQUIRE(make_packets(record, lengths[length_index], &packets));
        for (index = 0u; index < packets.count; ++index) {
            order[index] = (uint8_t)index;
        }
        REQUIRE(deliver_order(record, lengths[length_index], &packets,
            order, source));
    }
    make_record(record, 600u, 0x52u);
    REQUIRE(make_packets(record, 600u, &packets));
    for (index = 0u; index < 5u; ++index) {
        order[index] = (uint8_t)index;
    }
    do {
        REQUIRE(deliver_order(record, 600u, &packets, order, source));
    } while (next_permutation(order, 5u));
    return 1;
}

static int test_duplicate_and_conflict(void)
{
    ninlil_pa_s3_nar1_owner_v1_t owner;
    ninlil_pa_s3_nar1_owner_v1_t owner_before;
    uint8_t source[32];
    uint8_t record[600];
    uint8_t output[600];
    uint8_t output_before[600];
    packet_set_t packets;
    size_t output_size;
    ninlil_pa_s3_nar1_outcome_v1_t outcome;
    make_source(source, 0x31u);
    make_record(record, 159u, 0x61u);
    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(owner_init(&owner, 7u, source));
    (void)memset(output, 0xa5, sizeof(output));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 7u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_PROGRESS
        && owner.received_count == 1u);
    (void)memcpy(&owner_before, &owner, sizeof(owner));
    (void)memcpy(output_before, output, sizeof(output));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 7u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_DUPLICATE
        && owner.received_count == 1u && output_size == 0u);
    REQUIRE(memcmp(&owner, &owner_before, sizeof(owner)) == 0);
    REQUIRE(memcmp(output, output_before, sizeof(output)) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 7u, source,
        packets.bytes[1], packets.sizes[1], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_DELIVERED
        && output_size == 159u && memcmp(output, record, 159u) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 7u) == NINLIL_OK);

    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(owner_init(&owner, 7u, source));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 7u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    packets.bytes[0][68] ^= 1u;
    repair_packet_crc(packets.bytes[0], packets.sizes[0]);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 7u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL && output_size == 0u);
    REQUIRE(owner.received_count == 0u
        && all_zero(owner.record, sizeof(owner.record)));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 7u) == NINLIL_OK);
    return 1;
}

static int terminal_after_second_mutation(size_t offset, size_t width)
{
    ninlil_pa_s3_nar1_owner_v1_t owner;
    uint8_t source[32];
    uint8_t record[600];
    uint8_t output[600];
    packet_set_t packets;
    size_t output_size = 4u;
    ninlil_pa_s3_nar1_outcome_v1_t outcome = 0u;
    make_source(source, 0x41u);
    make_record(record, 159u, 0x71u);
    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(owner_init(&owner, 8u, source));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 8u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_PROGRESS);
    packets.bytes[0][offset + width - 1u] ^= 1u;
    repair_packet_crc(packets.bytes[0], packets.sizes[0]);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 8u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL && output_size == 0u);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 8u) == NINLIL_OK);
    return 1;
}

static int test_mixed_source_malformed_and_inner(void)
{
    ninlil_pa_s3_nar1_owner_v1_t owner;
    uint8_t source[32];
    uint8_t other_source[32];
    uint8_t record[600];
    uint8_t output[600];
    packet_set_t packets;
    size_t output_size = 8u;
    ninlil_pa_s3_nar1_outcome_v1_t outcome = 0u;
    uint32_t index;

    REQUIRE(terminal_after_second_mutation(12u, 16u));
    REQUIRE(terminal_after_second_mutation(28u, 8u));
    REQUIRE(terminal_after_second_mutation(36u, 4u));
    REQUIRE(terminal_after_second_mutation(40u, 2u));
    REQUIRE(terminal_after_second_mutation(44u, 16u));

    make_source(source, 0x51u);
    make_source(other_source, 0x52u);
    make_record(record, 159u, 0x81u);
    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(owner_init(&owner, 9u, source));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 9u, other_source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL && output_size == 0u);
    REQUIRE(owner.received_count == 0u
        && all_zero(owner.record, sizeof(owner.record)));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 9u) == NINLIL_OK);

    REQUIRE(owner_init(&owner, 9u, source));
    packets.bytes[0][64] ^= 1u;
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 9u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL && output_size == 0u);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 9u) == NINLIL_OK);

    make_record(record, 159u, 0x82u);
    record[18] = 2u;
    put_u32(record + 84u, crc32c_zeroed(record, 159u, 84u, 4u));
    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(owner_init(&owner, 9u, source));
    for (index = 0u; index < packets.count; ++index) {
        REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 9u, source,
            packets.bytes[index], packets.sizes[index], output,
            sizeof(output), &output_size, &outcome) == NINLIL_OK);
    }
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL && output_size == 0u);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 9u) == NINLIL_OK);
    return 1;
}

static int test_arguments_alias_reentry_and_corruption(void)
{
    ninlil_pa_s3_nar1_owner_v1_t owner;
    ninlil_pa_s3_nar1_owner_v1_t before;
    uint8_t source[32];
    uint8_t record[600];
    uint8_t output[600];
    uint8_t output_before[600];
    packet_set_t packets;
    size_t output_size = 44u;
    ninlil_pa_s3_nar1_outcome_v1_t outcome = 55u;
    make_source(source, 0x61u);
    make_record(record, 159u, 0x91u);
    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(owner_init(&owner, 10u, source));
    (void)memset(output, 0xa5, sizeof(output));
    (void)memcpy(output_before, output, sizeof(output));
    (void)memcpy(&before, &owner, sizeof(owner));

    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 11u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_E_WRONG_THREAD);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    REQUIRE(output_size == 44u && outcome == 55u
        && memcmp(output, output_before, sizeof(output)) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], output, 599u,
        &output_size, &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        owner.record, 1u, output, sizeof(output),
        &output_size, &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], owner.record, sizeof(output),
        &output_size, &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        (size_t *)(void *)&owner.complete_bytes,
        &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);

    owner.in_call = 1u;
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_E_REENTRANT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    owner.in_call = 0u;

    owner.received_mask = UINT32_C(0x20);
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    owner.received_mask = 0u;
    owner.fragment_count = UINT32_MAX;
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    owner.fragment_count = 0u;

    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_PROGRESS);
    owner.received_mask = 3u;
    owner.received_count = 2u;
    output_size = 44u;
    outcome = 55u;
    (void)memcpy(&before, &owner, sizeof(owner));
    (void)memcpy(output_before, output, sizeof(output));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 10u, source,
        packets.bytes[0], packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    REQUIRE(output_size == 44u && outcome == 55u
        && memcmp(output, output_before, sizeof(output)) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 10u) == NINLIL_OK);
    return 1;
}

static int test_malformed_fragment_shapes(void)
{
    ninlil_pa_s3_nar1_owner_v1_t owner;
    uint8_t source[32];
    uint8_t record[600];
    uint8_t output[600];
    uint8_t packet[192];
    packet_set_t packets;
    size_t output_size;
    ninlil_pa_s3_nar1_outcome_v1_t outcome;
    uint8_t malformed = 0u;
    uint8_t output_before[600];
    uint32_t variant;
    make_source(source, 0x69u);
    make_record(record, 159u, 0x99u);
    REQUIRE(make_packets(record, 159u, &packets));
    for (variant = 0u; variant < 4u; ++variant) {
        (void)memcpy(packet, packets.bytes[1], packets.sizes[1]);
        if (variant == 0u) {
            packet[63] ^= 1u;
        } else if (variant == 1u) {
            packet[43] = 3u;
        } else if (variant == 2u) {
            put_u16(packet + 10u, 34u);
        } else {
            packet[5] = 2u;
        }
        repair_packet_crc(packet, packets.sizes[1]);
        REQUIRE(owner_init(&owner, 19u, source));
        output_size = 9u;
        outcome = 9u;
        REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 19u, source,
            packet, packets.sizes[1], output, sizeof(output),
            &output_size, &outcome) == NINLIL_OK);
        REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL
            && output_size == 0u && all_zero(owner.record,
                sizeof(owner.record)));
        REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 19u) == NINLIL_OK);
    }

    REQUIRE(owner_init(&owner, 19u, source));
    (void)memset(output, 0xa5, sizeof(output));
    (void)memcpy(output_before, output, sizeof(output));
    output_size = 9u;
    outcome = 9u;
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&owner, 19u, source,
        &malformed, 1u, output, sizeof(output), &output_size, &outcome)
        == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_TERMINAL
        && output_size == 0u && memcmp(output, output_before,
            sizeof(output)) == 0 && owner.received_count == 0u
        && all_zero(owner.record, sizeof(owner.record)));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 19u) == NINLIL_OK);
    return 1;
}

static int test_exact_payload_shape_guards(void)
{
    uint8_t source[32];
    uint8_t record[600];
    packet_set_t packets;

    make_source(source, 0x6au);
    make_record(record, 159u, 0x9au);
    REQUIRE(make_packets(record, 159u, &packets));
    packets.sizes[0] = HEADER_BYTES + 123u;
    put_u16(packets.bytes[0] + 8u, (uint16_t)packets.sizes[0]);
    put_u16(packets.bytes[0] + 10u, 123u);
    repair_packet_crc(packets.bytes[0], packets.sizes[0]);
    packets.count = 1u;
    REQUIRE(feed_expect_terminal(&packets, source, 31u));

    REQUIRE(make_packets(record, 159u, &packets));
    packets.sizes[1] = HEADER_BYTES + 34u;
    put_u16(packets.bytes[1] + 8u, (uint16_t)packets.sizes[1]);
    put_u16(packets.bytes[1] + 10u, 34u);
    repair_packet_crc(packets.bytes[1], packets.sizes[1]);
    (void)memcpy(packets.bytes[0], packets.bytes[1], packets.sizes[1]);
    packets.sizes[0] = packets.sizes[1];
    packets.count = 1u;
    REQUIRE(feed_expect_terminal(&packets, source, 32u));
    return 1;
}

static int test_completion_integrity_guards(void)
{
    static const struct {
        size_t offset;
        size_t width;
    } tuple_fields[] = {
        {12u, 16u},
        {28u, 8u},
        {36u, 4u}
    };
    uint8_t source[32];
    uint8_t record[600];
    uint8_t original_digest[16];
    packet_set_t packets;
    uint32_t index;
    size_t field;

    make_source(source, 0x6bu);

    make_record(record, 159u, 0x9bu);
    REQUIRE(make_packets(record, 159u, &packets));
    (void)memcpy(original_digest, packets.bytes[0] + 44u,
        sizeof(original_digest));
    record[100] ^= 1u;
    put_u32(record + 84u, crc32c_zeroed(record, 159u, 84u, 4u));
    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(memcmp(original_digest, packets.bytes[0] + 44u,
        sizeof(original_digest)) != 0);
    for (index = 0u; index < packets.count; ++index) {
        (void)memcpy(packets.bytes[index] + 44u, original_digest,
            sizeof(original_digest));
        repair_packet_crc(packets.bytes[index], packets.sizes[index]);
    }
    REQUIRE(feed_expect_terminal(&packets, source, 33u));

    make_record(record, 159u, 0x9cu);
    record[84] ^= 1u;
    REQUIRE(make_packets(record, 159u, &packets));
    REQUIRE(feed_expect_terminal(&packets, source, 34u));

    for (field = 0u;
         field < sizeof(tuple_fields) / sizeof(tuple_fields[0]); ++field) {
        make_record(record, 159u, (uint8_t)(0x9du + field));
        REQUIRE(make_packets(record, 159u, &packets));
        for (index = 0u; index < packets.count; ++index) {
            packets.bytes[index][tuple_fields[field].offset
                + tuple_fields[field].width - 1u] ^= 1u;
            repair_packet_crc(packets.bytes[index], packets.sizes[index]);
        }
        REQUIRE(feed_expect_terminal(&packets, source,
            (uint64_t)(35u + field)));
    }
    return 1;
}

static int test_inner_structural_guards(void)
{
    enum inner_mutation {
        INNER_MAGIC,
        INNER_VERSION,
        INNER_HEADER_BYTES,
        INNER_TOTAL_BYTES,
        INNER_PAYLOAD_BYTES,
        INNER_KIND,
        INNER_RESERVED_17,
        INNER_RESERVED_19,
        INNER_SESSION,
        INNER_GENERATION,
        INNER_SEQUENCE,
        INNER_RESERVED_48,
        INNER_BINDING,
        INNER_MUTATION_COUNT
    };
    uint8_t source[32];
    uint8_t record[600];
    packet_set_t packets;
    uint32_t mutation;

    make_source(source, 0x6cu);
    for (mutation = 0u; mutation < INNER_MUTATION_COUNT; ++mutation) {
        make_record(record, 159u, (uint8_t)(0xb0u + mutation));
        switch ((enum inner_mutation)mutation) {
        case INNER_MAGIC:
            record[0] = (uint8_t)'X';
            break;
        case INNER_VERSION:
            put_u16(record + 4u, 2u);
            break;
        case INNER_HEADER_BYTES:
            put_u16(record + 6u, 87u);
            break;
        case INNER_TOTAL_BYTES:
            put_u32(record + 8u, 158u);
            break;
        case INNER_PAYLOAD_BYTES:
            put_u32(record + 12u, 70u);
            break;
        case INNER_KIND:
            record[16] = 12u;
            put_u32(record + 44u, 9u);
            break;
        case INNER_RESERVED_17:
            record[17] = 1u;
            break;
        case INNER_RESERVED_19:
            record[19] = 1u;
            break;
        case INNER_SESSION:
            (void)memset(record + 20u, 0, 16u);
            break;
        case INNER_GENERATION:
            put_u64(record + 36u, 0u);
            break;
        case INNER_SEQUENCE:
            put_u32(record + 44u, 2u);
            break;
        case INNER_RESERVED_48:
            record[48] = 1u;
            break;
        case INNER_BINDING:
            (void)memset(record + 52u, 0, 32u);
            break;
        case INNER_MUTATION_COUNT:
        default:
            return 0;
        }
        put_u32(record + 84u, crc32c_zeroed(record, 159u, 84u, 4u));
        REQUIRE(make_packets(record, 159u, &packets));
        REQUIRE(feed_expect_terminal(&packets, source,
            (uint64_t)(50u + mutation)));
    }
    return 1;
}

static int test_nar_parser_guards(void)
{
    enum nar_mutation {
        NAR_MAGIC,
        NAR_PROFILE,
        NAR_HEADER_BYTES,
        NAR_TOTAL_BYTES,
        NAR_PAYLOAD_VS_PACKET,
        NAR_COMPLETE_MIN,
        NAR_COMPLETE_MAX,
        NAR_COUNT_ZERO,
        NAR_COUNT_HIGH,
        NAR_INDEX,
        NAR_EXPECTED_COUNT,
        NAR_MUTATION_COUNT
    };
    uint8_t source[32];
    uint8_t record[600];
    packet_set_t packets;
    uint32_t mutation;

    make_source(source, 0x6du);
    for (mutation = 0u; mutation < NAR_MUTATION_COUNT; ++mutation) {
        make_record(record, 159u, (uint8_t)(0xd0u + mutation));
        REQUIRE(make_packets(record, 159u, &packets));
        switch ((enum nar_mutation)mutation) {
        case NAR_MAGIC:
            packets.bytes[0][0] = (uint8_t)'X';
            break;
        case NAR_PROFILE:
            packets.bytes[0][4] = 0x13u;
            break;
        case NAR_HEADER_BYTES:
            put_u16(packets.bytes[0] + 6u, 67u);
            break;
        case NAR_TOTAL_BYTES:
            put_u16(packets.bytes[0] + 8u,
                (uint16_t)(packets.sizes[0] - 1u));
            break;
        case NAR_PAYLOAD_VS_PACKET:
            packets.sizes[0] -= 1u;
            put_u16(packets.bytes[0] + 8u,
                (uint16_t)packets.sizes[0]);
            break;
        case NAR_COMPLETE_MIN:
            packets.sizes[0] = HEADER_BYTES + 87u;
            put_u16(packets.bytes[0] + 8u,
                (uint16_t)packets.sizes[0]);
            put_u16(packets.bytes[0] + 10u, 87u);
            put_u16(packets.bytes[0] + 40u, 87u);
            packets.bytes[0][43] = 1u;
            break;
        case NAR_COMPLETE_MAX:
            put_u16(packets.bytes[0] + 40u, 601u);
            packets.bytes[0][43] = 5u;
            break;
        case NAR_COUNT_ZERO:
            packets.bytes[0][43] = 0u;
            break;
        case NAR_COUNT_HIGH:
            packets.bytes[0][43] = 6u;
            break;
        case NAR_INDEX:
            packets.sizes[0] = HEADER_BYTES;
            put_u16(packets.bytes[0] + 8u,
                (uint16_t)packets.sizes[0]);
            put_u16(packets.bytes[0] + 10u, 0u);
            put_u16(packets.bytes[0] + 40u, 248u);
            packets.bytes[0][42] = 2u;
            packets.bytes[0][43] = 2u;
            put_u32(packets.bytes[0] + 60u, 248u);
            break;
        case NAR_EXPECTED_COUNT:
            packets.bytes[0][43] = 3u;
            break;
        case NAR_MUTATION_COUNT:
        default:
            return 0;
        }
        repair_packet_crc(packets.bytes[0], packets.sizes[0]);
        packets.count = 1u;
        REQUIRE(feed_expect_terminal(&packets, source,
            (uint64_t)(80u + mutation)));
    }
    return 1;
}

static int test_lifecycle_guards(void)
{
    ninlil_pa_s3_nar1_owner_v1_t owner = {0};
    ninlil_pa_s3_nar1_owner_v1_t before;
    ninlil_pa_s3_nar1_config_v1_t config;
    uint8_t source[32];

    make_source(source, 0x6eu);
    (void)memset(&config, 0, sizeof(config));
    (void)memcpy(config.source_locator_digest, source, 32u);
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_init(&owner, &config)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);

    config.owner_context_id = 91u;
    (void)memset(config.source_locator_digest, 0, 32u);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_init(&owner, &config)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);

    (void)memcpy(config.source_locator_digest, source, 32u);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_init(&owner, &config) == NINLIL_OK);
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_init(&owner, &config)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 91u) == NINLIL_OK);

    (void)memset(&owner, 0, sizeof(owner));
    (void)memcpy(owner.record, &config, sizeof(config));
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_init(&owner,
        (const ninlil_pa_s3_nar1_config_v1_t *)(const void *)owner.record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);

    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(NULL, 91u)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)memset(&owner, 0, sizeof(owner));
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 91u)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);

    REQUIRE(owner_init(&owner, 91u, source));
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 92u)
        == NINLIL_E_WRONG_THREAD);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    owner.in_call = 1u;
    (void)memcpy(&before, &owner, sizeof(owner));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 91u)
        == NINLIL_E_REENTRANT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    owner.in_call = 0u;
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&owner, 91u) == NINLIL_OK);
    REQUIRE(all_zero(&owner, sizeof(owner)));
    return 1;
}

static int test_two_owner_isolation(void)
{
    ninlil_pa_s3_nar1_owner_v1_t left;
    ninlil_pa_s3_nar1_owner_v1_t right;
    uint8_t left_source[32];
    uint8_t right_source[32];
    uint8_t left_record[600];
    uint8_t right_record[600];
    uint8_t output[600];
    packet_set_t left_packets;
    packet_set_t right_packets;
    size_t output_size;
    ninlil_pa_s3_nar1_outcome_v1_t outcome;
    make_source(left_source, 0x71u);
    make_source(right_source, 0x91u);
    make_record(left_record, 159u, 0xa1u);
    make_record(right_record, 159u, 0xb1u);
    REQUIRE(make_packets(left_record, 159u, &left_packets));
    REQUIRE(make_packets(right_record, 159u, &right_packets));
    REQUIRE(owner_init(&left, 21u, left_source));
    REQUIRE(owner_init(&right, 22u, right_source));
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&left, 21u, left_source,
        left_packets.bytes[0], left_packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&right, 22u, right_source,
        right_packets.bytes[0], right_packets.sizes[0], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&left, 21u, left_source,
        left_packets.bytes[1], left_packets.sizes[1], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_DELIVERED
        && memcmp(output, left_record, 159u) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_feed(&right, 22u, right_source,
        right_packets.bytes[1], right_packets.sizes[1], output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAR1_DELIVERED
        && memcmp(output, right_record, 159u) == 0);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&left, 21u) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nar1_owner_v1_close(&right, 22u) == NINLIL_OK);
    return 1;
}

int main(void)
{
    if (!test_boundaries_and_reorder()
        || !test_duplicate_and_conflict()
        || !test_mixed_source_malformed_and_inner()
        || !test_arguments_alias_reentry_and_corruption()
        || !test_malformed_fragment_shapes()
        || !test_exact_payload_shape_guards()
        || !test_completion_integrity_guards()
        || !test_inner_structural_guards()
        || !test_nar_parser_guards()
        || !test_lifecycle_guards()
        || !test_two_owner_isolation()) {
        return 1;
    }
    (void)puts("private PA-S3b1 NAR1 reassembly tests: ok");
    return 0;
}
