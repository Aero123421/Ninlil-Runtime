/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s3_nas1_stream.h"
#include "production_attachment_edhoc_fixture.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 0; \
    } \
} while (0)

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

static void put_u32_be(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
}

static uint32_t crc32c_zeroed(const uint8_t *bytes, size_t size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    size_t index;
    for (index = 0u; index < size; ++index) {
        uint32_t bit;
        const uint8_t value = index >= 84u && index < 88u ? 0u : bytes[index];
        crc ^= (uint32_t)value;
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1u)
                ^ (UINT32_C(0x82f63b78) & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static void repair_inner_crc(uint8_t *wrapper)
{
    uint8_t *record = wrapper + 12u;
    const size_t size = get_u32_be(wrapper + 8u);
    put_u32_be(record + 84u, crc32c_zeroed(record, size));
}

static int all_value(const void *pointer, size_t size, uint8_t value)
{
    const uint8_t *bytes = (const uint8_t *)pointer;
    size_t index;
    for (index = 0u; index < size; ++index) {
        if (bytes[index] != value) {
            return 0;
        }
    }
    return 1;
}

static ninlil_pa_s3_nas1_config_v1_t config_for(
    const uint8_t *wrapper, uint64_t owner_context_id)
{
    const uint8_t *record = wrapper + 12u;
    ninlil_pa_s3_nas1_config_v1_t config;
    (void)memset(&config, 0, sizeof(config));
    config.owner_context_id = owner_context_id;
    (void)memcpy(config.session_id, record + 20u, sizeof(config.session_id));
    (void)memcpy(config.carrier_binding_digest, record + 52u,
        sizeof(config.carrier_binding_digest));
    config.exchange_generation = get_u64_be(record + 36u);
    config.carrier_class = record[18];
    config.kind = record[16];
    config.record_sequence = get_u32_be(record + 44u);
    return config;
}

static int expect_close(const uint8_t *bytes, size_t size, uint32_t eof,
    const ninlil_pa_s3_nas1_config_v1_t *config)
{
    ninlil_pa_s3_nas1_owner_v1_t owner = {0};
    uint8_t output[NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX];
    size_t output_size = 99u;
    ninlil_pa_s3_nas1_outcome_v1_t outcome = 99u;

    (void)memset(output, 0xa5, sizeof(output));
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&owner, config) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner,
        config->owner_context_id, bytes, size, eof, output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAS1_CLOSE && output_size == 0u);
    REQUIRE(all_value(output, sizeof(output), 0xa5));
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(
        &owner, config->owner_context_id) == NINLIL_OK);
    REQUIRE(all_value(&owner, sizeof(owner), 0u));
    return 1;
}

static int test_success_and_prefixes(void)
{
    const uint8_t *wrapper = ninlil_pa_nas_usb_m1;
    const size_t wrapper_size = sizeof(ninlil_pa_nas_usb_m1);
    ninlil_pa_s3_nas1_config_v1_t config = config_for(wrapper, 77u);
    ninlil_pa_s3_nas1_owner_v1_t owner = {0};
    uint8_t output[NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX];
    size_t output_size = 0u;
    ninlil_pa_s3_nas1_outcome_v1_t outcome = 0u;
    size_t prefix;

    (void)memset(output, 0xa5, sizeof(output));
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&owner, &config) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 77u, wrapper,
        wrapper_size, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAS1_DELIVERED);
    REQUIRE(output_size == wrapper_size - 12u);
    REQUIRE(memcmp(output, wrapper + 12u, output_size) == 0);
    REQUIRE(all_value(output + output_size, sizeof(output) - output_size,
        0xa5));
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 77u, wrapper, 1u, 0u,
        output, sizeof(output), &output_size, &outcome)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&owner, 77u) == NINLIL_OK);
    REQUIRE(all_value(&owner, sizeof(owner), 0u));

    for (prefix = 0u; prefix < wrapper_size; ++prefix) {
        ninlil_pa_s3_nas1_owner_v1_t partial_owner = {0};
        (void)memset(output, 0xa5, sizeof(output));
        output_size = 99u;
        outcome = 99u;
        REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(
            &partial_owner, &config) == NINLIL_OK);
        REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&partial_owner, 77u,
            wrapper, prefix, 0u, output, sizeof(output), &output_size,
            &outcome) == NINLIL_OK);
        REQUIRE(outcome == NINLIL_PA_S3_NAS1_NEED_MORE);
        REQUIRE(output_size == 0u && all_value(output, sizeof(output), 0xa5));
        REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(
            &partial_owner, 77u) == NINLIL_OK);
    }

    {
        static const size_t chunks[] = {1u, 6u, 5u, 79u};
        size_t offset = 0u;
        size_t index;
        (void)memset(&owner, 0, sizeof(owner));
        (void)memset(output, 0xa5, sizeof(output));
        REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&owner, &config) == NINLIL_OK);
        for (index = 0u; index < sizeof(chunks) / sizeof(chunks[0]); ++index) {
            REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 77u,
                wrapper + offset, chunks[index], 0u, output, sizeof(output),
                &output_size, &outcome) == NINLIL_OK);
            REQUIRE(outcome == NINLIL_PA_S3_NAS1_NEED_MORE
                && output_size == 0u
                && all_value(output, sizeof(output), 0xa5));
            offset += chunks[index];
        }
        REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 77u,
            wrapper + offset, wrapper_size - offset, 0u, output,
            sizeof(output), &output_size, &outcome) == NINLIL_OK);
        REQUIRE(outcome == NINLIL_PA_S3_NAS1_DELIVERED
            && output_size == wrapper_size - 12u);
        REQUIRE(all_value(output + output_size, sizeof(output) - output_size,
            0xa5));
        REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&owner, 77u) == NINLIL_OK);
    }
    return 1;
}

static int expect_delivery(
    const uint8_t *wrapper, size_t wrapper_size, uint64_t owner_context_id)
{
    ninlil_pa_s3_nas1_config_v1_t config =
        config_for(wrapper, owner_context_id);
    ninlil_pa_s3_nas1_owner_v1_t owner = {0};
    uint8_t output[NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX];
    size_t output_size = 0u;
    ninlil_pa_s3_nas1_outcome_v1_t outcome = 0u;

    (void)memset(output, 0xa5, sizeof(output));
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&owner, &config) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, owner_context_id,
        wrapper, wrapper_size, 1u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAS1_DELIVERED);
    REQUIRE(output_size == wrapper_size - 12u);
    REQUIRE(memcmp(output, wrapper + 12u, output_size) == 0);
    REQUIRE(all_value(output + output_size, sizeof(output) - output_size,
        0xa5));
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(
        &owner, owner_context_id) == NINLIL_OK);
    REQUIRE(all_value(&owner, sizeof(owner), 0u));
    return 1;
}

static int test_record_bounds(void)
{
    uint8_t wrapper[NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX];
    size_t index;

    (void)memset(wrapper, 0, sizeof(wrapper));
    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, 12u + 88u);
    put_u32_be(wrapper + 8u, 88u);
    put_u32_be(wrapper + 12u + 8u, 88u);
    put_u32_be(wrapper + 12u + 12u, 0u);
    repair_inner_crc(wrapper);
    REQUIRE(expect_delivery(wrapper, 12u + 88u, 78u));

    (void)memset(wrapper, 0, sizeof(wrapper));
    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, 12u + 88u);
    put_u32_be(wrapper + 8u, NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX);
    put_u32_be(wrapper + 12u + 8u, NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX);
    put_u32_be(wrapper + 12u + 12u,
        NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX - 88u);
    for (index = 12u + 88u; index < sizeof(wrapper); ++index) {
        wrapper[index] = (uint8_t)index;
    }
    repair_inner_crc(wrapper);
    REQUIRE(expect_delivery(wrapper, sizeof(wrapper), 79u));
    return 1;
}

static int test_kind_sequence_table(void)
{
    static const uint32_t valid[][2] = {
        {1u, 0u}, {2u, 0u}, {3u, 1u}, {3u, 8u}, {4u, 1u}, {5u, 2u},
        {6u, 3u}, {7u, 4u}, {8u, 5u}, {9u, 6u}, {10u, 7u}, {11u, 8u}
    };
    static const uint32_t invalid[][2] = {
        {1u, 1u}, {2u, 1u}, {3u, 0u}, {3u, 9u}, {4u, 0u}, {9u, 4u},
        {11u, 7u}, {12u, 9u}
    };
    uint8_t wrapper[sizeof(ninlil_pa_nas_usb_m1)];
    ninlil_pa_s3_nas1_config_v1_t original =
        config_for(ninlil_pa_nas_usb_m1, 80u);
    size_t index;

    for (index = 0u; index < sizeof(valid) / sizeof(valid[0]); ++index) {
        (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
        wrapper[12u + 16u] = (uint8_t)valid[index][0];
        put_u32_be(wrapper + 12u + 44u, valid[index][1]);
        repair_inner_crc(wrapper);
        REQUIRE(expect_delivery(wrapper, sizeof(wrapper), 100u + index));
    }
    for (index = 0u; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
        (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
        wrapper[12u + 16u] = (uint8_t)invalid[index][0];
        put_u32_be(wrapper + 12u + 44u, invalid[index][1]);
        repair_inner_crc(wrapper);
        REQUIRE(expect_close(wrapper, sizeof(wrapper), 0u, &original));
    }
    return 1;
}

static int test_expected_tuple_mismatches(void)
{
    uint8_t wrapper[sizeof(ninlil_pa_nas_usb_m1)];
    ninlil_pa_s3_nas1_config_v1_t expected =
        config_for(ninlil_pa_nas_usb_m1, 190u);

    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
    wrapper[5] = NINLIL_PA_S3_NAS1_WIFI_STREAM;
    REQUIRE(expect_close(wrapper, sizeof(wrapper), 0u, &expected));

    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
    wrapper[12u + 18u] = NINLIL_PA_S3_NAS1_WIFI_STREAM;
    repair_inner_crc(wrapper);
    REQUIRE(expect_close(wrapper, sizeof(wrapper), 0u, &expected));

    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
    wrapper[12u + 16u] = 3u;
    put_u32_be(wrapper + 12u + 44u, 1u);
    repair_inner_crc(wrapper);
    REQUIRE(expect_close(wrapper, sizeof(wrapper), 0u, &expected));

    expected.kind = 3u;
    expected.record_sequence = 8u;
    REQUIRE(expect_close(wrapper, sizeof(wrapper), 0u, &expected));
    return 1;
}

static int test_wire_failures(void)
{
    uint8_t mutated[sizeof(ninlil_pa_nas_usb_m1) + 1u];
    uint8_t overflow[NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX + 1u];
    ninlil_pa_s3_nas1_config_v1_t config =
        config_for(ninlil_pa_nas_usb_m1, 77u);
    static const size_t nac_mutations[] = {
        12u, 16u, 18u, 20u, 24u, 28u, 29u, 30u, 31u, 32u, 48u, 56u,
        60u, 64u
    };
    size_t index;

    REQUIRE(expect_close(ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1) - 1u, 1u, &config));

    (void)memcpy(mutated, ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1));
    mutated[sizeof(ninlil_pa_nas_usb_m1)] = 0u;
    REQUIRE(expect_close(mutated, sizeof(mutated), 0u, &config));

    (void)memset(overflow, 0, sizeof(overflow));
    REQUIRE(expect_close(overflow, sizeof(overflow), 0u, &config));

    for (index = 0u; index < sizeof(nac_mutations) / sizeof(nac_mutations[0]);
         ++index) {
        (void)memcpy(mutated, ninlil_pa_nas_usb_m1,
            sizeof(ninlil_pa_nas_usb_m1));
        mutated[nac_mutations[index]] ^= 1u;
        repair_inner_crc(mutated);
        REQUIRE(expect_close(mutated, sizeof(ninlil_pa_nas_usb_m1), 0u,
            &config));
    }

    (void)memcpy(mutated, ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1));
    mutated[0] ^= 1u;
    REQUIRE(expect_close(mutated, sizeof(ninlil_pa_nas_usb_m1), 0u, &config));
    (void)memcpy(mutated, ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1));
    mutated[4] = 2u;
    REQUIRE(expect_close(mutated, sizeof(ninlil_pa_nas_usb_m1), 0u, &config));
    (void)memcpy(mutated, ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1));
    mutated[7] = 11u;
    REQUIRE(expect_close(mutated, sizeof(ninlil_pa_nas_usb_m1), 0u, &config));
    (void)memcpy(mutated, ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1));
    mutated[11] = 87u;
    REQUIRE(expect_close(mutated, sizeof(ninlil_pa_nas_usb_m1), 0u, &config));

    (void)memcpy(mutated, ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1));
    mutated[12u + 84u] ^= 1u;
    REQUIRE(expect_close(mutated, sizeof(ninlil_pa_nas_usb_m1), 0u, &config));

    return 1;
}

static int test_wifi_and_error_sequence(void)
{
    uint8_t wrapper[sizeof(ninlil_pa_nas_usb_m1)];
    uint8_t output[NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX];
    ninlil_pa_s3_nas1_config_v1_t config;
    ninlil_pa_s3_nas1_owner_v1_t owner = {0};
    size_t output_size = 0u;
    ninlil_pa_s3_nas1_outcome_v1_t outcome = 0u;

    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
    wrapper[5] = 2u;
    wrapper[12u + 18u] = 2u;
    repair_inner_crc(wrapper);
    config = config_for(wrapper, 88u);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&owner, &config) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 88u, wrapper,
        sizeof(wrapper), 1u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAS1_DELIVERED
        && output_size == sizeof(wrapper) - 12u);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&owner, 88u) == NINLIL_OK);

    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
    wrapper[12u + 16u] = 3u;
    put_u32_be(wrapper + 12u + 44u, 8u);
    repair_inner_crc(wrapper);
    config = config_for(wrapper, 89u);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&owner, &config) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 89u, wrapper,
        sizeof(wrapper), 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_OK);
    REQUIRE(outcome == NINLIL_PA_S3_NAS1_DELIVERED);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&owner, 89u) == NINLIL_OK);

    (void)memcpy(wrapper, ninlil_pa_nas_usb_m1, sizeof(wrapper));
    wrapper[12u + 16u] = 3u;
    put_u32_be(wrapper + 12u + 44u, 9u);
    repair_inner_crc(wrapper);
    config.kind = 3u;
    config.record_sequence = 8u;
    REQUIRE(expect_close(wrapper, sizeof(wrapper), 0u, &config));
    return 1;
}

static int test_owner_boundaries(void)
{
    ninlil_pa_s3_nas1_config_v1_t config =
        config_for(ninlil_pa_nas_usb_m1, 101u);
    ninlil_pa_s3_nas1_owner_v1_t owner = {0};
    ninlil_pa_s3_nas1_owner_v1_t before;
    ninlil_pa_s3_nas1_owner_v1_t other = {0};
    ninlil_pa_s3_nas1_owner_v1_t corrupt = {0};
    uint8_t output[NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX];
    uint8_t before_output[NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX];
    size_t output_size = 55u;
    ninlil_pa_s3_nas1_outcome_v1_t outcome = 55u;
    size_t before_output_size;
    ninlil_pa_s3_nas1_outcome_v1_t before_outcome;
    union {
        size_t size;
        ninlil_pa_s3_nas1_outcome_v1_t outcome;
    } scalar_alias;
    const size_t half = sizeof(ninlil_pa_nas_usb_m1) / 2u;

    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&owner, &config) == NINLIL_OK);
    before = owner;
    (void)memset(output, 0xa5, sizeof(output));
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 102u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_E_WRONG_THREAD);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && output_size == 55u && outcome == 55u
        && all_value(output, sizeof(output), 0xa5));

    before = owner;
    (void)memcpy(before_output, output, sizeof(output));
    before_output_size = output_size;
    before_outcome = outcome;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output) - 1u,
        &output_size, &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);

    owner.buffered_bytes = NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX + 1u;
    before = owner;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    owner.buffered_bytes = 0u;

    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&corrupt, &config) == NINLIL_OK);
    corrupt.wrapper_bytes = NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX + 1u;
    before = corrupt;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&corrupt, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_E_INVALID_STATE);
    REQUIRE(memcmp(&corrupt, &before, sizeof(corrupt)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&corrupt, 101u) == NINLIL_OK);
    REQUIRE(all_value(&corrupt, sizeof(corrupt), 0u));

    owner.in_call = 1u;
    before = owner;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_E_REENTRANT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&owner, 101u)
        == NINLIL_E_REENTRANT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);
    owner.in_call = 0u;
    before = owner;
    (void)memcpy(before_output, output, sizeof(output));
    before_output_size = output_size;
    before_outcome = outcome;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        owner.buffer, 1u, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, owner.buffer, sizeof(owner.buffer),
        &output_size, &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output),
        (size_t *)(void *)&owner.owner_context_id, &outcome)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output),
        &output_size, &owner.state) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output),
        (size_t *)(void *)output, &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output),
        &output_size, (ninlil_pa_s3_nas1_outcome_v1_t *)(void *)output)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    scalar_alias.size = 55u;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, 1u, 0u, output, sizeof(output),
        &scalar_alias.size,
        (ninlil_pa_s3_nas1_outcome_v1_t *)(void *)&scalar_alias.size)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && scalar_alias.size == 55u);
    (void)memcpy(output, ninlil_pa_nas_usb_m1,
        sizeof(ninlil_pa_nas_usb_m1));
    before = owner;
    (void)memcpy(before_output, output, sizeof(output));
    before_output_size = output_size;
    before_outcome = outcome;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u, output,
        sizeof(ninlil_pa_nas_usb_m1), 0u, output, sizeof(output),
        &output_size, &outcome) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0
        && memcmp(output, before_output, sizeof(output)) == 0
        && output_size == before_output_size && outcome == before_outcome);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&owner, 102u)
        == NINLIL_E_WRONG_THREAD);
    REQUIRE(memcmp(&owner, &before, sizeof(owner)) == 0);

    config.owner_context_id = 202u;
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_init(&other, &config) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1, half, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_OK && outcome == NINLIL_PA_S3_NAS1_NEED_MORE);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&other, 202u,
        ninlil_pa_nas_usb_m1, half, 0u, output, sizeof(output), &output_size,
        &outcome) == NINLIL_OK && outcome == NINLIL_PA_S3_NAS1_NEED_MORE);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&owner, 101u,
        ninlil_pa_nas_usb_m1 + half,
        sizeof(ninlil_pa_nas_usb_m1) - half, 0u, output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK
        && outcome == NINLIL_PA_S3_NAS1_DELIVERED);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_feed(&other, 202u,
        ninlil_pa_nas_usb_m1 + half,
        sizeof(ninlil_pa_nas_usb_m1) - half, 0u, output, sizeof(output),
        &output_size, &outcome) == NINLIL_OK
        && outcome == NINLIL_PA_S3_NAS1_DELIVERED);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&owner, 101u) == NINLIL_OK);
    REQUIRE(ninlil_pa_s3_nas1_owner_v1_close(&other, 202u) == NINLIL_OK);
    REQUIRE(all_value(&owner, sizeof(owner), 0u)
        && all_value(&other, sizeof(other), 0u));
    return 1;
}

int main(void)
{
    if (!test_success_and_prefixes() || !test_record_bounds()
        || !test_kind_sequence_table() || !test_expected_tuple_mismatches()
        || !test_wire_failures()
        || !test_wifi_and_error_sequence() || !test_owner_boundaries()) {
        return 1;
    }
    (void)puts("PA-S3a NAS1 stream tests: OK");
    return 0;
}
