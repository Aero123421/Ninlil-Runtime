#include "abi_contract.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CANARY_BYTE ((uint8_t)0xa5u)
#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))

typedef struct header_fixture {
    NINLIL_STRUCT_HEADER;
    uint32_t required_value;
    uint64_t known_tail;
} header_fixture_t;

typedef struct output_fixture {
    NINLIL_STRUCT_HEADER;
    uint32_t scalar;
    uint8_t *buffer;
    uint32_t capacity;
    uint32_t length;
    uint64_t known_tail;
} output_fixture_t;

typedef struct output_envelope {
    uint8_t before[16];
    output_fixture_t output;
    uint8_t after[32];
} output_envelope_t;

_Static_assert(
    offsetof(output_fixture_t, capacity)
        == offsetof(output_fixture_t, buffer) + sizeof(((output_fixture_t *)0)->buffer),
    "output fixture preserve ranges must be adjacent");

typedef struct header_case {
    const char *name;
    uint16_t abi_version;
    uint16_t struct_size;
    size_t required_size;
    size_t known_size;
    ninlil_status_t expected;
} header_case_t;

typedef struct output_case {
    const char *name;
    uint16_t abi_version;
    uint16_t struct_size;
    ninlil_status_t expected;
    size_t expected_write_size;
} output_case_t;

typedef struct layout_case {
    const char *name;
    size_t required_size;
    size_t known_size;
    ninlil_status_t expected;
} layout_case_t;

typedef struct preserve_case {
    const char *name;
    const ninlil_contract_preserve_range_t *ranges;
    size_t range_count;
} preserve_case_t;

typedef struct enum_case {
    const char *name;
    uint32_t value;
    ninlil_status_t expected;
} enum_case_t;

typedef struct enum_table_case {
    const char *name;
    uint32_t value;
    const uint32_t *supported;
    size_t supported_count;
    const uint32_t *reserved;
    size_t reserved_count;
    ninlil_status_t expected;
} enum_table_case_t;

static int byte_is_preserved(
    size_t offset,
    const ninlil_contract_preserve_range_t *ranges,
    size_t range_count)
{
    size_t index;
    if (offset < sizeof(uint16_t) * 2u) {
        return 1;
    }
    for (index = 0u; index < range_count; ++index) {
        if (offset >= ranges[index].offset && offset - ranges[index].offset < ranges[index].length) {
            return 1;
        }
    }
    return 0;
}

static int test_header_contract(void)
{
    const size_t required_size = offsetof(header_fixture_t, required_value)
        + sizeof(((header_fixture_t *)0)->required_value);
    const size_t known_size = sizeof(header_fixture_t);
    const header_case_t cases[] = {
        {"small", NINLIL_ABI_VERSION, (uint16_t)(required_size - 1u), required_size, known_size,
            NINLIL_E_ABI_MISMATCH},
        {"required exact", NINLIL_ABI_VERSION, (uint16_t)required_size, required_size, known_size,
            NINLIL_OK},
        {"known exact", NINLIL_ABI_VERSION, (uint16_t)known_size, required_size, known_size,
            NINLIL_OK},
        {"future larger", NINLIL_ABI_VERSION, (uint16_t)(known_size + 16u), required_size,
            known_size, NINLIL_OK},
        {"wrong ABI", (uint16_t)(NINLIL_ABI_VERSION + 1u), (uint16_t)known_size, required_size,
            known_size, NINLIL_E_ABI_MISMATCH}};
    const layout_case_t invalid_layout_cases[] = {
        {"required below header", 3u, known_size, NINLIL_E_INVALID_ARGUMENT},
        {"known below required", known_size, required_size, NINLIL_E_INVALID_ARGUMENT},
        {"known exceeds struct_size domain", required_size, (size_t)UINT16_MAX + 1u,
            NINLIL_E_INVALID_ARGUMENT}};
    size_t index;
    int failures = 0;

    for (index = 0u; index < ARRAY_COUNT(cases); ++index) {
        header_fixture_t fixture;
        ninlil_status_t actual;
        memset(&fixture, CANARY_BYTE, sizeof(fixture));
        fixture.abi_version = cases[index].abi_version;
        fixture.struct_size = cases[index].struct_size;
        actual = ninlil_contract_validate_struct(
            &fixture, cases[index].required_size, cases[index].known_size);
        if (actual != cases[index].expected) {
            fprintf(stderr, "header %s: expected %d, got %d\n", cases[index].name,
                (int)cases[index].expected, (int)actual);
            ++failures;
        }
    }
    if (ninlil_contract_validate_struct(NULL, required_size, known_size)
        != NINLIL_E_INVALID_ARGUMENT) {
        fputs("header null: expected INVALID_ARGUMENT\n", stderr);
        ++failures;
    }
    for (index = 0u; index < ARRAY_COUNT(invalid_layout_cases); ++index) {
        header_fixture_t fixture;
        ninlil_status_t actual;
        memset(&fixture, CANARY_BYTE, sizeof(fixture));
        fixture.abi_version = NINLIL_ABI_VERSION;
        fixture.struct_size = (uint16_t)known_size;
        actual = ninlil_contract_validate_struct(&fixture,
            invalid_layout_cases[index].required_size, invalid_layout_cases[index].known_size);
        if (actual != invalid_layout_cases[index].expected) {
            fprintf(stderr, "header layout %s: expected %d, got %d\n",
                invalid_layout_cases[index].name, (int)invalid_layout_cases[index].expected,
                (int)actual);
            ++failures;
        }
    }
    if (ninlil_contract_require_nonnull(NULL) != NINLIL_E_INVALID_ARGUMENT
        || ninlil_contract_require_nonnull(&cases) != NINLIL_OK) {
        fputs("nonnull contract classification failed\n", stderr);
        ++failures;
    }
    return failures == 0 ? 0 : -1;
}

static int verify_output_bytes(
    const output_envelope_t *before,
    const output_envelope_t *after,
    ninlil_status_t status,
    size_t write_size,
    const ninlil_contract_preserve_range_t *ranges,
    size_t range_count,
    const char *name)
{
    const uint8_t *before_bytes = (const uint8_t *)before;
    const uint8_t *after_bytes = (const uint8_t *)after;
    size_t output_start = offsetof(output_envelope_t, output);
    size_t output_end = output_start + sizeof(output_fixture_t);
    size_t index;

    for (index = 0u; index < sizeof(*after); ++index) {
        uint8_t expected = before_bytes[index];
        if (status == NINLIL_OK && index >= output_start && index < output_end) {
            size_t output_offset = index - output_start;
            if (output_offset < write_size
                && !byte_is_preserved(output_offset, ranges, range_count)) {
                expected = 0u;
            }
        }
        if (after_bytes[index] != expected) {
            fprintf(stderr, "output %s: unexpected byte at envelope offset %zu\n", name, index);
            return -1;
        }
    }
    return 0;
}

static int test_output_contract(void)
{
    const size_t required_size = offsetof(output_fixture_t, length)
        + sizeof(((output_fixture_t *)0)->length);
    const size_t known_size = sizeof(output_fixture_t);
    const ninlil_contract_preserve_range_t ranges[] = {
        {offsetof(output_fixture_t, buffer), sizeof(((output_fixture_t *)0)->buffer)},
        {offsetof(output_fixture_t, capacity), sizeof(((output_fixture_t *)0)->capacity)}};
    const ninlil_contract_preserve_range_t zero_length_range[] = {
        {offsetof(output_fixture_t, buffer), 0u}};
    const ninlil_contract_preserve_range_t header_overlap_range[] = {
        {sizeof(uint16_t), sizeof(uint16_t)}};
    const ninlil_contract_preserve_range_t required_boundary_range[] = {
        {required_size - 1u, 2u}};
    const ninlil_contract_preserve_range_t size_overflow_range[] = {{SIZE_MAX, 2u}};
    const ninlil_contract_preserve_range_t overlapping_ranges[] = {
        {offsetof(output_fixture_t, buffer), sizeof(((output_fixture_t *)0)->buffer)},
        {offsetof(output_fixture_t, buffer) + 1u, 2u}};
    const preserve_case_t invalid_preserve_cases[] = {
        {"count with null ranges", NULL, 1u},
        {"zero length", zero_length_range, ARRAY_COUNT(zero_length_range)},
        {"ABI header overlap", header_overlap_range, ARRAY_COUNT(header_overlap_range)},
        {"required boundary", required_boundary_range, ARRAY_COUNT(required_boundary_range)},
        {"SIZE_MAX offset", size_overflow_range, ARRAY_COUNT(size_overflow_range)},
        {"overlapping ranges", overlapping_ranges, ARRAY_COUNT(overlapping_ranges)}};
    const output_case_t cases[] = {
        {"required bounded", NINLIL_ABI_VERSION, (uint16_t)required_size, NINLIL_OK,
            required_size},
        {"known exact with adjacent preserves", NINLIL_ABI_VERSION, (uint16_t)known_size,
            NINLIL_OK, known_size},
        {"future larger", NINLIL_ABI_VERSION, (uint16_t)(known_size + 16u), NINLIL_OK,
            known_size},
        {"small", NINLIL_ABI_VERSION, (uint16_t)(required_size - 1u),
            NINLIL_E_ABI_MISMATCH, 0u},
        {"wrong ABI", (uint16_t)(NINLIL_ABI_VERSION + 1u), (uint16_t)known_size,
            NINLIL_E_ABI_MISMATCH, 0u}};
    uint8_t caller_buffer[8] = {0};
    size_t index;
    int failures = 0;

    for (index = 0u; index < ARRAY_COUNT(cases); ++index) {
        output_envelope_t envelope;
        output_envelope_t before;
        ninlil_status_t actual;
        memset(&envelope, CANARY_BYTE, sizeof(envelope));
        envelope.output.abi_version = cases[index].abi_version;
        envelope.output.struct_size = cases[index].struct_size;
        envelope.output.buffer = caller_buffer;
        envelope.output.capacity = (uint32_t)sizeof(caller_buffer);
        before = envelope;
        actual = ninlil_contract_prepare_output(
            &envelope.output, required_size, known_size, ranges, ARRAY_COUNT(ranges));
        if (actual != cases[index].expected) {
            fprintf(stderr, "output %s: expected %d, got %d\n", cases[index].name,
                (int)cases[index].expected, (int)actual);
            ++failures;
            continue;
        }
        failures += verify_output_bytes(&before, &envelope, actual, cases[index].expected_write_size,
                        ranges, ARRAY_COUNT(ranges), cases[index].name)
            != 0;
    }
    if (ninlil_contract_prepare_output(
            NULL, required_size, known_size, ranges, ARRAY_COUNT(ranges))
        != NINLIL_E_INVALID_ARGUMENT) {
        fputs("output null: expected INVALID_ARGUMENT\n", stderr);
        ++failures;
    }
    for (index = 0u; index < ARRAY_COUNT(invalid_preserve_cases); ++index) {
        output_envelope_t envelope;
        output_envelope_t before;
        ninlil_status_t actual;
        memset(&envelope, CANARY_BYTE, sizeof(envelope));
        envelope.output.abi_version = NINLIL_ABI_VERSION;
        envelope.output.struct_size = (uint16_t)known_size;
        envelope.output.buffer = caller_buffer;
        envelope.output.capacity = (uint32_t)sizeof(caller_buffer);
        before = envelope;
        actual = ninlil_contract_prepare_output(&envelope.output, required_size, known_size,
            invalid_preserve_cases[index].ranges, invalid_preserve_cases[index].range_count);
        if (actual != NINLIL_E_INVALID_ARGUMENT) {
            fprintf(stderr, "output preserve %s: expected INVALID_ARGUMENT, got %d\n",
                invalid_preserve_cases[index].name, (int)actual);
            ++failures;
        }
        if (memcmp(&before, &envelope, sizeof(envelope)) != 0) {
            fprintf(stderr, "output preserve %s: envelope changed on error\n",
                invalid_preserve_cases[index].name);
            ++failures;
        }
    }
    return failures == 0 ? 0 : -1;
}

static int test_enum_contract(void)
{
    static const uint32_t supported[] = {NINLIL_ROLE_CONTROLLER, NINLIL_ROLE_ENDPOINT};
    static const uint32_t reserved[] = {NINLIL_ROLE_CELL_AGENT_RESERVED};
    static const uint32_t duplicate_supported[] = {
        NINLIL_ROLE_CONTROLLER, NINLIL_ROLE_CONTROLLER};
    static const uint32_t duplicate_reserved[] = {
        NINLIL_ROLE_CELL_AGENT_RESERVED, NINLIL_ROLE_CELL_AGENT_RESERVED};
    static const uint32_t overlap_reserved[] = {NINLIL_ROLE_CONTROLLER};
    const enum_case_t cases[] = {
        {"controller", NINLIL_ROLE_CONTROLLER, NINLIL_OK},
        {"endpoint", NINLIL_ROLE_ENDPOINT, NINLIL_OK},
        {"named reserved", NINLIL_ROLE_CELL_AGENT_RESERVED, NINLIL_E_UNSUPPORTED},
        {"unknown numeric", UINT32_MAX, NINLIL_E_INVALID_ARGUMENT}};
    const enum_table_case_t invalid_table_cases[] = {
        {"supported count with null", NINLIL_ROLE_CONTROLLER, NULL, 1u, reserved,
            ARRAY_COUNT(reserved), NINLIL_E_INVALID_ARGUMENT},
        {"reserved count with null", NINLIL_ROLE_CONTROLLER, supported,
            ARRAY_COUNT(supported), NULL, 1u, NINLIL_E_INVALID_ARGUMENT},
        {"duplicate supported", NINLIL_ROLE_CONTROLLER, duplicate_supported,
            ARRAY_COUNT(duplicate_supported), reserved, ARRAY_COUNT(reserved),
            NINLIL_E_INVALID_ARGUMENT},
        {"duplicate reserved", NINLIL_ROLE_CELL_AGENT_RESERVED, supported,
            ARRAY_COUNT(supported), duplicate_reserved, ARRAY_COUNT(duplicate_reserved),
            NINLIL_E_INVALID_ARGUMENT},
        {"supported reserved overlap", NINLIL_ROLE_CONTROLLER, supported, 1u,
            overlap_reserved, ARRAY_COUNT(overlap_reserved), NINLIL_E_INVALID_ARGUMENT},
        {"empty valid tables unknown numeric", UINT32_MAX, NULL, 0u, NULL, 0u,
            NINLIL_E_INVALID_ARGUMENT}};
    size_t index;
    int failures = 0;

    for (index = 0u; index < ARRAY_COUNT(cases); ++index) {
        ninlil_status_t actual = ninlil_contract_classify_u32(cases[index].value, supported,
            ARRAY_COUNT(supported), reserved, ARRAY_COUNT(reserved));
        if (actual != cases[index].expected) {
            fprintf(stderr, "enum %s: expected %d, got %d\n", cases[index].name,
                (int)cases[index].expected, (int)actual);
            ++failures;
        }
    }
    for (index = 0u; index < ARRAY_COUNT(invalid_table_cases); ++index) {
        ninlil_status_t actual = ninlil_contract_classify_u32(invalid_table_cases[index].value,
            invalid_table_cases[index].supported, invalid_table_cases[index].supported_count,
            invalid_table_cases[index].reserved, invalid_table_cases[index].reserved_count);
        if (actual != invalid_table_cases[index].expected) {
            fprintf(stderr, "enum table %s: expected %d, got %d\n",
                invalid_table_cases[index].name, (int)invalid_table_cases[index].expected,
                (int)actual);
            ++failures;
        }
    }
    return failures == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    int result;
    if (argc != 2) {
        fprintf(stderr, "usage: %s <header|output|enum>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "header") == 0) {
        result = test_header_contract();
    } else if (strcmp(argv[1], "output") == 0) {
        result = test_output_contract();
    } else if (strcmp(argv[1], "enum") == 0) {
        result = test_enum_contract();
    } else {
        fprintf(stderr, "unknown contract test mode: %s\n", argv[1]);
        return 2;
    }
    if (result != 0) {
        return 1;
    }
    printf("ABI contract %s tests ok\n", argv[1]);
    return 0;
}
