#include "deterministic_entropy.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",       \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int hex_nibble(char value, uint8_t *out)
{
    if (value >= '0' && value <= '9') {
        *out = (uint8_t)(value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *out = (uint8_t)(value - 'a' + 10);
        return 1;
    }
    return 0;
}

static int parse_hex(const char *hex, uint8_t *out, size_t length)
{
    size_t index;
    for (index = 0u; index < length; ++index) {
        uint8_t high;
        uint8_t low;
        if (!hex_nibble(hex[index * 2u], &high)
            || !hex_nibble(hex[index * 2u + 1u], &low)) {
            return 0;
        }
        out[index] = (uint8_t)((high << 4u) | low);
    }
    return hex[length * 2u] == '\0';
}

static int test_golden_streams_and_multiblock(void)
{
    static const char *golden[3] = {
        "7ad714f1260c1fd750efd7209bc0cd6d08b69ebfc2e40f173273b731dbf6929e",
        "968198a87ecbad2092b55f929da076a3d59d6963afba9d8212a061bb7684c08f",
        "4faf7975a1ca8185196dcb80ccd0bfa1560ca72056449276ae8a723f8f7f4033"
    };
    static const char *stream1_block1 =
        "0d5382f07b9c59639f7c1957ae22fea7742b0b44e855d011ffd887ffe7e89cd3";
    uint32_t stream;

    for (stream = 0u; stream < 3u; ++stream) {
        ninlil_test_entropy_t *entropy = ninlil_test_entropy_create(
            UINT64_C(0x0123456789abcdef), stream);
        const ninlil_entropy_ops_t *ops;
        uint8_t actual[32];
        uint8_t expected[32];
        REQUIRE(entropy != NULL && parse_hex(golden[stream], expected, 32u));
        ops = ninlil_test_entropy_ops(entropy);
        REQUIRE(ops != NULL && ops->abi_version == NINLIL_ABI_VERSION
            && ops->struct_size == sizeof(*ops));
        REQUIRE(ops->fill(ops->user, actual, sizeof(actual)) == NINLIL_PORT_OK);
        REQUIRE(memcmp(actual, expected, sizeof(actual)) == 0);
        REQUIRE(ninlil_test_entropy_counter(entropy) == 1u);
        ninlil_test_entropy_destroy(entropy);
    }
    {
        ninlil_test_entropy_t *entropy = ninlil_test_entropy_create(
            UINT64_C(0x0123456789abcdef), 1u);
        const ninlil_entropy_ops_t *ops = ninlil_test_entropy_ops(entropy);
        uint8_t actual[40];
        uint8_t expected[40];
        REQUIRE(entropy != NULL && parse_hex(golden[1], expected, 32u));
        {
            uint8_t second[32];
            REQUIRE(parse_hex(stream1_block1, second, sizeof(second)));
            (void)memcpy(&expected[32], second, 8u);
        }
        REQUIRE(ops->fill(ops->user, actual, sizeof(actual)) == NINLIL_PORT_OK);
        REQUIRE(memcmp(actual, expected, sizeof(actual)) == 0);
        REQUIRE(ninlil_test_entropy_counter(entropy) == 2u);
        ninlil_test_entropy_scenario_reset(entropy,
            UINT64_C(0x0123456789abcdef), 1u);
        REQUIRE(ops->fill(ops->user, actual, 1u) == NINLIL_PORT_OK
            && actual[0] == 0x96u);
        REQUIRE(ops->fill(ops->user, actual, 1u) == NINLIL_PORT_OK
            && actual[0] == 0x0du);
        REQUIRE(ninlil_test_entropy_counter(entropy) == 2u);
        ninlil_test_entropy_destroy(entropy);
    }
    return 0;
}

static int test_zero_failure_partial_and_all_zero(void)
{
    static const char *block0 =
        "968198a87ecbad2092b55f929da076a3d59d6963afba9d8212a061bb7684c08f";
    static const char *block1 =
        "0d5382f07b9c59639f7c1957ae22fea7742b0b44e855d011ffd887ffe7e89cd3";
    ninlil_test_entropy_t *entropy = ninlil_test_entropy_create(
        UINT64_C(0x0123456789abcdef), 1u);
    const ninlil_entropy_ops_t *ops = ninlil_test_entropy_ops(entropy);
    uint8_t actual[32];
    uint8_t expected0[32];
    uint8_t expected1[32];

    REQUIRE(entropy != NULL && parse_hex(block0, expected0, sizeof(expected0))
        && parse_hex(block1, expected1, sizeof(expected1)));
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_TEMPORARY, 0u, 2u));
    (void)memset(actual, 0xaa, sizeof(actual));
    REQUIRE(ops->fill(ops->user, actual, 0u) == NINLIL_PORT_OK);
    REQUIRE(ops->fill(ops->user, NULL, 0u) == NINLIL_PORT_OK);
    REQUIRE(ninlil_test_entropy_counter(entropy) == 0u && actual[0] == 0xaau);
    REQUIRE(ops->fill(ops->user, actual, 16u)
        == NINLIL_PORT_TEMPORARY_FAILURE);
    REQUIRE(ops->fill(ops->user, actual, 16u)
        == NINLIL_PORT_TEMPORARY_FAILURE);
    REQUIRE(ninlil_test_entropy_counter(entropy) == 0u && actual[0] == 0xaau);
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_PERMANENT, 0u, 1u));
    REQUIRE(ops->fill(ops->user, actual, 16u)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_test_entropy_counter(entropy) == 0u && actual[0] == 0xaau);
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_PARTIAL, 8u, 1u));
    REQUIRE(ops->fill(ops->user, actual, 16u)
        == NINLIL_PORT_TEMPORARY_FAILURE);
    REQUIRE(memcmp(actual, expected0, 8u) == 0 && actual[8] == 0xaau
        && ninlil_test_entropy_counter(entropy) == 0u);
    REQUIRE(ops->fill(ops->user, actual, 16u) == NINLIL_PORT_OK);
    REQUIRE(memcmp(actual, expected0, 16u) == 0
        && ninlil_test_entropy_counter(entropy) == 1u);
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO, 0u, 1u));
    (void)memset(actual, 0xaa, sizeof(actual));
    REQUIRE(ops->fill(ops->user, actual, 16u) == NINLIL_PORT_OK);
    {
        uint8_t zero[16] = {0u};
        REQUIRE(memcmp(actual, zero, sizeof(zero)) == 0);
    }
    REQUIRE(ninlil_test_entropy_counter(entropy) == 2u);
    ninlil_test_entropy_scenario_reset(entropy,
        UINT64_C(0x0123456789abcdef), 1u);
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO, 0u, 1u));
    REQUIRE(ops->fill(ops->user, actual, 16u) == NINLIL_PORT_OK);
    REQUIRE(ops->fill(ops->user, actual, 16u) == NINLIL_PORT_OK);
    REQUIRE(memcmp(actual, expected1, 16u) == 0);
    ninlil_test_entropy_destroy(entropy);
    return 0;
}

static int test_invalid_partial_restart_and_reset(void)
{
    static const char *block0 =
        "968198a87ecbad2092b55f929da076a3d59d6963afba9d8212a061bb7684c08f";
    ninlil_test_entropy_t *entropy = ninlil_test_entropy_create(
        UINT64_C(0x0123456789abcdef), 1u);
    const ninlil_entropy_ops_t *ops = ninlil_test_entropy_ops(entropy);
    uint8_t actual[16];
    uint8_t expected[32];
    const ninlil_test_entropy_trace_record_t *trace;

    REQUIRE(entropy != NULL && parse_hex(block0, expected, sizeof(expected)));
    REQUIRE(!ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_NONE, 0u, 1u));
    REQUIRE(!ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_PARTIAL, 0u, 1u));
    REQUIRE(!ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_TEMPORARY, 1u, 1u));
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_TEMPORARY, 0u, 1u));
    (void)memset(actual, 0xaa, sizeof(actual));
    REQUIRE(ops->fill(ops->user, NULL, sizeof(actual))
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_test_entropy_invalid_call_count(entropy) == 1u
        && ninlil_test_entropy_counter(entropy) == 0u);
    ninlil_test_entropy_simulate_restart(entropy);
    REQUIRE(ninlil_test_entropy_restart_count(entropy) == 1u);
    REQUIRE(ops->fill(ops->user, actual, sizeof(actual))
        == NINLIL_PORT_TEMPORARY_FAILURE);
    REQUIRE(actual[0] == 0xaau && ninlil_test_entropy_counter(entropy) == 0u);
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_PARTIAL, 16u, 1u));
    REQUIRE(ops->fill(ops->user, actual, sizeof(actual))
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(actual[0] == 0xaau && ninlil_test_entropy_counter(entropy) == 0u
        && ninlil_test_entropy_script_error_count(entropy) == 1u);
    REQUIRE(ops->fill(ops->user, actual, sizeof(actual)) == NINLIL_PORT_OK);
    REQUIRE(memcmp(actual, expected, sizeof(actual)) == 0);
    trace = ninlil_test_entropy_trace_at(
        entropy, ninlil_test_entropy_trace_count(entropy) - 2u);
    REQUIRE(trace != NULL && trace->script_configuration_error == 1u
        && trace->bytes_written == 0u
        && trace->counter_before == trace->counter_after);
    REQUIRE(!ninlil_test_entropy_trace_overflowed(entropy));
    ninlil_test_entropy_scenario_reset(entropy, 1u, 9u);
    REQUIRE(ninlil_test_entropy_counter(entropy) == 0u
        && ninlil_test_entropy_call_count(entropy) == 0u
        && ninlil_test_entropy_restart_count(entropy) == 0u
        && ninlil_test_entropy_trace_count(entropy) == 0u);
    ninlil_test_entropy_destroy(entropy);
    return 0;
}

static int test_counter_headroom_and_exhaustion(void)
{
    ninlil_test_entropy_t *entropy = ninlil_test_entropy_create(1u, 1u);
    const ninlil_entropy_ops_t *ops = ninlil_test_entropy_ops(entropy);
    uint8_t actual[40];

    REQUIRE(entropy != NULL);
    REQUIRE(ninlil_test_entropy_set_counter_for_test(
        entropy, UINT64_MAX, 0));
    REQUIRE(ninlil_test_entropy_script(entropy,
        NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO, 0u, 1u));
    (void)memset(actual, 0xaa, sizeof(actual));
    REQUIRE(ops->fill(ops->user, actual, 33u)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(actual[0] == 0xaau && actual[32] == 0xaau
        && ninlil_test_entropy_counter(entropy) == UINT64_MAX
        && !ninlil_test_entropy_exhausted(entropy));
    REQUIRE(ops->fill(ops->user, actual, 32u) == NINLIL_PORT_OK);
    {
        uint8_t zero[32] = {0u};
        REQUIRE(memcmp(actual, zero, sizeof(zero)) == 0);
    }
    REQUIRE(ninlil_test_entropy_exhausted(entropy));
    (void)memset(actual, 0xaa, sizeof(actual));
    REQUIRE(ops->fill(ops->user, actual, 1u)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(actual[0] == 0xaau);
    REQUIRE(!ninlil_test_entropy_set_counter_for_test(
        entropy, 1u, 1));
    REQUIRE(!ninlil_test_entropy_set_counter_for_test(
        entropy, 1u, 2));
    ninlil_test_entropy_destroy(entropy);
    return 0;
}

int main(void)
{
    if (test_golden_streams_and_multiblock() != 0
        || test_zero_failure_partial_and_all_zero() != 0
        || test_invalid_partial_restart_and_reset() != 0
        || test_counter_headroom_and_exhaustion() != 0) {
        return 1;
    }
    return 0;
}
