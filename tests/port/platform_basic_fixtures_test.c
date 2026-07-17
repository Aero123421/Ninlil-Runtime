#include "platform_basic_fixtures.h"

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

static ninlil_time_sample_t sample(
    uint8_t epoch_tail,
    uint64_t now_ms,
    ninlil_clock_trust_t trust)
{
    ninlil_time_sample_t result;
    (void)memset(&result, 0, sizeof(result));
    result.abi_version = NINLIL_ABI_VERSION;
    result.struct_size = (uint16_t)sizeof(result);
    result.clock_epoch_id.bytes[15] = epoch_tail;
    result.now_ms = now_ms;
    result.trust = trust;
    return result;
}

static ninlil_time_sample_t caller_output(void)
{
    ninlil_time_sample_t result;
    (void)memset(&result, 0, sizeof(result));
    result.abi_version = NINLIL_ABI_VERSION;
    result.struct_size = (uint16_t)sizeof(result);
    return result;
}

static int test_allocator(void)
{
    ninlil_test_allocator_t *allocator = ninlil_test_allocator_create();
    const ninlil_allocator_ops_t *ops;
    void *first;
    void *second;
    void *third;
    void *leak;
    void *reverse_first;
    void *reverse_second;
    void *reverse_third;
    uint8_t unknown = 0u;
    ninlil_test_allocator_diagnostics_t diagnostics;
    const ninlil_test_allocator_trace_record_t *trace;

    REQUIRE(allocator != NULL);
    REQUIRE(ninlil_test_allocator_alignment_address_is_valid(
        UINTPTR_MAX - 3u, 4u));
    REQUIRE(!ninlil_test_allocator_alignment_address_is_valid(
        UINTPTR_MAX - 2u, 4u));
    REQUIRE(!ninlil_test_allocator_alignment_address_is_valid(0u, 3u));
    ops = ninlil_test_allocator_ops(allocator);
    REQUIRE(ops != NULL && ops->abi_version == NINLIL_ABI_VERSION
        && ops->struct_size == sizeof(*ops));
    REQUIRE(ops->allocate(ops->user, 0u, 1u) == NULL);
    REQUIRE(ops->allocate(ops->user, 1u, 0u) == NULL);
    REQUIRE(ops->allocate(ops->user, 1u, 3u) == NULL);
    REQUIRE(ops->allocate(ops->user, UINT64_MAX, 2u) == NULL);
    diagnostics = ninlil_test_allocator_diagnostics(allocator);
    REQUIRE(diagnostics.invalid_allocate_calls == 4u
        && diagnostics.valid_allocation_attempts == 0u
        && diagnostics.live_allocations == 0u
        && diagnostics.violation_count == 4u);
    first = ops->allocate(ops->user, 1u, 1u);
    second = ops->allocate(ops->user, 33u, 64u);
    third = ops->allocate(ops->user, 128u, 4096u);
    REQUIRE(first != NULL && second != NULL && third != NULL);
    REQUIRE((uintptr_t)first % 1u == 0u);
    REQUIRE((uintptr_t)second % 64u == 0u);
    REQUIRE((uintptr_t)third % 4096u == 0u);
    (void)memset(first, 1, 1u);
    (void)memset(second, 2, 33u);
    (void)memset(third, 3, 128u);
    diagnostics = ninlil_test_allocator_diagnostics(allocator);
    REQUIRE(diagnostics.live_allocations == 3u
        && diagnostics.live_bytes == 162u
        && diagnostics.peak_live_allocations == 3u
        && diagnostics.peak_live_bytes == 162u);
    ops->deallocate(ops->user, second, 32u, 64u);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 1u);
    REQUIRE(trace != NULL
        && trace->result == NINLIL_TEST_ALLOCATOR_RESULT_SIZE_MISMATCH);
    ops->deallocate(ops->user, second, 33u, 32u);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 1u);
    REQUIRE(trace != NULL
        && trace->result == NINLIL_TEST_ALLOCATOR_RESULT_ALIGNMENT_MISMATCH);
    ops->deallocate(ops->user, second, 32u, 32u);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 1u);
    REQUIRE(trace != NULL
        && trace->result == NINLIL_TEST_ALLOCATOR_RESULT_SIZE_MISMATCH);
    diagnostics = ninlil_test_allocator_diagnostics(allocator);
    REQUIRE(diagnostics.wrong_frees == 3u
        && diagnostics.size_mismatches == 2u
        && diagnostics.alignment_mismatches == 1u
        && diagnostics.live_allocations == 3u);
    ops->deallocate(ops->user, second, 33u, 64u);
    ops->deallocate(ops->user, second, 33u, 64u);
    ops->deallocate(ops->user, &unknown, 1u, 1u);
    ops->deallocate(ops->user, NULL, 1u, 1u);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 1u);
    REQUIRE(trace != NULL
        && trace->result == NINLIL_TEST_ALLOCATOR_RESULT_NULL_FREE);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 2u);
    REQUIRE(trace != NULL
        && trace->result == NINLIL_TEST_ALLOCATOR_RESULT_UNKNOWN_FREE);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 3u);
    REQUIRE(trace != NULL
        && trace->result == NINLIL_TEST_ALLOCATOR_RESULT_DOUBLE_FREE);
    diagnostics = ninlil_test_allocator_diagnostics(allocator);
    REQUIRE(diagnostics.double_frees == 1u
        && diagnostics.unknown_frees == 1u
        && diagnostics.null_frees == 1u
        && diagnostics.live_allocations == 2u
        && diagnostics.live_bytes == 129u);
    ops->deallocate(ops->user, third, 128u, 4096u);
    ops->deallocate(ops->user, first, 1u, 1u);
    ninlil_test_allocator_fail_at(allocator,
        diagnostics.valid_allocation_attempts + 2u);
    first = ops->allocate(ops->user, 8u, 8u);
    REQUIRE(first != NULL);
    REQUIRE(ops->allocate(ops->user, 8u, 8u) == NULL);
    ninlil_test_allocator_fail_next(allocator, 2u);
    REQUIRE(ops->allocate(ops->user, 8u, 8u) == NULL);
    REQUIRE(ops->allocate(ops->user, 8u, 8u) == NULL);
    leak = ops->allocate(ops->user, 16u, 16u);
    REQUIRE(leak != NULL);
    ops->deallocate(ops->user, first, 8u, 8u);
    reverse_first = ops->allocate(ops->user, 2u, 2u);
    reverse_second = ops->allocate(ops->user, 4u, 4u);
    reverse_third = ops->allocate(ops->user, 8u, 8u);
    REQUIRE(reverse_first != NULL && reverse_second != NULL
        && reverse_third != NULL);
    ops->deallocate(ops->user, reverse_third, 8u, 8u);
    ops->deallocate(ops->user, reverse_second, 4u, 4u);
    ops->deallocate(ops->user, reverse_first, 2u, 2u);
    diagnostics = ninlil_test_allocator_diagnostics(allocator);
    REQUIRE(diagnostics.injected_failures == 3u
        && diagnostics.live_allocations == 1u
        && diagnostics.live_bytes == 16u
        && diagnostics.violation_count == 10u
        && diagnostics.trace_overflowed == 0u);
    REQUIRE(ninlil_test_allocator_trace_count(allocator)
        == diagnostics.allocate_calls + diagnostics.deallocate_calls);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 1u);
    REQUIRE(trace != NULL && trace->kind == NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE
        && trace->result == NINLIL_TEST_ALLOCATOR_RESULT_OK
        && trace->allocation_id == 6u);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 2u);
    REQUIRE(trace != NULL && trace->allocation_id == 7u);
    trace = ninlil_test_allocator_trace_at(
        allocator, ninlil_test_allocator_trace_count(allocator) - 3u);
    REQUIRE(trace != NULL && trace->allocation_id == 8u);
    REQUIRE(ninlil_test_allocator_destroy(allocator) == 1u);
    return 0;
}

static int test_execution(void)
{
    ninlil_test_execution_t *execution = ninlil_test_execution_create(0u);
    const ninlil_execution_ops_t *ops;
    const ninlil_test_execution_trace_record_t *trace;

    REQUIRE(execution != NULL);
    ops = ninlil_test_execution_ops(execution);
    REQUIRE(ops != NULL && ops->abi_version == NINLIL_ABI_VERSION
        && ops->struct_size == sizeof(*ops));
    REQUIRE(ops->current_context_id(ops->user) == 0u);
    ninlil_test_execution_set_context_id(execution, 42u);
    REQUIRE(ops->current_context_id(ops->user) == 42u);
    ninlil_test_execution_set_context_id(execution, 7u);
    REQUIRE(ops->current_context_id(ops->user) == 7u);
    REQUIRE(ninlil_test_execution_call_count(execution) == 3u
        && ninlil_test_execution_trace_count(execution) == 3u);
    trace = ninlil_test_execution_trace_at(execution, 1u);
    REQUIRE(trace != NULL && trace->sequence == 2u
        && trace->returned_context_id == 42u);
    ninlil_test_execution_destroy(execution);
    return 0;
}

static int test_clock(void)
{
    ninlil_test_clock_t *clock = ninlil_test_clock_create();
    const ninlil_clock_ops_t *ops;
    ninlil_time_sample_t output;
    ninlil_time_sample_t before;
    ninlil_time_sample_t scripted;
    ninlil_time_sample_t raw;
    ninlil_time_sample_t expected;
    ninlil_id128_t rollback_epoch;
    const ninlil_test_clock_trace_record_t *trace;

    REQUIRE(clock != NULL);
    ops = ninlil_test_clock_ops(clock);
    REQUIRE(ops != NULL && ops->abi_version == NINLIL_ABI_VERSION
        && ops->struct_size == sizeof(*ops));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK);
    REQUIRE(output.clock_epoch_id.bytes[0] == 0xa0u
        && output.clock_epoch_id.bytes[15] == 1u
        && output.now_ms == 0u && output.trust == NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_test_clock_advance(clock, 10u));
    REQUIRE(ninlil_test_clock_advance_offset(clock, 5u));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.now_ms == 15u);
    REQUIRE(ninlil_test_clock_script(clock,
        NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u));
    (void)memset(&output, 0x5a, sizeof(output));
    output.abi_version = NINLIL_ABI_VERSION;
    output.struct_size = (uint16_t)sizeof(output);
    before = output;
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_TEMPORARY_FAILURE);
    REQUIRE(memcmp(&output, &before, sizeof(output)) == 0);
    REQUIRE(ninlil_test_clock_script(clock,
        NINLIL_PORT_PERMANENT_FAILURE, NULL, 1u));
    output = caller_output();
    before = output;
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(memcmp(&output, &before, sizeof(output)) == 0);
    scripted = sample(2u, 50u, NINLIL_CLOCK_UNCERTAIN);
    REQUIRE(ninlil_test_clock_script(clock, NINLIL_PORT_OK, &scripted, 1u));
    expected = scripted;
    (void)memset(&scripted, 0xee, sizeof(scripted));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK);
    REQUIRE(output.now_ms == expected.now_ms
        && output.clock_epoch_id.bytes[15] == 2u
        && output.trust == expected.trust);
    (void)memset(&rollback_epoch, 0, sizeof(rollback_epoch));
    rollback_epoch.bytes[15] = 3u;
    REQUIRE(ninlil_test_clock_rollback(clock, &rollback_epoch));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.clock_epoch_id.bytes[15] == 3u
        && output.trust == NINLIL_CLOCK_UNCERTAIN);
    scripted = sample(4u, 100u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_test_clock_recover(clock, &scripted));
    scripted = sample(4u, 99u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(!ninlil_test_clock_recover(clock, &scripted));
    REQUIRE(ninlil_test_clock_script(clock,
        NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u));
    REQUIRE(!ninlil_test_clock_script(clock,
        NINLIL_PORT_OK, &scripted, 1u));
    output = caller_output();
    before = output;
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_TEMPORARY_FAILURE
        && memcmp(&output, &before, sizeof(output)) == 0);
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.clock_epoch_id.bytes[15] == 4u && output.now_ms == 100u);
    raw = sample(4u, 1u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_test_clock_script_raw(clock,
        NINLIL_PORT_OK, &raw, 1u));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.clock_epoch_id.bytes[15] == 4u && output.now_ms == 1u);
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.clock_epoch_id.bytes[15] == 4u && output.now_ms == 100u);
    raw = sample(9u, 1u, NINLIL_CLOCK_TRUSTED);
    raw.abi_version = 77u;
    raw.reserved_zero = 99u;
    REQUIRE(ninlil_test_clock_script_raw(clock,
        (ninlil_port_status_t)999u, &raw, 1u));
    expected = raw;
    (void)memset(&raw, 0xcc, sizeof(raw));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == (ninlil_port_status_t)999u);
    REQUIRE(memcmp(&output, &expected, sizeof(output)) == 0);
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.clock_epoch_id.bytes[15] == 4u && output.now_ms == 100u);
    raw = sample(0u, 2u, (ninlil_clock_trust_t)999u);
    REQUIRE(ninlil_test_clock_script_raw(clock,
        NINLIL_PORT_OK, &raw, 1u));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && memcmp(&output, &raw, sizeof(output)) == 0);
    REQUIRE(ops->now(ops->user, NULL) == NINLIL_PORT_PERMANENT_FAILURE);
    /* Zero/poison input is allowed: port owns OK output (full V1–V5 write). */
    (void)memset(&output, 0x33, sizeof(output));
    output.abi_version = 0u;
    output.struct_size = 0u;
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK);
    REQUIRE(output.abi_version == NINLIL_ABI_VERSION);
    REQUIRE(output.struct_size >= (uint16_t)sizeof(output));
    REQUIRE(output.reserved_zero == 0u);
    REQUIRE(output.trust == NINLIL_CLOCK_TRUSTED
        || output.trust == NINLIL_CLOCK_UNCERTAIN);
    /* TEMP leaves sample bytes untouched (not treated as poison). */
    REQUIRE(ninlil_test_clock_script(clock,
        NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u));
    output = caller_output();
    before = output;
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_TEMPORARY_FAILURE);
    REQUIRE(memcmp(&output, &before, sizeof(output)) == 0);
    raw = sample(5u, UINT64_MAX, NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_test_clock_recover(clock, &raw));
    REQUIRE(!ninlil_test_clock_advance(clock, 1u));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.now_ms == UINT64_MAX);
    raw = sample(6u, 1u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_test_clock_recover(clock, &raw));
    REQUIRE(!ninlil_test_clock_advance_offset(clock, UINT64_MAX));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.now_ms == 1u);
    raw = sample(7u, 0u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_test_clock_recover(clock, &raw));
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.clock_epoch_id.bytes[15] == 7u && output.now_ms == 0u);
    scripted = sample(7u, 200u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(ninlil_test_clock_script(clock, NINLIL_PORT_OK, &scripted, 1u));
    REQUIRE(ninlil_test_clock_advance(clock, 300u));
    (void)memset(&output, 0x55, sizeof(output));
    output.abi_version = NINLIL_ABI_VERSION;
    output.struct_size = (uint16_t)sizeof(output);
    before = output;
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(memcmp(&output, &before, sizeof(output)) == 0
        && ninlil_test_clock_configuration_error_count(clock) == 1u);
    trace = ninlil_test_clock_trace_at(
        clock, ninlil_test_clock_trace_count(clock) - 1u);
    REQUIRE(trace != NULL && trace->configuration_error == 1u
        && trace->status == NINLIL_PORT_PERMANENT_FAILURE);
    output = caller_output();
    REQUIRE(ops->now(ops->user, &output) == NINLIL_PORT_OK
        && output.clock_epoch_id.bytes[15] == 7u && output.now_ms == 300u);
    REQUIRE(ninlil_test_clock_call_count(clock) == 21u);
    trace = ninlil_test_clock_trace_at(
        clock, ninlil_test_clock_trace_count(clock) - 1u);
    REQUIRE(trace != NULL && trace->status == NINLIL_PORT_OK
        && trace->sample.now_ms == 300u);
    REQUIRE(!ninlil_test_clock_script(clock,
        (ninlil_port_status_t)999u, NULL, 1u));
    raw = sample(0u, 0u, NINLIL_CLOCK_TRUSTED);
    REQUIRE(!ninlil_test_clock_script(clock, NINLIL_PORT_OK, &raw, 1u));
    ninlil_test_clock_destroy(clock);
    return 0;
}

int main(void)
{
    if (test_allocator() != 0 || test_execution() != 0
        || test_clock() != 0) {
        return 1;
    }
    return 0;
}
