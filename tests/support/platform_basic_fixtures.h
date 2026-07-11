#ifndef NINLIL_TEST_PLATFORM_BASIC_FIXTURES_H
#define NINLIL_TEST_PLATFORM_BASIC_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_TEST_PLATFORM_TRACE_CAPACITY ((size_t)1024u)
#define NINLIL_TEST_CLOCK_SCRIPT_CAPACITY ((size_t)32u)

typedef struct ninlil_test_allocator ninlil_test_allocator_t;
typedef struct ninlil_test_execution ninlil_test_execution_t;
typedef struct ninlil_test_clock ninlil_test_clock_t;

typedef enum ninlil_test_allocator_trace_kind {
    NINLIL_TEST_ALLOCATOR_TRACE_ALLOCATE = 1,
    NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE = 2
} ninlil_test_allocator_trace_kind_t;

typedef enum ninlil_test_allocator_result {
    NINLIL_TEST_ALLOCATOR_RESULT_OK = 1,
    NINLIL_TEST_ALLOCATOR_RESULT_INJECTED_FAILURE = 2,
    NINLIL_TEST_ALLOCATOR_RESULT_INVALID_CALL = 3,
    NINLIL_TEST_ALLOCATOR_RESULT_SYSTEM_FAILURE = 4,
    NINLIL_TEST_ALLOCATOR_RESULT_NULL_FREE = 5,
    NINLIL_TEST_ALLOCATOR_RESULT_UNKNOWN_FREE = 6,
    NINLIL_TEST_ALLOCATOR_RESULT_DOUBLE_FREE = 7,
    NINLIL_TEST_ALLOCATOR_RESULT_SIZE_MISMATCH = 8,
    NINLIL_TEST_ALLOCATOR_RESULT_ALIGNMENT_MISMATCH = 9
} ninlil_test_allocator_result_t;

typedef struct ninlil_test_allocator_trace_record {
    uint64_t sequence;
    ninlil_test_allocator_trace_kind_t kind;
    ninlil_test_allocator_result_t result;
    uint64_t allocation_id;
    uint64_t size;
    uint32_t alignment;
} ninlil_test_allocator_trace_record_t;

typedef struct ninlil_test_allocator_diagnostics {
    uint64_t allocate_calls;
    uint64_t deallocate_calls;
    uint64_t valid_allocation_attempts;
    uint64_t live_allocations;
    uint64_t live_bytes;
    uint64_t peak_live_allocations;
    uint64_t peak_live_bytes;
    uint64_t invalid_allocate_calls;
    uint64_t injected_failures;
    uint64_t system_failures;
    uint64_t double_frees;
    uint64_t null_frees;
    uint64_t wrong_frees;
    uint64_t size_mismatches;
    uint64_t alignment_mismatches;
    uint64_t unknown_frees;
    uint64_t violation_count;
    uint32_t trace_overflowed;
} ninlil_test_allocator_diagnostics_t;

ninlil_test_allocator_t *ninlil_test_allocator_create(void);
const ninlil_allocator_ops_t *ninlil_test_allocator_ops(
    ninlil_test_allocator_t *allocator);
void ninlil_test_allocator_fail_at(
    ninlil_test_allocator_t *allocator,
    uint64_t valid_attempt_ordinal);
void ninlil_test_allocator_fail_next(
    ninlil_test_allocator_t *allocator,
    uint64_t count);
ninlil_test_allocator_diagnostics_t ninlil_test_allocator_diagnostics(
    const ninlil_test_allocator_t *allocator);
size_t ninlil_test_allocator_trace_count(
    const ninlil_test_allocator_t *allocator);
const ninlil_test_allocator_trace_record_t *ninlil_test_allocator_trace_at(
    const ninlil_test_allocator_t *allocator,
    size_t index);
/* Returns the number of allocations that were live at destruction. */
uint64_t ninlil_test_allocator_destroy(ninlil_test_allocator_t *allocator);

/* Pure helper used to exercise uintptr alignment-addition boundaries. */
int ninlil_test_allocator_alignment_address_is_valid(
    uintptr_t address,
    uint32_t alignment);

typedef struct ninlil_test_execution_trace_record {
    uint64_t sequence;
    uint64_t returned_context_id;
} ninlil_test_execution_trace_record_t;

ninlil_test_execution_t *ninlil_test_execution_create(uint64_t context_id);
const ninlil_execution_ops_t *ninlil_test_execution_ops(
    ninlil_test_execution_t *execution);
void ninlil_test_execution_set_context_id(
    ninlil_test_execution_t *execution,
    uint64_t context_id);
uint64_t ninlil_test_execution_call_count(
    const ninlil_test_execution_t *execution);
size_t ninlil_test_execution_trace_count(
    const ninlil_test_execution_t *execution);
const ninlil_test_execution_trace_record_t *ninlil_test_execution_trace_at(
    const ninlil_test_execution_t *execution,
    size_t index);
void ninlil_test_execution_destroy(ninlil_test_execution_t *execution);

typedef struct ninlil_test_clock_trace_record {
    uint64_t sequence;
    ninlil_port_status_t status;
    ninlil_time_sample_t sample;
    uint32_t raw_outcome;
    uint32_t configuration_error;
} ninlil_test_clock_trace_record_t;

ninlil_test_clock_t *ninlil_test_clock_create(void);
const ninlil_clock_ops_t *ninlil_test_clock_ops(ninlil_test_clock_t *clock);
int ninlil_test_clock_advance(ninlil_test_clock_t *clock, uint64_t delta_ms);
int ninlil_test_clock_advance_offset(
    ninlil_test_clock_t *clock,
    uint64_t delta_ms);
int ninlil_test_clock_rollback(
    ninlil_test_clock_t *clock,
    const ninlil_id128_t *fresh_epoch_id);
int ninlil_test_clock_recover(
    ninlil_test_clock_t *clock,
    const ninlil_time_sample_t *trusted_sample);
int ninlil_test_clock_script(
    ninlil_test_clock_t *clock,
    ninlil_port_status_t status,
    const ninlil_time_sample_t *sample,
    uint32_t remaining_count);
int ninlil_test_clock_script_raw(
    ninlil_test_clock_t *clock,
    ninlil_port_status_t status,
    const ninlil_time_sample_t *exact_sample,
    uint32_t remaining_count);
uint64_t ninlil_test_clock_call_count(const ninlil_test_clock_t *clock);
uint64_t ninlil_test_clock_configuration_error_count(
    const ninlil_test_clock_t *clock);
size_t ninlil_test_clock_trace_count(const ninlil_test_clock_t *clock);
const ninlil_test_clock_trace_record_t *ninlil_test_clock_trace_at(
    const ninlil_test_clock_t *clock,
    size_t index);
void ninlil_test_clock_destroy(ninlil_test_clock_t *clock);

#ifdef __cplusplus
}
#endif

#endif
