#include "platform_basic_fixtures.h"

#include <stdlib.h>
#include <string.h>

typedef struct allocator_record {
    void *raw;
    void *aligned;
    uint64_t size;
    uint32_t alignment;
    uint64_t id;
    int active;
    struct allocator_record *next;
} allocator_record_t;

struct ninlil_test_allocator {
    ninlil_allocator_ops_t ops;
    allocator_record_t *records;
    ninlil_test_allocator_diagnostics_t diagnostics;
    ninlil_test_allocator_trace_record_t
        trace[NINLIL_TEST_PLATFORM_TRACE_CAPACITY];
    size_t trace_count;
    uint64_t next_sequence;
    uint64_t next_allocation_id;
    uint64_t fail_at;
    uint64_t fail_next;
};

struct ninlil_test_execution {
    ninlil_execution_ops_t ops;
    uint64_t context_id;
    uint64_t call_count;
    ninlil_test_execution_trace_record_t
        trace[NINLIL_TEST_PLATFORM_TRACE_CAPACITY];
    size_t trace_count;
    uint64_t next_sequence;
};

typedef struct clock_script_entry {
    ninlil_port_status_t status;
    ninlil_time_sample_t sample;
    uint32_t remaining_count;
    int raw;
} clock_script_entry_t;

struct ninlil_test_clock {
    ninlil_clock_ops_t ops;
    ninlil_id128_t epoch_id;
    uint64_t sim_time_ms;
    uint64_t offset_ms;
    ninlil_clock_trust_t trust;
    clock_script_entry_t script[NINLIL_TEST_CLOCK_SCRIPT_CAPACITY];
    size_t script_head;
    size_t script_count;
    ninlil_test_clock_trace_record_t
        trace[NINLIL_TEST_PLATFORM_TRACE_CAPACITY];
    size_t trace_count;
    uint64_t call_count;
    uint64_t configuration_error_count;
    uint64_t next_sequence;
};

static uint64_t increment_saturating(uint64_t value)
{
    return value == UINT64_MAX ? UINT64_MAX : value + 1u;
}

static int is_power_of_two(uint32_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

int ninlil_test_allocator_alignment_address_is_valid(
    uintptr_t address,
    uint32_t alignment)
{
    return is_power_of_two(alignment)
        && address <= UINTPTR_MAX - (uintptr_t)(alignment - 1u);
}

static void allocator_trace(
    ninlil_test_allocator_t *allocator,
    ninlil_test_allocator_trace_kind_t kind,
    ninlil_test_allocator_result_t result,
    uint64_t allocation_id,
    uint64_t size,
    uint32_t alignment)
{
    ninlil_test_allocator_trace_record_t *record;

    if (allocator->trace_count >= NINLIL_TEST_PLATFORM_TRACE_CAPACITY) {
        allocator->diagnostics.trace_overflowed = 1u;
        return;
    }
    record = &allocator->trace[allocator->trace_count];
    allocator->trace_count += 1u;
    record->sequence = allocator->next_sequence;
    allocator->next_sequence = increment_saturating(allocator->next_sequence);
    record->kind = kind;
    record->result = result;
    record->allocation_id = allocation_id;
    record->size = size;
    record->alignment = alignment;
}

static void *allocator_allocate(
    void *user,
    uint64_t size,
    uint32_t alignment)
{
    ninlil_test_allocator_t *allocator = (ninlil_test_allocator_t *)user;
    allocator_record_t *record;
    void *raw;
    uintptr_t address;
    uintptr_t aligned_address;
    size_t total;
    int injected;

    if (allocator == NULL) {
        return NULL;
    }
    allocator->diagnostics.allocate_calls = increment_saturating(
        allocator->diagnostics.allocate_calls);
    if (size == 0u || size > SIZE_MAX || !is_power_of_two(alignment)
        || (uint64_t)(alignment - 1u) > (uint64_t)SIZE_MAX - size) {
        allocator->diagnostics.invalid_allocate_calls = increment_saturating(
            allocator->diagnostics.invalid_allocate_calls);
        allocator->diagnostics.violation_count = increment_saturating(
            allocator->diagnostics.violation_count);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_ALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_INVALID_CALL, 0u, size, alignment);
        return NULL;
    }
    allocator->diagnostics.valid_allocation_attempts = increment_saturating(
        allocator->diagnostics.valid_allocation_attempts);
    injected = allocator->fail_next != 0u
        || (allocator->fail_at != 0u
            && allocator->diagnostics.valid_allocation_attempts
                == allocator->fail_at);
    if (allocator->fail_next != 0u) {
        allocator->fail_next -= 1u;
    }
    if (injected) {
        allocator->diagnostics.injected_failures = increment_saturating(
            allocator->diagnostics.injected_failures);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_ALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_INJECTED_FAILURE,
            0u, size, alignment);
        return NULL;
    }
    if (size > UINT64_MAX - allocator->diagnostics.live_bytes
        || allocator->diagnostics.live_allocations == UINT64_MAX) {
        allocator->diagnostics.system_failures = increment_saturating(
            allocator->diagnostics.system_failures);
        allocator->diagnostics.violation_count = increment_saturating(
            allocator->diagnostics.violation_count);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_ALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_SYSTEM_FAILURE, 0u, size, alignment);
        return NULL;
    }
    total = (size_t)size + (size_t)(alignment - 1u);
    raw = malloc(total);
    record = (allocator_record_t *)malloc(sizeof(*record));
    if (raw == NULL || record == NULL) {
        free(raw);
        free(record);
        allocator->diagnostics.system_failures = increment_saturating(
            allocator->diagnostics.system_failures);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_ALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_SYSTEM_FAILURE, 0u, size, alignment);
        return NULL;
    }
    address = (uintptr_t)raw;
    if (!ninlil_test_allocator_alignment_address_is_valid(
            address, alignment)) {
        free(raw);
        free(record);
        allocator->diagnostics.system_failures = increment_saturating(
            allocator->diagnostics.system_failures);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_ALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_SYSTEM_FAILURE, 0u, size, alignment);
        return NULL;
    }
    aligned_address = (address + (uintptr_t)(alignment - 1u))
        & ~(uintptr_t)(alignment - 1u);
    record->raw = raw;
    record->aligned = (void *)aligned_address;
    record->size = size;
    record->alignment = alignment;
    record->id = allocator->next_allocation_id;
    allocator->next_allocation_id = increment_saturating(
        allocator->next_allocation_id);
    record->active = 1;
    record->next = allocator->records;
    allocator->records = record;
    allocator->diagnostics.live_allocations = increment_saturating(
        allocator->diagnostics.live_allocations);
    allocator->diagnostics.live_bytes += size;
    if (allocator->diagnostics.peak_live_allocations
        < allocator->diagnostics.live_allocations) {
        allocator->diagnostics.peak_live_allocations =
            allocator->diagnostics.live_allocations;
    }
    if (allocator->diagnostics.peak_live_bytes
        < allocator->diagnostics.live_bytes) {
        allocator->diagnostics.peak_live_bytes =
            allocator->diagnostics.live_bytes;
    }
    allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_ALLOCATE,
        NINLIL_TEST_ALLOCATOR_RESULT_OK, record->id, size, alignment);
    return record->aligned;
}

static void allocator_deallocate(
    void *user,
    void *pointer,
    uint64_t size,
    uint32_t alignment)
{
    ninlil_test_allocator_t *allocator = (ninlil_test_allocator_t *)user;
    allocator_record_t *record;
    allocator_record_t *pointer_match = NULL;

    if (allocator == NULL) {
        return;
    }
    allocator->diagnostics.deallocate_calls = increment_saturating(
        allocator->diagnostics.deallocate_calls);
    record = allocator->records;
    while (record != NULL) {
        if (record->aligned == pointer) {
            pointer_match = record;
            if (record->active) {
                break;
            }
        }
        record = record->next;
    }
    if (pointer == NULL) {
        allocator->diagnostics.null_frees = increment_saturating(
            allocator->diagnostics.null_frees);
        allocator->diagnostics.violation_count = increment_saturating(
            allocator->diagnostics.violation_count);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_NULL_FREE, 0u, size, alignment);
    } else if (pointer_match == NULL) {
        allocator->diagnostics.unknown_frees = increment_saturating(
            allocator->diagnostics.unknown_frees);
        allocator->diagnostics.violation_count = increment_saturating(
            allocator->diagnostics.violation_count);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_UNKNOWN_FREE, 0u, size, alignment);
    } else if (!pointer_match->active) {
        allocator->diagnostics.double_frees = increment_saturating(
            allocator->diagnostics.double_frees);
        allocator->diagnostics.violation_count = increment_saturating(
            allocator->diagnostics.violation_count);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_DOUBLE_FREE,
            pointer_match->id, size, alignment);
    } else if (pointer_match->size != size) {
        allocator->diagnostics.wrong_frees = increment_saturating(
            allocator->diagnostics.wrong_frees);
        allocator->diagnostics.size_mismatches = increment_saturating(
            allocator->diagnostics.size_mismatches);
        allocator->diagnostics.violation_count = increment_saturating(
            allocator->diagnostics.violation_count);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_SIZE_MISMATCH,
            pointer_match->id, size, alignment);
    } else if (pointer_match->alignment != alignment) {
        allocator->diagnostics.wrong_frees = increment_saturating(
            allocator->diagnostics.wrong_frees);
        allocator->diagnostics.alignment_mismatches = increment_saturating(
            allocator->diagnostics.alignment_mismatches);
        allocator->diagnostics.violation_count = increment_saturating(
            allocator->diagnostics.violation_count);
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_ALIGNMENT_MISMATCH,
            pointer_match->id, size, alignment);
    } else {
        (void)memset(pointer_match->aligned, 0xddu, (size_t)pointer_match->size);
        pointer_match->active = 0;
        allocator->diagnostics.live_allocations -= 1u;
        allocator->diagnostics.live_bytes -= pointer_match->size;
        allocator_trace(allocator, NINLIL_TEST_ALLOCATOR_TRACE_DEALLOCATE,
            NINLIL_TEST_ALLOCATOR_RESULT_OK,
            pointer_match->id, size, alignment);
    }
}

ninlil_test_allocator_t *ninlil_test_allocator_create(void)
{
    ninlil_test_allocator_t *allocator =
        (ninlil_test_allocator_t *)calloc(1u, sizeof(*allocator));
    if (allocator == NULL) {
        return NULL;
    }
    allocator->next_sequence = 1u;
    allocator->next_allocation_id = 1u;
    allocator->ops.abi_version = NINLIL_ABI_VERSION;
    allocator->ops.struct_size = (uint16_t)sizeof(allocator->ops);
    allocator->ops.user = allocator;
    allocator->ops.allocate = allocator_allocate;
    allocator->ops.deallocate = allocator_deallocate;
    return allocator;
}

const ninlil_allocator_ops_t *ninlil_test_allocator_ops(
    ninlil_test_allocator_t *allocator)
{
    return allocator == NULL ? NULL : &allocator->ops;
}

void ninlil_test_allocator_fail_at(
    ninlil_test_allocator_t *allocator,
    uint64_t valid_attempt_ordinal)
{
    if (allocator != NULL) {
        allocator->fail_at = valid_attempt_ordinal;
    }
}

void ninlil_test_allocator_fail_next(
    ninlil_test_allocator_t *allocator,
    uint64_t count)
{
    if (allocator != NULL) {
        allocator->fail_next = count;
    }
}

ninlil_test_allocator_diagnostics_t ninlil_test_allocator_diagnostics(
    const ninlil_test_allocator_t *allocator)
{
    ninlil_test_allocator_diagnostics_t diagnostics;
    (void)memset(&diagnostics, 0, sizeof(diagnostics));
    if (allocator != NULL) {
        diagnostics = allocator->diagnostics;
    }
    return diagnostics;
}

size_t ninlil_test_allocator_trace_count(
    const ninlil_test_allocator_t *allocator)
{
    return allocator == NULL ? 0u : allocator->trace_count;
}

const ninlil_test_allocator_trace_record_t *ninlil_test_allocator_trace_at(
    const ninlil_test_allocator_t *allocator,
    size_t index)
{
    if (allocator == NULL || index >= allocator->trace_count) {
        return NULL;
    }
    return &allocator->trace[index];
}

uint64_t ninlil_test_allocator_destroy(ninlil_test_allocator_t *allocator)
{
    allocator_record_t *record;
    uint64_t leaks;

    if (allocator == NULL) {
        return 0u;
    }
    leaks = allocator->diagnostics.live_allocations;
    record = allocator->records;
    while (record != NULL) {
        allocator_record_t *next = record->next;
        free(record->raw);
        free(record);
        record = next;
    }
    free(allocator);
    return leaks;
}

static uint64_t execution_current_context_id(void *user)
{
    ninlil_test_execution_t *execution = (ninlil_test_execution_t *)user;
    uint64_t result;

    if (execution == NULL) {
        return 0u;
    }
    result = execution->context_id;
    execution->call_count = increment_saturating(execution->call_count);
    if (execution->trace_count < NINLIL_TEST_PLATFORM_TRACE_CAPACITY) {
        ninlil_test_execution_trace_record_t *record =
            &execution->trace[execution->trace_count];
        execution->trace_count += 1u;
        record->sequence = execution->next_sequence;
        execution->next_sequence = increment_saturating(
            execution->next_sequence);
        record->returned_context_id = result;
    }
    return result;
}

ninlil_test_execution_t *ninlil_test_execution_create(uint64_t context_id)
{
    ninlil_test_execution_t *execution =
        (ninlil_test_execution_t *)calloc(1u, sizeof(*execution));
    if (execution == NULL) {
        return NULL;
    }
    execution->context_id = context_id;
    execution->next_sequence = 1u;
    execution->ops.abi_version = NINLIL_ABI_VERSION;
    execution->ops.struct_size = (uint16_t)sizeof(execution->ops);
    execution->ops.user = execution;
    execution->ops.current_context_id = execution_current_context_id;
    return execution;
}

const ninlil_execution_ops_t *ninlil_test_execution_ops(
    ninlil_test_execution_t *execution)
{
    return execution == NULL ? NULL : &execution->ops;
}

void ninlil_test_execution_set_context_id(
    ninlil_test_execution_t *execution,
    uint64_t context_id)
{
    if (execution != NULL) {
        execution->context_id = context_id;
    }
}

uint64_t ninlil_test_execution_call_count(
    const ninlil_test_execution_t *execution)
{
    return execution == NULL ? 0u : execution->call_count;
}

size_t ninlil_test_execution_trace_count(
    const ninlil_test_execution_t *execution)
{
    return execution == NULL ? 0u : execution->trace_count;
}

const ninlil_test_execution_trace_record_t *ninlil_test_execution_trace_at(
    const ninlil_test_execution_t *execution,
    size_t index)
{
    if (execution == NULL || index >= execution->trace_count) {
        return NULL;
    }
    return &execution->trace[index];
}

void ninlil_test_execution_destroy(ninlil_test_execution_t *execution)
{
    free(execution);
}

static int id_is_nonzero(const ninlil_id128_t *id)
{
    size_t index;
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int time_sample_is_valid(const ninlil_time_sample_t *sample)
{
    return sample != NULL
        && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size >= sizeof(*sample)
        && id_is_nonzero(&sample->clock_epoch_id)
        && (sample->trust == NINLIL_CLOCK_TRUSTED
            || sample->trust == NINLIL_CLOCK_UNCERTAIN)
        && sample->reserved_zero == 0u;
}

static int clock_current_logical_now(
    const ninlil_test_clock_t *clock,
    uint64_t *out_now)
{
    if (clock->offset_ms > UINT64_MAX - clock->sim_time_ms) {
        return 0;
    }
    *out_now = clock->sim_time_ms + clock->offset_ms;
    return 1;
}

static int sample_does_not_regress_current_clock(
    const ninlil_test_clock_t *clock,
    const ninlil_time_sample_t *sample)
{
    uint64_t current_now;
    if (!clock_current_logical_now(clock, &current_now)) {
        return 0;
    }
    return memcmp(&sample->clock_epoch_id, &clock->epoch_id,
               sizeof(sample->clock_epoch_id)) != 0
        || sample->now_ms >= current_now;
}

static void clock_trace(
    ninlil_test_clock_t *clock,
    ninlil_port_status_t status,
    const ninlil_time_sample_t *sample,
    int raw,
    int configuration_error)
{
    if (clock->trace_count < NINLIL_TEST_PLATFORM_TRACE_CAPACITY) {
        ninlil_test_clock_trace_record_t *record =
            &clock->trace[clock->trace_count];
        clock->trace_count += 1u;
        record->sequence = clock->next_sequence;
        clock->next_sequence = increment_saturating(clock->next_sequence);
        record->status = status;
        record->sample = *sample;
        record->raw_outcome = raw != 0;
        record->configuration_error = configuration_error != 0;
    }
}

static ninlil_port_status_t clock_now(
    void *user,
    ninlil_time_sample_t *out_sample)
{
    ninlil_test_clock_t *clock = (ninlil_test_clock_t *)user;
    ninlil_port_status_t status;
    ninlil_time_sample_t trace_sample;
    int raw = 0;
    int configuration_error = 0;

    if (clock == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    clock->call_count = increment_saturating(clock->call_count);
    /* Port owns output: NULL is permanent; zeroed/poison input is allowed
     * (authority may pass zero sample so callback must write V1–V5 on OK). */
    if (out_sample == NULL) {
        (void)memset(&trace_sample, 0, sizeof(trace_sample));
        clock_trace(clock, NINLIL_PORT_PERMANENT_FAILURE, &trace_sample, 0, 0);
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (clock->script_count != 0u) {
        clock_script_entry_t *entry = &clock->script[clock->script_head];
        status = entry->status;
        raw = entry->raw;
        if (entry->raw) {
            *out_sample = entry->sample;
        } else if (entry->status == NINLIL_PORT_OK) {
            if (!sample_does_not_regress_current_clock(clock, &entry->sample)) {
                status = NINLIL_PORT_PERMANENT_FAILURE;
                configuration_error = 1;
                clock->configuration_error_count = increment_saturating(
                    clock->configuration_error_count);
            } else {
                /* Complete OK sample (callback fills V1–V5, not pre-init). */
                out_sample->abi_version = NINLIL_ABI_VERSION;
                out_sample->struct_size =
                    (uint16_t)sizeof(ninlil_time_sample_t);
                out_sample->clock_epoch_id = entry->sample.clock_epoch_id;
                out_sample->now_ms = entry->sample.now_ms;
                out_sample->trust = entry->sample.trust;
                out_sample->reserved_zero = 0u;
                clock->epoch_id = entry->sample.clock_epoch_id;
                clock->sim_time_ms = entry->sample.now_ms;
                clock->offset_ms = 0u;
                clock->trust = entry->sample.trust;
            }
        }
        entry->remaining_count -= 1u;
        if (entry->remaining_count == 0u) {
            clock->script_head = (clock->script_head + 1u)
                % NINLIL_TEST_CLOCK_SCRIPT_CAPACITY;
            clock->script_count -= 1u;
        }
    } else {
        if (clock->offset_ms > UINT64_MAX - clock->sim_time_ms) {
            status = NINLIL_PORT_PERMANENT_FAILURE;
        } else {
            status = NINLIL_PORT_OK;
            out_sample->abi_version = NINLIL_ABI_VERSION;
            out_sample->struct_size = (uint16_t)sizeof(ninlil_time_sample_t);
            out_sample->clock_epoch_id = clock->epoch_id;
            out_sample->now_ms = clock->sim_time_ms + clock->offset_ms;
            out_sample->trust = clock->trust;
            out_sample->reserved_zero = 0u;
        }
    }
    trace_sample = *out_sample;
    clock_trace(clock, status, &trace_sample, raw, configuration_error);
    return status;
}

ninlil_test_clock_t *ninlil_test_clock_create(void)
{
    ninlil_test_clock_t *clock =
        (ninlil_test_clock_t *)calloc(1u, sizeof(*clock));
    if (clock == NULL) {
        return NULL;
    }
    clock->next_sequence = 1u;
    clock->epoch_id.bytes[0] = 0xa0u;
    clock->epoch_id.bytes[15] = 0x01u;
    clock->trust = NINLIL_CLOCK_TRUSTED;
    clock->ops.abi_version = NINLIL_ABI_VERSION;
    clock->ops.struct_size = (uint16_t)sizeof(clock->ops);
    clock->ops.user = clock;
    clock->ops.now = clock_now;
    return clock;
}

const ninlil_clock_ops_t *ninlil_test_clock_ops(ninlil_test_clock_t *clock)
{
    return clock == NULL ? NULL : &clock->ops;
}

int ninlil_test_clock_advance(ninlil_test_clock_t *clock, uint64_t delta_ms)
{
    if (clock == NULL
        || delta_ms > UINT64_MAX - clock->sim_time_ms
        || clock->sim_time_ms + delta_ms
            > UINT64_MAX - clock->offset_ms) {
        return 0;
    }
    clock->sim_time_ms += delta_ms;
    return 1;
}

int ninlil_test_clock_advance_offset(
    ninlil_test_clock_t *clock,
    uint64_t delta_ms)
{
    if (clock == NULL || delta_ms > UINT64_MAX - clock->offset_ms) {
        return 0;
    }
    if (clock->offset_ms + delta_ms > UINT64_MAX - clock->sim_time_ms) {
        return 0;
    }
    clock->offset_ms += delta_ms;
    return 1;
}

int ninlil_test_clock_rollback(
    ninlil_test_clock_t *clock,
    const ninlil_id128_t *fresh_epoch_id)
{
    if (clock == NULL || fresh_epoch_id == NULL
        || !id_is_nonzero(fresh_epoch_id)
        || memcmp(fresh_epoch_id, &clock->epoch_id,
            sizeof(*fresh_epoch_id)) == 0) {
        return 0;
    }
    clock->epoch_id = *fresh_epoch_id;
    clock->trust = NINLIL_CLOCK_UNCERTAIN;
    return 1;
}

int ninlil_test_clock_recover(
    ninlil_test_clock_t *clock,
    const ninlil_time_sample_t *trusted_sample)
{
    if (clock == NULL || !time_sample_is_valid(trusted_sample)
        || trusted_sample->trust != NINLIL_CLOCK_TRUSTED
        || !sample_does_not_regress_current_clock(clock, trusted_sample)) {
        return 0;
    }
    clock->epoch_id = trusted_sample->clock_epoch_id;
    clock->sim_time_ms = trusted_sample->now_ms;
    clock->offset_ms = 0u;
    clock->trust = trusted_sample->trust;
    return 1;
}

int ninlil_test_clock_script(
    ninlil_test_clock_t *clock,
    ninlil_port_status_t status,
    const ninlil_time_sample_t *sample,
    uint32_t remaining_count)
{
    clock_script_entry_t *entry;
    size_t tail;

    if (clock == NULL || remaining_count == 0u
        || (status != NINLIL_PORT_OK
            && status != NINLIL_PORT_TEMPORARY_FAILURE
            && status != NINLIL_PORT_PERMANENT_FAILURE)
        || (status == NINLIL_PORT_OK && !time_sample_is_valid(sample))
        || (status == NINLIL_PORT_OK
            && !sample_does_not_regress_current_clock(clock, sample))
        || (status != NINLIL_PORT_OK && sample != NULL)
        || clock->script_count >= NINLIL_TEST_CLOCK_SCRIPT_CAPACITY) {
        return 0;
    }
    tail = (clock->script_head + clock->script_count)
        % NINLIL_TEST_CLOCK_SCRIPT_CAPACITY;
    entry = &clock->script[tail];
    (void)memset(entry, 0, sizeof(*entry));
    entry->status = status;
    if (sample != NULL) {
        entry->sample = *sample;
    }
    entry->remaining_count = remaining_count;
    entry->raw = 0;
    clock->script_count += 1u;
    return 1;
}

int ninlil_test_clock_script_raw(
    ninlil_test_clock_t *clock,
    ninlil_port_status_t status,
    const ninlil_time_sample_t *exact_sample,
    uint32_t remaining_count)
{
    clock_script_entry_t *entry;
    size_t tail;

    if (clock == NULL || exact_sample == NULL || remaining_count == 0u
        || clock->script_count >= NINLIL_TEST_CLOCK_SCRIPT_CAPACITY) {
        return 0;
    }
    tail = (clock->script_head + clock->script_count)
        % NINLIL_TEST_CLOCK_SCRIPT_CAPACITY;
    entry = &clock->script[tail];
    entry->status = status;
    entry->sample = *exact_sample;
    entry->remaining_count = remaining_count;
    entry->raw = 1;
    clock->script_count += 1u;
    return 1;
}

uint64_t ninlil_test_clock_call_count(const ninlil_test_clock_t *clock)
{
    return clock == NULL ? 0u : clock->call_count;
}

uint64_t ninlil_test_clock_configuration_error_count(
    const ninlil_test_clock_t *clock)
{
    return clock == NULL ? 0u : clock->configuration_error_count;
}

size_t ninlil_test_clock_trace_count(const ninlil_test_clock_t *clock)
{
    return clock == NULL ? 0u : clock->trace_count;
}

const ninlil_test_clock_trace_record_t *ninlil_test_clock_trace_at(
    const ninlil_test_clock_t *clock,
    size_t index)
{
    if (clock == NULL || index >= clock->trace_count) {
        return NULL;
    }
    return &clock->trace[index];
}

void ninlil_test_clock_destroy(ninlil_test_clock_t *clock)
{
    free(clock);
}
