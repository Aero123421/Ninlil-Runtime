#ifndef NINLIL_TEST_SCRIPTED_STORAGE_SPY_H
#define NINLIL_TEST_SCRIPTED_STORAGE_SPY_H

/*
 * Dedicated D2-S1 scripted Storage Port spy.
 * Exact call order / status / handle-shape / length / fence / rollback
 * control for the private domain scanner. Does not weaken the shared
 * in-memory provider contract (tests/support/in_memory_storage.*).
 */

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_SPY_MAX_ROWS ((size_t)128u)
#define NINLIL_SPY_MAX_KEY ((uint32_t)255u)
#define NINLIL_SPY_MAX_VALUE ((uint32_t)4096u)
#define NINLIL_SPY_MAX_TRACE ((size_t)1024u)
#define NINLIL_SPY_MAX_FAULTS ((size_t)32u)
#define NINLIL_SPY_MAX_CLOSE_HANDLES ((size_t)8u)

typedef enum ninlil_spy_op {
    NINLIL_SPY_OP_OPEN = 0,
    NINLIL_SPY_OP_CLOSE = 1,
    NINLIL_SPY_OP_BEGIN = 2,
    NINLIL_SPY_OP_GET = 3,
    NINLIL_SPY_OP_PUT = 4,
    NINLIL_SPY_OP_ERASE = 5,
    NINLIL_SPY_OP_ITER_OPEN = 6,
    NINLIL_SPY_OP_ITER_NEXT = 7,
    NINLIL_SPY_OP_ITER_CLOSE = 8,
    NINLIL_SPY_OP_CAPACITY = 9,
    NINLIL_SPY_OP_COMMIT = 10,
    NINLIL_SPY_OP_ROLLBACK = 11,
    NINLIL_SPY_OP_COUNT = 12
} ninlil_spy_op_t;

typedef enum ninlil_spy_shape {
    NINLIL_SPY_SHAPE_NATURAL = 0,
    NINLIL_SPY_SHAPE_OK_NULL = 1,
    NINLIL_SPY_SHAPE_ERROR_WITH_HANDLE = 2,
    NINLIL_SPY_SHAPE_BTS_LENGTHS = 3,
    NINLIL_SPY_SHAPE_NOT_FOUND_POISON = 4,
    NINLIL_SPY_SHAPE_OK_BAD_LENGTH = 5,
    NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH = 6,
    /* Provider rewrites inout data pointer away from caller slot (get/iter). */
    NINLIL_SPY_SHAPE_REWRITE_DATA_PTR = 7,
    /* Provider rewrites inout capacity (get/iter). */
    NINLIL_SPY_SHAPE_REWRITE_CAPACITY = 8,
    /*
     * iter_next only: same-snapshot inconsistency — return natural key with
     * value bytes that differ from the retained get path (last byte flipped).
     */
    NINLIL_SPY_SHAPE_VALUE_MISMATCH = 9,
    /*
     * iter_next only: clean terminal NOT_FOUND (both lengths 0) even when
     * further natural rows remain (omits remaining catalog keys).
     */
    NINLIL_SPY_SHAPE_EARLY_END = 10
} ninlil_spy_shape_t;

typedef struct ninlil_spy_row {
    uint8_t key[NINLIL_SPY_MAX_KEY];
    uint32_t key_length;
    uint8_t value[NINLIL_SPY_MAX_VALUE];
    uint32_t value_length;
} ninlil_spy_row_t;

typedef struct ninlil_spy_fault {
    ninlil_spy_op_t op;
    uint32_t on_call; /* 1-based occurrence of this op */
    ninlil_storage_status_t status;
    ninlil_spy_shape_t shape;
    uint32_t key_length;
    uint32_t value_length;
    uint32_t used;
} ninlil_spy_fault_t;

/*
 * Trace retains exact get key bytes (no domain semantics). Capacity covers
 * Storage key bound 255; catalog keys are 9/10 bytes.
 */
#define NINLIL_SPY_TRACE_KEY_BYTES ((uint32_t)255u)

/* Stable, test-only identities: reopen generations are intentionally distinct. */
typedef enum ninlil_spy_handle_id {
    NINLIL_SPY_HANDLE_NONE = 0,
    NINLIL_SPY_HANDLE_H1 = 1,
    NINLIL_SPY_HANDLE_T1 = 2,
    NINLIL_SPY_HANDLE_I1 = 3,
    NINLIL_SPY_HANDLE_I10 = 12
} ninlil_spy_handle_id_t;

typedef struct ninlil_spy_trace {
    ninlil_spy_op_t op;
    uint32_t api_call_index;
    ninlil_storage_status_t status;
    uint8_t status_present;
    ninlil_storage_mode_t mode;
    uint8_t mode_present;
    uint32_t input_handle_id;
    uint32_t output_handle_id;
    uint32_t prefix_length;
    uint8_t prefix_bytes[NINLIL_SPY_TRACE_KEY_BYTES];
    uint32_t key_capacity;
    uint32_t value_capacity;
    uint32_t key_length;
    uint32_t value_length;
    uint32_t produced_handle; /* 1 if out handle/iter was non-NULL */
    /* Exact requested GET bytes and produced ITER_NEXT key bytes. */
    uint8_t request_key_bytes[NINLIL_SPY_TRACE_KEY_BYTES];
    uint32_t request_key_bytes_length;
    uint8_t key_bytes[NINLIL_SPY_TRACE_KEY_BYTES];
    uint32_t key_bytes_length;
} ninlil_spy_trace_t;

typedef struct ninlil_scripted_storage_spy {
    ninlil_storage_ops_t ops;
    ninlil_spy_row_t rows[NINLIL_SPY_MAX_ROWS];
    size_t row_count;
    size_t iter_position;
    ninlil_spy_fault_t faults[NINLIL_SPY_MAX_FAULTS];
    size_t fault_count;
    ninlil_spy_trace_t trace[NINLIL_SPY_MAX_TRACE];
    size_t trace_count;
    uint8_t trace_overflow;
    uint32_t trace_api_call_index;
    uint64_t call_counts[NINLIL_SPY_OP_COUNT];
    uint64_t mutation_calls;
    uint64_t allocator_calls;
    int handle_live;
    int txn_live;
    int iter_live;
    uint32_t iter_generation;
    int closed;
    uint32_t begin_calls;
    uint32_t iter_open_calls;
    uint32_t iter_open_success_calls;
    uint32_t iter_next_calls;
    uint32_t iter_close_calls;
    uint32_t rollback_calls;
    uint32_t close_calls;
    uint32_t get_calls;
    /* Exact handles passed to close (order preserved; for original-vs-foreign). */
    ninlil_storage_handle_t closed_handles[NINLIL_SPY_MAX_CLOSE_HANDLES];
    uint32_t closed_handle_count;
    /* Opaque live handles as non-NULL tokens. */
    int handle_token;
    int txn_token;
    int iter_token;
} ninlil_scripted_storage_spy_t;

void ninlil_spy_init(ninlil_scripted_storage_spy_t *spy);

int ninlil_spy_add_row(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *key,
    uint32_t key_length,
    const uint8_t *value,
    uint32_t value_length);

int ninlil_spy_add_fault(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_spy_op_t op,
    uint32_t on_call,
    ninlil_storage_status_t status,
    ninlil_spy_shape_t shape,
    uint32_t key_length,
    uint32_t value_length);

const ninlil_storage_ops_t *ninlil_spy_ops(
    ninlil_scripted_storage_spy_t *spy);

ninlil_storage_handle_t ninlil_spy_open_handle(
    ninlil_scripted_storage_spy_t *spy);

uint64_t ninlil_spy_call_count(
    const ninlil_scripted_storage_spy_t *spy,
    ninlil_spy_op_t op);

int ninlil_spy_assert_no_mutations(const ninlil_scripted_storage_spy_t *spy);

/* Test-only public-call boundary for exact oracle api_call_index tracing. */
void ninlil_spy_trace_set_api_call_index(
    ninlil_scripted_storage_spy_t *spy, uint32_t api_call_index);

/* Returns 1 if every rollback is preceded by matching iter_close when iter was live. */
int ninlil_spy_iter_close_before_rollback(
    const ninlil_scripted_storage_spy_t *spy);

/* Number of times close was called with this exact handle pointer. */
uint32_t ninlil_spy_close_count_for_handle(
    const ninlil_scripted_storage_spy_t *spy,
    ninlil_storage_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TEST_SCRIPTED_STORAGE_SPY_H */
