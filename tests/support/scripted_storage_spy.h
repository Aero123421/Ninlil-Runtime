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
#define NINLIL_SPY_MAX_TRACE ((size_t)256u)
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
    NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH = 6
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

typedef struct ninlil_spy_trace {
    ninlil_spy_op_t op;
    ninlil_storage_status_t status;
    ninlil_storage_mode_t mode;
    uint32_t prefix_length;
    uint32_t key_capacity;
    uint32_t value_capacity;
    uint32_t key_length;
    uint32_t value_length;
    uint32_t produced_handle; /* 1 if out handle/iter was non-NULL */
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
    uint64_t call_counts[NINLIL_SPY_OP_COUNT];
    uint64_t mutation_calls;
    uint64_t allocator_calls;
    int handle_live;
    int txn_live;
    int iter_live;
    int closed;
    uint32_t begin_calls;
    uint32_t iter_open_calls;
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
