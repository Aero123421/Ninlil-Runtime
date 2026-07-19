#ifndef NINLIL_TEST_N6_MEM_STORAGE_H
#define NINLIL_TEST_N6_MEM_STORAGE_H

#include "ninlil/platform.h"

#include <stdint.h>

/*
 * Scripted in-memory storage for N6 host tests.
 * Can force COMMIT_UNKNOWN outcomes into all four CU classes and
 * inject phase faults / provider shape poisons.
 */

typedef enum n6_mem_cu_outcome {
    N6_MEM_CU_NONE = 0,
    N6_MEM_CU_ALL_OLD = 1,      /* discard staging; durable stays pre-image */
    N6_MEM_CU_ALL_PROPOSED = 2, /* apply full staging then CU */
    N6_MEM_CU_MIXED = 3,        /* apply first staged put only, leave rest old */
    N6_MEM_CU_THIRD = 4         /* apply mutated third values for staged keys */
} n6_mem_cu_outcome_t;

typedef enum n6_mem_fault {
    N6_MEM_FAULT_NONE = 0,
    N6_MEM_FAULT_OPEN = 1, /* operational: non-OK + NULL */
    N6_MEM_FAULT_BEGIN = 2, /* operational: non-OK + NULL handle */
    N6_MEM_FAULT_GET = 3,
    N6_MEM_FAULT_PUT = 4,
    N6_MEM_FAULT_COMMIT = 5,
    N6_MEM_FAULT_ROLLBACK = 6,
    N6_MEM_FAULT_CAPACITY = 7, /* operational IO_ERROR, header/numerics clean */
    N6_MEM_FAULT_ITER_OPEN = 8, /* operational: non-OK + NULL iter */
    N6_MEM_FAULT_ITER_NEXT = 9, /* operational IO_ERROR, lengths 0, data intact */
    N6_MEM_FAULT_CLOSE_NOOP = 10,
    N6_MEM_FAULT_COMMIT_CORRUPT = 11,
    /* Malformed provider shapes: */
    N6_MEM_FAULT_BEGIN_NONOK_HANDLE = 12, /* non-OK + non-NULL txn */
    N6_MEM_FAULT_BEGIN_OK_NULL = 13,      /* OK + NULL txn */
    N6_MEM_FAULT_ITER_OPEN_NONOK_HANDLE = 14, /* non-OK + non-NULL iter */
    N6_MEM_FAULT_ITER_OPEN_OK_NULL = 15,      /* OK + NULL iter */
    N6_MEM_FAULT_OPEN_NONOK_HANDLE = 16, /* open non-OK + non-NULL handle */
    N6_MEM_FAULT_OPEN_OK_NULL = 17,      /* open OK + NULL */
    N6_MEM_FAULT_OPEN_UNKNOWN = 18,      /* open non-OK unknown status + NULL */
    N6_MEM_FAULT_CAPACITY_POISON = 19, /* non-OK + mutates header/numerics */
    N6_MEM_FAULT_CAPACITY_BAD_OK = 20, /* OK but bad struct_size/maxima */
    N6_MEM_FAULT_ITER_NEXT_NOTFOUND_POISON = 21, /* NOT_FOUND with length/data poison */
    N6_MEM_FAULT_ITER_NEXT_REWRITE_PTR = 22, /* rewrite data pointer */
    N6_MEM_FAULT_ITER_NEXT_OK_OVERSIZE = 23, /* OK with length > capacity */
    N6_MEM_FAULT_ITER_NEXT_OK_TAIL = 24, /* OK with tail mutation */
    N6_MEM_FAULT_ITER_NEXT_BTS = 25, /* BUFFER_TOO_SMALL proper shape */
    N6_MEM_FAULT_ITER_NEXT_BTS_BAD = 26, /* BTS without oversize lengths */
    N6_MEM_FAULT_ITER_NEXT_UNKNOWN = 27, /* unknown status */
    N6_MEM_FAULT_GET_NOTFOUND_POISON = 28,
    N6_MEM_FAULT_GET_REWRITE_PTR = 29,
    N6_MEM_FAULT_GET_OK_TAIL = 30,
    N6_MEM_FAULT_GET_BTS = 31,
    N6_MEM_FAULT_GET_UNKNOWN = 32,
    N6_MEM_FAULT_BEGIN_UNKNOWN = 33, /* begin non-OK unknown + NULL */
    N6_MEM_FAULT_CAPACITY_UNKNOWN = 34, /* capacity non-OK unknown, clean shape */
    N6_MEM_FAULT_CAPACITY_NOSPACE = 35, /* capacity non-OK NO_SPACE, clean shape */
    N6_MEM_FAULT_GET_NOSPACE = 36, /* get NO_SPACE, length 0, buffer untouched */
    N6_MEM_FAULT_GET_BTS_POISON = 37, /* BTS + buffer mutation (shape fail) */
    N6_MEM_FAULT_ROLLBACK_BUSY = 38, /* rollback IO/BUSY (boot mapping KAT) */
    N6_MEM_FAULT_ROLLBACK_NOSPACE = 39, /* rollback NO_SPACE → CORRUPT for boot */
    N6_MEM_FAULT_OPEN_NOSPACE = 40 /* open non-OK NO_SPACE + NULL */
} n6_mem_fault_t;

/*
 * Generic programmable fault (avoids enum explosion for closed status matrix).
 * One armed program: next matching op(s) return status with shape applied.
 */
typedef enum n6_mem_prog_op {
    N6_MEM_PROG_NONE = 0,
    N6_MEM_PROG_OPEN = 1,
    N6_MEM_PROG_BEGIN = 2,
    N6_MEM_PROG_GET = 3,
    N6_MEM_PROG_PUT = 4,
    N6_MEM_PROG_COMMIT = 5,
    N6_MEM_PROG_ROLLBACK = 6,
    N6_MEM_PROG_CAPACITY = 7
} n6_mem_prog_op_t;

typedef enum n6_mem_prog_shape {
    N6_MEM_SHAPE_DEFAULT = 0,      /* clean outputs for the status */
    N6_MEM_SHAPE_OK_NULL = 1,      /* OK + NULL handle (open/begin) */
    N6_MEM_SHAPE_NONOK_HANDLE = 2, /* non-OK + non-NULL handle/txn */
    N6_MEM_SHAPE_GET_PTR = 3,      /* rewrite get data pointer (not capacity) */
    N6_MEM_SHAPE_GET_OVERSIZE = 4, /* OK length > capacity (capacity field intact) */
    N6_MEM_SHAPE_GET_TAIL = 5,     /* OK with tail beyond length poisoned */
    N6_MEM_SHAPE_GET_MISS_POISON = 6, /* NOT_FOUND with length/data poison */
    N6_MEM_SHAPE_GET_BTS = 7,      /* BUFFER_TOO_SMALL length > cap, intact */
    N6_MEM_SHAPE_CAP_POISON = 8,   /* capacity mutates header/numerics */
    N6_MEM_SHAPE_CAP_BAD_OK = 9,   /* capacity OK but bad struct_size/maxima */
    N6_MEM_SHAPE_GET_CAP_REWRITE = 10 /* rewrite declared capacity field only */
} n6_mem_prog_shape_t;

const ninlil_storage_ops_t *n6_mem_storage_ops(void);
void n6_mem_storage_reset(void);

/* Next FULL commit returns COMMIT_UNKNOWN with the scripted durable outcome. */
void n6_mem_storage_inject_cu(n6_mem_cu_outcome_t outcome);

/* One-shot or sticky phase fault. count=1 means next call only. */
void n6_mem_storage_inject_fault(n6_mem_fault_t fault, int remaining_hits);

/* Skip skip_count matching calls, then fault remaining_hits times (e.g. Nth iter_open). */
void n6_mem_storage_inject_fault_after(
    n6_mem_fault_t fault, int skip_count, int remaining_hits);

/* Program next matching op: status + shape, remaining_hits (usually 1). */
void n6_mem_storage_program(
    n6_mem_prog_op_t op, ninlil_storage_status_t status,
    n6_mem_prog_shape_t shape, int remaining_hits);
/*
 * Skip skip_count matching calls of op, then arm remaining_hits.
 * Second slot: may coexist with n6_mem_storage_program (different op).
 */
void n6_mem_storage_program_after(
    n6_mem_prog_op_t op, ninlil_storage_status_t status,
    n6_mem_prog_shape_t shape, int skip_count, int remaining_hits);
void n6_mem_storage_clear_program(void);

/* Legacy helpers */
void n6_mem_storage_fail_get(int v);
void n6_mem_storage_fail_put(int v);

/* Direct durable put (for boot partial-set fixtures); bypasses txn. */
int n6_mem_storage_seed(
    const uint8_t *key, uint32_t klen, const uint8_t *val, uint32_t vlen);

/* Always append a new live slot (even if key already exists). For duplicate-key KATs. */
int n6_mem_storage_seed_append(
    const uint8_t *key, uint32_t klen, const uint8_t *val, uint32_t vlen);

/* Force capacity shape for binder tests (0 = default large). */
void n6_mem_storage_set_capacity(
    uint64_t max_entries, uint64_t used_entries, uint64_t max_bytes,
    uint64_t used_bytes);

uint32_t n6_mem_storage_close_count(void);
uint32_t n6_mem_storage_open_count(void);
uint32_t n6_mem_storage_begin_count(void);
uint32_t n6_mem_storage_iter_open_count(void);
uint32_t n6_mem_storage_iter_close_count(void);
uint32_t n6_mem_storage_iter_next_count(void);
uint32_t n6_mem_storage_commit_count(void);
uint32_t n6_mem_storage_rollback_count(void);
uint32_t n6_mem_storage_get_count(void);
uint32_t n6_mem_storage_put_count(void);
uint32_t n6_mem_storage_capacity_count(void);

#endif
