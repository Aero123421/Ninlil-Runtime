#ifndef NINLIL_TEST_IN_MEMORY_STORAGE_H
#define NINLIL_TEST_IN_MEMORY_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_TEST_STORAGE_MAX_NAMESPACES ((uint32_t)32u)
#define NINLIL_TEST_STORAGE_TRACE_CAPACITY ((size_t)1024u)
#define NINLIL_TEST_STORAGE_FAULT_QUEUE_CAPACITY ((size_t)16u)

typedef struct ninlil_test_storage ninlil_test_storage_t;

typedef enum ninlil_test_storage_operation {
    NINLIL_TEST_STORAGE_OP_OPEN = 0,
    NINLIL_TEST_STORAGE_OP_CLOSE = 1,
    NINLIL_TEST_STORAGE_OP_BEGIN = 2,
    NINLIL_TEST_STORAGE_OP_GET = 3,
    NINLIL_TEST_STORAGE_OP_PUT = 4,
    NINLIL_TEST_STORAGE_OP_ERASE = 5,
    NINLIL_TEST_STORAGE_OP_ITER_OPEN = 6,
    NINLIL_TEST_STORAGE_OP_ITER_NEXT = 7,
    NINLIL_TEST_STORAGE_OP_ITER_CLOSE = 8,
    NINLIL_TEST_STORAGE_OP_CAPACITY = 9,
    NINLIL_TEST_STORAGE_OP_COMMIT = 10,
    NINLIL_TEST_STORAGE_OP_ROLLBACK = 11,
    NINLIL_TEST_STORAGE_OP_COUNT = 12
} ninlil_test_storage_operation_t;

typedef struct ninlil_test_storage_config {
    uint32_t max_namespaces;
    uint64_t max_entries_per_namespace;
    uint64_t max_bytes_per_namespace;
} ninlil_test_storage_config_t;

typedef struct ninlil_test_storage_trace_record {
    uint64_t sequence;
    ninlil_test_storage_operation_t operation;
    ninlil_storage_status_t status;
    uint64_t handle_id;
    uint64_t transaction_id;
    uint64_t iterator_id;
    ninlil_durability_t durability;
} ninlil_test_storage_trace_record_t;

/*
 * The fixture owns every object returned by its vtable. Configuration limits
 * are finite logical limits, not allocator or filesystem byte counts.
 */
ninlil_test_storage_t *ninlil_test_storage_create(
    const ninlil_test_storage_config_t *config);

void ninlil_test_storage_destroy(ninlil_test_storage_t *storage);

const ninlil_storage_ops_t *ninlil_test_storage_ops(
    ninlil_test_storage_t *storage);

/*
 * Script the next otherwise-valid status-returning call of one operation.
 * CLOSE and ITER_CLOSE are void and therefore reject fault scripting.
 * Invalid call shapes are rejected before, and do not consume, the script.
 */
int ninlil_test_storage_fault_next(
    ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation,
    ninlil_storage_status_t status);

/*
 * Enqueue an operation-specific FIFO fault. COMMIT operation's
 * COMMIT_UNKNOWN requires has_commit_unknown_truth=1. The same raw status on
 * another operation has no commit truth and requires both truth fields zero.
 * OK, NOT_FOUND, and BUFFER_TOO_SMALL are natural-path results and cannot be
 * fault entries. Boolean arguments accept exact 0 or 1 only.
 */
int ninlil_test_storage_fault_enqueue(
    ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation,
    ninlil_storage_status_t status,
    uint32_t remaining_count,
    int has_commit_unknown_truth,
    int commit_unknown_committed);

/* Preserve committed namespaces while discarding every volatile resource. */
void ninlil_test_storage_simulate_crash(ninlil_test_storage_t *storage);

uint64_t ninlil_test_storage_call_count(
    const ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation);

size_t ninlil_test_storage_trace_count(
    const ninlil_test_storage_t *storage);

int ninlil_test_storage_trace_overflowed(
    const ninlil_test_storage_t *storage);

const ninlil_test_storage_trace_record_t *ninlil_test_storage_trace_at(
    const ninlil_test_storage_t *storage,
    size_t index);

uint64_t ninlil_test_storage_live_handles(
    const ninlil_test_storage_t *storage);

uint64_t ninlil_test_storage_live_transactions(
    const ninlil_test_storage_t *storage);

uint64_t ninlil_test_storage_live_iterators(
    const ninlil_test_storage_t *storage);

#ifdef __cplusplus
}
#endif

#endif
