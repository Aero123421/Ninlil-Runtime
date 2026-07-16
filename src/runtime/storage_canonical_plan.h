#ifndef NINLIL_RUNTIME_STORAGE_CANONICAL_PLAN_H
#define NINLIL_RUNTIME_STORAGE_CANONICAL_PLAN_H

#include <ninlil/platform.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Production-private, provider-neutral M1a READ_WRITE seam. */
typedef struct ninlil_storage_canonical_row {
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
} ninlil_storage_canonical_row_t;

typedef struct ninlil_storage_canonical_view {
    const ninlil_storage_canonical_row_t *rows;
    uint32_t row_count;
} ninlil_storage_canonical_view_t;

typedef struct ninlil_storage_canonical_metrics {
    uint64_t begin_entries;
    uint64_t begin_bytes;
    uint64_t final_entries;
    uint64_t final_bytes;
    uint64_t staging_entries;
    uint64_t staging_bytes;
} ninlil_storage_canonical_metrics_t;

typedef struct ninlil_storage_canonical_result {
    ninlil_storage_status_t cleanup_status;
    uint32_t transaction_started;
    uint32_t commit_attempted;
    uint32_t fence_required;
    ninlil_storage_canonical_metrics_t metrics;
} ninlil_storage_canonical_result_t;

typedef void (*ninlil_storage_canonical_before_commit_fn)(void *user);

/*
 * Validates real sorted/unique begin and final rows, calls capacity before
 * READ_WRITE begin, then emits each final row once and each begin-only erase
 * once. A non-OK preflight result guarantees begin/put/erase/commit were not
 * called. commit always consumes the transaction, including failure.
 */
ninlil_storage_status_t ninlil_storage_canonical_apply(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    ninlil_storage_canonical_view_t begin_view,
    ninlil_storage_canonical_view_t final_view,
    ninlil_storage_canonical_before_commit_fn before_commit,
    void *before_commit_user,
    ninlil_storage_canonical_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
