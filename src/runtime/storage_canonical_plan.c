#include "storage_canonical_plan.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Per-row portable logical bytes upper bound used by view_metrics:
 * 16 (overhead) + key 255 + value NINLIL_M1A_MAX_STORAGE_VALUE_BYTES.
 * row_count is uint32_t, so a successful view's entry/byte totals and the
 * checked sum of two such views cannot overflow uint64_t. Staging overflow
 * is still fail-closed (CORRUPT) if ever observed.
 */
#define NINLIL_STORAGE_CANONICAL_MAX_ROW_LOGICAL_BYTES \
    (UINT64_C(16) + 255u + (uint64_t)NINLIL_M1A_MAX_STORAGE_VALUE_BYTES)

static int checked_add_u64(uint64_t left, uint64_t right, uint64_t *out)
{
    if (out == NULL || left > UINT64_MAX - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

static int key_compare(ninlil_bytes_view_t left, ninlil_bytes_view_t right)
{
    uint32_t common = left.length < right.length ? left.length : right.length;
    int comparison = common == 0u ? 0 : memcmp(left.data, right.data, common);

    if (comparison != 0) {
        return comparison;
    }
    if (left.length < right.length) {
        return -1;
    }
    return left.length > right.length ? 1 : 0;
}

static int view_metrics(
    ninlil_storage_canonical_view_t view,
    uint64_t *out_entries,
    uint64_t *out_bytes)
{
    uint64_t bytes = 0u;
    uint32_t index;

    if ((view.row_count != 0u && view.rows == NULL)
        || out_entries == NULL || out_bytes == NULL) {
        return 0;
    }
    for (index = 0u; index < view.row_count; ++index) {
        const ninlil_storage_canonical_row_t *row = &view.rows[index];
        uint64_t row_bytes;

        if (row->key.length == 0u
            || row->key.length > 255u
            || row->key.data == NULL
            || row->value.length > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES
            || (row->value.length != 0u && row->value.data == NULL)
            || (index != 0u
                && key_compare(view.rows[index - 1u].key, row->key) >= 0)) {
            return 0;
        }
        row_bytes = UINT64_C(16) + row->key.length + row->value.length;
        if (row_bytes > NINLIL_STORAGE_CANONICAL_MAX_ROW_LOGICAL_BYTES
            || !checked_add_u64(bytes, row_bytes, &bytes)) {
            return 0;
        }
    }
    *out_entries = view.row_count;
    *out_bytes = bytes;
    return 1;
}

static int capacity_header_ok(const ninlil_storage_capacity_t *capacity)
{
    return capacity->abi_version == NINLIL_ABI_VERSION
        && capacity->struct_size == sizeof(*capacity);
}

static int capacity_non_ok_shape(const ninlil_storage_capacity_t *capacity)
{
    return capacity_header_ok(capacity)
        && capacity->max_entries == 0u && capacity->used_entries == 0u
        && capacity->max_bytes == 0u && capacity->used_bytes == 0u;
}

/* Normative capacity OK shape: max > 0 and used <= max (docs/12). */
static int capacity_ok_shape(const ninlil_storage_capacity_t *capacity)
{
    return capacity_header_ok(capacity)
        && capacity->max_entries > 0u
        && capacity->max_bytes > 0u
        && capacity->used_entries <= capacity->max_entries
        && capacity->used_bytes <= capacity->max_bytes;
}

static ninlil_storage_status_t rollback_failure(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_txn_t transaction,
    ninlil_storage_status_t primary,
    ninlil_storage_canonical_result_t *result)
{
    ninlil_storage_status_t cleanup = storage->rollback(
        storage->user, transaction);
    if (cleanup != NINLIL_STORAGE_OK) {
        result->cleanup_status = cleanup;
    }
    return primary;
}

ninlil_storage_status_t ninlil_storage_canonical_apply(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    ninlil_storage_canonical_view_t begin_view,
    ninlil_storage_canonical_view_t final_view,
    ninlil_storage_canonical_before_commit_fn before_commit,
    void *before_commit_user,
    ninlil_storage_canonical_result_t *out_result)
{
    ninlil_storage_capacity_t capacity;
    ninlil_storage_status_t status;
    ninlil_storage_txn_t transaction = NULL;
    uint32_t begin_index;
    uint32_t final_index;

    if (out_result == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (storage == NULL || handle == NULL || storage->capacity == NULL
        || storage->begin == NULL || storage->put == NULL
        || storage->erase == NULL || storage->commit == NULL
        || storage->rollback == NULL
        || !view_metrics(begin_view,
            &out_result->metrics.begin_entries,
            &out_result->metrics.begin_bytes)
        || !view_metrics(final_view,
            &out_result->metrics.final_entries,
            &out_result->metrics.final_bytes)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (begin_view.row_count == 0u && final_view.row_count == 0u) {
        return NINLIL_STORAGE_CORRUPT;
    }

    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    status = storage->capacity(storage->user, handle, &capacity);
    if (status != NINLIL_STORAGE_OK) {
        if (capacity_non_ok_shape(&capacity)) {
            return status;
        }
        out_result->fence_required = 1u;
        return NINLIL_STORAGE_CORRUPT;
    }
    if (!capacity_ok_shape(&capacity)
        || capacity.used_entries != out_result->metrics.begin_entries
        || capacity.used_bytes != out_result->metrics.begin_bytes) {
        out_result->fence_required = 1u;
        return NINLIL_STORAGE_CORRUPT;
    }
    /*
     * Staging totals are checked sums of the two views. Overflow is
     * fail-closed CORRUPT with mutation 0 (no begin/put/erase/commit).
     * Per-view begin/final <= max is the space gate; a 2*max comparison is
     * not required once each side is bounded and the sum is checked.
     */
    if (!checked_add_u64(out_result->metrics.begin_entries,
            out_result->metrics.final_entries,
            &out_result->metrics.staging_entries)
        || !checked_add_u64(out_result->metrics.begin_bytes,
            out_result->metrics.final_bytes,
            &out_result->metrics.staging_bytes)) {
        out_result->metrics.staging_entries = 0u;
        out_result->metrics.staging_bytes = 0u;
        out_result->fence_required = 1u;
        return NINLIL_STORAGE_CORRUPT;
    }
    if (out_result->metrics.begin_entries > capacity.max_entries
        || out_result->metrics.final_entries > capacity.max_entries
        || out_result->metrics.begin_bytes > capacity.max_bytes
        || out_result->metrics.final_bytes > capacity.max_bytes) {
        return NINLIL_STORAGE_NO_SPACE;
    }

    status = storage->begin(storage->user, handle,
        NINLIL_STORAGE_READ_WRITE, &transaction);
    if ((status == NINLIL_STORAGE_OK) != (transaction != NULL)) {
        if (transaction != NULL) {
            ninlil_storage_status_t cleanup = storage->rollback(
                storage->user, transaction);
            if (cleanup != NINLIL_STORAGE_OK) {
                out_result->cleanup_status = cleanup;
            }
        }
        out_result->fence_required = 1u;
        return NINLIL_STORAGE_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    out_result->transaction_started = 1u;

    for (final_index = 0u; final_index < final_view.row_count; ++final_index) {
        status = storage->put(storage->user, transaction,
            final_view.rows[final_index].key,
            final_view.rows[final_index].value);
        if (status != NINLIL_STORAGE_OK) {
            return rollback_failure(storage, transaction, status, out_result);
        }
    }
    begin_index = 0u;
    final_index = 0u;
    while (begin_index < begin_view.row_count) {
        int comparison;

        if (final_index >= final_view.row_count) {
            comparison = -1;
        } else {
            comparison = key_compare(begin_view.rows[begin_index].key,
                final_view.rows[final_index].key);
        }
        if (comparison < 0) {
            status = storage->erase(storage->user, transaction,
                begin_view.rows[begin_index].key);
            if (status != NINLIL_STORAGE_OK) {
                return rollback_failure(
                    storage, transaction, status, out_result);
            }
            begin_index += 1u;
        } else if (comparison == 0) {
            begin_index += 1u;
            final_index += 1u;
        } else {
            final_index += 1u;
        }
    }
    if (before_commit != NULL) {
        before_commit(before_commit_user);
    }
    out_result->commit_attempted = 1u;
    return storage->commit(
        storage->user, transaction, NINLIL_DURABILITY_FULL);
}
