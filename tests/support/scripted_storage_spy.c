#include "scripted_storage_spy.h"

#include <string.h>

static void trace_push(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_spy_op_t op,
    ninlil_storage_status_t status,
    ninlil_storage_mode_t mode,
    uint32_t prefix_length,
    uint32_t key_capacity,
    uint32_t value_capacity,
    uint32_t key_length,
    uint32_t value_length,
    uint32_t produced_handle)
{
    ninlil_spy_trace_t *entry;

    spy->call_counts[op] += 1u;
    if (spy->trace_count >= NINLIL_SPY_MAX_TRACE) {
        return;
    }
    entry = &spy->trace[spy->trace_count++];
    entry->op = op;
    entry->status = status;
    entry->mode = mode;
    entry->prefix_length = prefix_length;
    entry->key_capacity = key_capacity;
    entry->value_capacity = value_capacity;
    entry->key_length = key_length;
    entry->value_length = value_length;
    entry->produced_handle = produced_handle;
    entry->key_bytes_length = 0u;
    (void)memset(entry->key_bytes, 0, sizeof(entry->key_bytes));
}

/* Record exact get key bytes into the most recent GET trace entry. */
static void trace_set_get_key(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *key_data,
    uint32_t key_length)
{
    ninlil_spy_trace_t *entry;

    if (spy->trace_count == 0u) {
        return;
    }
    entry = &spy->trace[spy->trace_count - 1u];
    if (entry->op != NINLIL_SPY_OP_GET) {
        return;
    }
    entry->key_bytes_length = 0u;
    if (key_data == NULL || key_length == 0u) {
        return;
    }
    if (key_length > NINLIL_SPY_TRACE_KEY_BYTES) {
        key_length = NINLIL_SPY_TRACE_KEY_BYTES;
    }
    (void)memcpy(entry->key_bytes, key_data, key_length);
    entry->key_bytes_length = key_length;
}

static ninlil_spy_fault_t *find_fault(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_spy_op_t op,
    uint32_t occurrence)
{
    size_t index;

    for (index = 0u; index < spy->fault_count; ++index) {
        ninlil_spy_fault_t *fault = &spy->faults[index];
        if (fault->op == op && fault->on_call == occurrence
            && fault->used == 0u) {
            return fault;
        }
    }
    return NULL;
}

static ninlil_storage_status_t spy_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;

    (void)storage_namespace;
    (void)expected_schema;
    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    spy->mutation_calls += 1u;
    trace_push(spy, NINLIL_SPY_OP_OPEN, NINLIL_STORAGE_UNSUPPORTED_SCHEMA,
        0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}

static void spy_close(void *user, ninlil_storage_handle_t handle)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;

    spy->close_calls += 1u;
    if (spy->closed_handle_count < NINLIL_SPY_MAX_CLOSE_HANDLES) {
        spy->closed_handles[spy->closed_handle_count++] = handle;
    }
    /* Only clear spy liveness when closing this spy's own open handle token. */
    if (handle == (ninlil_storage_handle_t)&spy->handle_token) {
        spy->handle_live = 0;
        spy->closed = 1;
        spy->handle_token = 0;
        spy->txn_live = 0;
        spy->iter_live = 0;
        spy->txn_token = 0;
        spy->iter_token = 0;
    }
    trace_push(spy, NINLIL_SPY_OP_CLOSE, NINLIL_STORAGE_OK,
        0u, 0u, 0u, 0u, 0u, 0u, 0u);
}

static ninlil_storage_status_t spy_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;
    ninlil_spy_fault_t *fault;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;

    spy->begin_calls += 1u;
    if (out_txn != NULL) {
        *out_txn = NULL;
    }
    if (handle == NULL || out_txn == NULL || !spy->handle_live
        || spy->txn_live) {
        status = NINLIL_STORAGE_CORRUPT;
        trace_push(spy, NINLIL_SPY_OP_BEGIN, status, mode, 0u, 0u, 0u, 0u, 0u, 0u);
        return status;
    }

    fault = find_fault(spy, NINLIL_SPY_OP_BEGIN, spy->begin_calls);
    if (fault != NULL) {
        fault->used = 1u;
        status = fault->status;
        if (fault->shape == NINLIL_SPY_SHAPE_OK_NULL) {
            *out_txn = NULL;
            status = NINLIL_STORAGE_OK;
        } else if (fault->shape == NINLIL_SPY_SHAPE_ERROR_WITH_HANDLE) {
            spy->txn_token = 1;
            *out_txn = (ninlil_storage_txn_t)&spy->txn_token;
            spy->txn_live = 1;
            if (status == NINLIL_STORAGE_OK) {
                status = NINLIL_STORAGE_IO_ERROR;
            }
        } else if (status == NINLIL_STORAGE_OK) {
            spy->txn_token = 1;
            *out_txn = (ninlil_storage_txn_t)&spy->txn_token;
            spy->txn_live = 1;
        } else {
            *out_txn = NULL;
        }
        if (mode == NINLIL_STORAGE_READ_WRITE) {
            spy->mutation_calls += 1u;
        }
        trace_push(spy, NINLIL_SPY_OP_BEGIN, status, mode, 0u, 0u, 0u, 0u, 0u,
            *out_txn != NULL ? 1u : 0u);
        return status;
    }

    if (mode != NINLIL_STORAGE_READ_ONLY) {
        spy->mutation_calls += 1u;
        status = NINLIL_STORAGE_CORRUPT;
        trace_push(spy, NINLIL_SPY_OP_BEGIN, status, mode, 0u, 0u, 0u, 0u, 0u, 0u);
        return status;
    }
    spy->txn_token = 1;
    *out_txn = (ninlil_storage_txn_t)&spy->txn_token;
    spy->txn_live = 1;
    spy->iter_position = 0u;
    trace_push(spy, NINLIL_SPY_OP_BEGIN, status, mode, 0u, 0u, 0u, 0u, 0u, 1u);
    return status;
}

static ninlil_storage_status_t spy_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;
    ninlil_spy_fault_t *fault;
    ninlil_storage_status_t status = NINLIL_STORAGE_NOT_FOUND;
    size_t index;
    uint32_t out_length = 0u;
    uint32_t capacity = 0u;
    /* Alternate buffer for REWRITE_DATA_PTR: not the caller's encoded slot. */
    static uint8_t rewrite_alt[256];

    spy->get_calls += 1u;
    if (inout_value != NULL) {
        capacity = inout_value->capacity;
        inout_value->length = 0u;
    }
    if (txn == NULL || inout_value == NULL || !spy->txn_live
        || (key.length > 0u && key.data == NULL)
        || (inout_value->capacity > 0u && inout_value->data == NULL)) {
        status = NINLIL_STORAGE_CORRUPT;
        trace_push(spy, NINLIL_SPY_OP_GET, status, 0u, 0u, capacity,
            key.length, 0u, 0u, 0u);
        if (key.data != NULL && key.length > 0u) {
            trace_set_get_key(spy, key.data, key.length);
        }
        return status;
    }

    fault = find_fault(spy, NINLIL_SPY_OP_GET, spy->get_calls);
    if (fault != NULL) {
        fault->used = 1u;
        status = fault->status;
        if (fault->shape == NINLIL_SPY_SHAPE_BTS_LENGTHS) {
            status = NINLIL_STORAGE_BUFFER_TOO_SMALL;
            /* ch12-valid required length may be non-zero; not a second poison. */
            if (fault->value_length != 0u) {
                inout_value->length = fault->value_length;
                out_length = fault->value_length;
            }
        } else if (fault->shape == NINLIL_SPY_SHAPE_NOT_FOUND_POISON) {
            status = NINLIL_STORAGE_NOT_FOUND;
            inout_value->length =
                fault->value_length != 0u ? fault->value_length : 1u;
            out_length = inout_value->length;
        } else if (fault->shape == NINLIL_SPY_SHAPE_OK_BAD_LENGTH) {
            status = NINLIL_STORAGE_OK;
            inout_value->length = capacity + 1u;
            out_length = inout_value->length;
        } else if (fault->shape == NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH) {
            if (status == NINLIL_STORAGE_OK) {
                status = NINLIL_STORAGE_IO_ERROR;
            }
            inout_value->length =
                fault->value_length != 0u ? fault->value_length : 1u;
            out_length = inout_value->length;
        } else if (fault->shape == NINLIL_SPY_SHAPE_OK_NULL) {
            /* OK with length>0 would require NULL data; leave length 0. */
            status = NINLIL_STORAGE_OK;
            inout_value->length = 0u;
            out_length = 0u;
        } else if (fault->shape == NINLIL_SPY_SHAPE_REWRITE_DATA_PTR
            || fault->shape == NINLIL_SPY_SHAPE_REWRITE_CAPACITY) {
            /* Fall through to row lookup, then rewrite descriptor. */
            status = NINLIL_STORAGE_OK;
        } else if (status == NINLIL_STORAGE_OK) {
            /* Natural OK under fault: fall through to row lookup below. */
            fault = NULL;
        } else if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            inout_value->length = 0u;
            out_length = 0u;
            trace_push(spy, NINLIL_SPY_OP_GET, status, 0u, 0u, capacity,
                key.length, out_length, 0u, 0u);
            trace_set_get_key(spy, key.data, key.length);
            return status;
        } else if ((unsigned)status > (unsigned)NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
            /* Unknown status with length 0. */
            inout_value->length = 0u;
            out_length = 0u;
            trace_push(spy, NINLIL_SPY_OP_GET, status, 0u, 0u, capacity,
                key.length, out_length, 0u, 0u);
            trace_set_get_key(spy, key.data, key.length);
            return status;
        } else {
            inout_value->length = 0u;
            out_length = 0u;
        }
        if (fault != NULL
            && fault->shape != NINLIL_SPY_SHAPE_REWRITE_DATA_PTR
            && fault->shape != NINLIL_SPY_SHAPE_REWRITE_CAPACITY
            && !(fault->shape == NINLIL_SPY_SHAPE_NATURAL
                && status == NINLIL_STORAGE_OK)) {
            trace_push(spy, NINLIL_SPY_OP_GET, status, 0u, 0u, capacity,
                key.length, out_length, 0u, 0u);
            trace_set_get_key(spy, key.data, key.length);
            return status;
        }
    }

    for (index = 0u; index < spy->row_count; ++index) {
        const ninlil_spy_row_t *row = &spy->rows[index];
        if (row->key_length == key.length
            && (key.length == 0u
                || memcmp(row->key, key.data, key.length) == 0)) {
            if (fault != NULL
                && fault->shape == NINLIL_SPY_SHAPE_REWRITE_DATA_PTR
                && row->value_length <= sizeof(rewrite_alt)) {
                /*
                 * Leave caller slot completely untouched (preseeded stale valid
                 * bytes remain). Return OK with data redirected to alternate.
                 */
                if (row->value_length != 0u) {
                    (void)memcpy(rewrite_alt, row->value, row->value_length);
                }
                inout_value->data = rewrite_alt;
                inout_value->length = row->value_length;
                out_length = row->value_length;
                status = NINLIL_STORAGE_OK;
            } else if (row->value_length > inout_value->capacity) {
                status = NINLIL_STORAGE_BUFFER_TOO_SMALL;
                inout_value->length = 0u;
                out_length = 0u;
            } else {
                if (row->value_length != 0u) {
                    (void)memcpy(
                        inout_value->data, row->value, row->value_length);
                }
                inout_value->length = row->value_length;
                out_length = row->value_length;
                status = NINLIL_STORAGE_OK;
                if (fault != NULL
                    && fault->shape == NINLIL_SPY_SHAPE_REWRITE_CAPACITY) {
                    /* Bytes written to original slot; capacity rewritten. */
                    inout_value->capacity =
                        capacity == 0u ? 1u : capacity + 1u;
                }
            }
            trace_push(spy, NINLIL_SPY_OP_GET, status, 0u, 0u,
                inout_value->capacity, key.length, out_length, 0u, 0u);
            trace_set_get_key(spy, key.data, key.length);
            return status;
        }
    }

    status = NINLIL_STORAGE_NOT_FOUND;
    inout_value->length = 0u;
    trace_push(spy, NINLIL_SPY_OP_GET, status, 0u, 0u, capacity,
        key.length, 0u, 0u, 0u);
    trace_set_get_key(spy, key.data, key.length);
    return status;
}

static ninlil_storage_status_t spy_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;

    (void)txn;
    (void)key;
    (void)value;
    spy->mutation_calls += 1u;
    trace_push(spy, NINLIL_SPY_OP_PUT, NINLIL_STORAGE_CORRUPT,
        0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return NINLIL_STORAGE_CORRUPT;
}

static ninlil_storage_status_t spy_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;

    (void)txn;
    (void)key;
    spy->mutation_calls += 1u;
    trace_push(spy, NINLIL_SPY_OP_ERASE, NINLIL_STORAGE_CORRUPT,
        0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return NINLIL_STORAGE_CORRUPT;
}

static ninlil_storage_status_t spy_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;
    ninlil_spy_fault_t *fault;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;

    spy->iter_open_calls += 1u;
    if (out_iter != NULL) {
        *out_iter = NULL;
    }
    if (txn == NULL || out_iter == NULL || !spy->txn_live || spy->iter_live) {
        status = NINLIL_STORAGE_CORRUPT;
        trace_push(spy, NINLIL_SPY_OP_ITER_OPEN, status, 0u,
            prefix.length, 0u, 0u, 0u, 0u, 0u);
        return status;
    }

    fault = find_fault(spy, NINLIL_SPY_OP_ITER_OPEN, spy->iter_open_calls);
    if (fault != NULL) {
        fault->used = 1u;
        status = fault->status;
        if (fault->shape == NINLIL_SPY_SHAPE_OK_NULL) {
            *out_iter = NULL;
            status = NINLIL_STORAGE_OK;
        } else if (fault->shape == NINLIL_SPY_SHAPE_ERROR_WITH_HANDLE) {
            spy->iter_token = 1;
            *out_iter = (ninlil_storage_iter_t)&spy->iter_token;
            spy->iter_live = 1;
            if (status == NINLIL_STORAGE_OK) {
                status = NINLIL_STORAGE_IO_ERROR;
            }
        } else if (status == NINLIL_STORAGE_OK) {
            if (prefix.data != NULL || prefix.length != 0u) {
                status = NINLIL_STORAGE_CORRUPT;
                *out_iter = NULL;
            } else {
                spy->iter_token = 1;
                *out_iter = (ninlil_storage_iter_t)&spy->iter_token;
                spy->iter_live = 1;
                spy->iter_position = 0u;
            }
        } else {
            *out_iter = NULL;
        }
        trace_push(spy, NINLIL_SPY_OP_ITER_OPEN, status, 0u,
            prefix.length, 0u, 0u, 0u, 0u,
            *out_iter != NULL ? 1u : 0u);
        return status;
    }

    if (prefix.data != NULL || prefix.length != 0u) {
        status = NINLIL_STORAGE_CORRUPT;
        trace_push(spy, NINLIL_SPY_OP_ITER_OPEN, status, 0u,
            prefix.length, 0u, 0u, 0u, 0u, 0u);
        return status;
    }
    spy->iter_token = 1;
    *out_iter = (ninlil_storage_iter_t)&spy->iter_token;
    spy->iter_live = 1;
    spy->iter_position = 0u;
    trace_push(spy, NINLIL_SPY_OP_ITER_OPEN, status, 0u,
        prefix.length, 0u, 0u, 0u, 0u, 1u);
    return status;
}

static ninlil_storage_status_t spy_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;
    ninlil_spy_fault_t *fault;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;
    uint32_t key_cap = 0u;
    uint32_t value_cap = 0u;
    /* Alternate buffers for REWRITE_DATA_PTR (not caller workspace scratch). */
    static uint8_t iter_rewrite_key_alt[NINLIL_SPY_MAX_KEY];
    static uint8_t iter_rewrite_value_alt[256];

    spy->iter_next_calls += 1u;
    if (inout_key != NULL) {
        key_cap = inout_key->capacity;
        inout_key->length = 0u;
    }
    if (inout_value != NULL) {
        value_cap = inout_value->capacity;
        inout_value->length = 0u;
    }
    if (iter == NULL || !spy->iter_live || inout_key == NULL
        || inout_value == NULL || inout_key->data == NULL
        || inout_value->data == NULL) {
        status = NINLIL_STORAGE_CORRUPT;
        trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
            key_cap, value_cap, 0u, 0u, 0u);
        return status;
    }

    fault = find_fault(spy, NINLIL_SPY_OP_ITER_NEXT, spy->iter_next_calls);
    if (fault != NULL) {
        fault->used = 1u;
        status = fault->status;
        if (fault->shape == NINLIL_SPY_SHAPE_EARLY_END) {
            /* Clean terminal NOT_FOUND even if natural rows remain. */
            inout_key->length = 0u;
            inout_value->length = 0u;
            status = NINLIL_STORAGE_NOT_FOUND;
            trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
                key_cap, value_cap, 0u, 0u, 0u);
            return status;
        }
        if (fault->shape == NINLIL_SPY_SHAPE_BTS_LENGTHS) {
            inout_key->length = fault->key_length;
            inout_value->length = fault->value_length;
            status = NINLIL_STORAGE_BUFFER_TOO_SMALL;
        } else if (fault->shape == NINLIL_SPY_SHAPE_NOT_FOUND_POISON) {
            inout_key->length = fault->key_length;
            inout_value->length = fault->value_length;
            status = NINLIL_STORAGE_NOT_FOUND;
        } else if (fault->shape == NINLIL_SPY_SHAPE_OK_BAD_LENGTH) {
            inout_key->length = fault->key_length;
            inout_value->length = fault->value_length;
            status = NINLIL_STORAGE_OK;
        } else if (fault->shape == NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH) {
            inout_key->length = fault->key_length;
            inout_value->length = fault->value_length;
            if (status == NINLIL_STORAGE_OK) {
                status = NINLIL_STORAGE_IO_ERROR;
            }
        } else if (fault->shape == NINLIL_SPY_SHAPE_VALUE_MISMATCH
            || fault->shape == NINLIL_SPY_SHAPE_REWRITE_DATA_PTR
            || fault->shape == NINLIL_SPY_SHAPE_REWRITE_CAPACITY) {
            /* Fall through to natural row, then apply shape. */
            status = NINLIL_STORAGE_OK;
        } else if (status == NINLIL_STORAGE_OK) {
            /* fall through to natural if status OK without special shape */
            fault = NULL;
        } else {
            inout_key->length = 0u;
            inout_value->length = 0u;
            trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
                key_cap, value_cap, 0u, 0u, 0u);
            return status;
        }
        if (fault != NULL
            && fault->shape != NINLIL_SPY_SHAPE_VALUE_MISMATCH
            && fault->shape != NINLIL_SPY_SHAPE_REWRITE_DATA_PTR
            && fault->shape != NINLIL_SPY_SHAPE_REWRITE_CAPACITY
            && fault->shape != NINLIL_SPY_SHAPE_NATURAL) {
            trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
                key_cap, value_cap, inout_key->length, inout_value->length, 0u);
            return status;
        }
    }

    if (spy->iter_position >= spy->row_count) {
        status = NINLIL_STORAGE_NOT_FOUND;
        inout_key->length = 0u;
        inout_value->length = 0u;
        trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
            key_cap, value_cap, 0u, 0u, 0u);
        return status;
    }

    {
        const ninlil_spy_row_t *row = &spy->rows[spy->iter_position];
        if (row->key_length > inout_key->capacity
            || row->value_length > inout_value->capacity) {
            inout_key->length = row->key_length;
            inout_value->length = row->value_length;
            status = NINLIL_STORAGE_BUFFER_TOO_SMALL;
            trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
                key_cap, value_cap, inout_key->length, inout_value->length, 0u);
            return status;
        }

        if (fault != NULL
            && fault->shape == NINLIL_SPY_SHAPE_REWRITE_DATA_PTR) {
            /*
             * Leave caller workspace scratch untouched (may hold preseed).
             * Redirect both data pointers to spy-owned alternate buffers.
             */
            if (row->key_length != 0u) {
                (void)memcpy(
                    iter_rewrite_key_alt, row->key, row->key_length);
            }
            if (row->value_length != 0u
                && row->value_length <= sizeof(iter_rewrite_value_alt)) {
                (void)memcpy(
                    iter_rewrite_value_alt, row->value, row->value_length);
            }
            inout_key->data = iter_rewrite_key_alt;
            inout_key->length = row->key_length;
            inout_value->data = iter_rewrite_value_alt;
            inout_value->length = row->value_length;
            spy->iter_position += 1u;
            status = NINLIL_STORAGE_OK;
            trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
                key_cap, value_cap, inout_key->length, inout_value->length, 0u);
            return status;
        }

        (void)memcpy(inout_key->data, row->key, row->key_length);
        inout_key->length = row->key_length;
        (void)memcpy(inout_value->data, row->value, row->value_length);
        inout_value->length = row->value_length;
        if (fault != NULL
            && fault->shape == NINLIL_SPY_SHAPE_VALUE_MISMATCH
            && row->value_length > 0u) {
            /* Differ from retained get bytes without changing shared rows. */
            inout_value->data[row->value_length - 1u] ^= 0x5Au;
        }
        if (fault != NULL
            && fault->shape == NINLIL_SPY_SHAPE_REWRITE_CAPACITY) {
            inout_key->capacity = key_cap == 0u ? 1u : key_cap + 1u;
            inout_value->capacity = value_cap == 0u ? 1u : value_cap + 1u;
        }
        spy->iter_position += 1u;
        status = NINLIL_STORAGE_OK;
        trace_push(spy, NINLIL_SPY_OP_ITER_NEXT, status, 0u, 0u,
            inout_key->capacity, inout_value->capacity, inout_key->length,
            inout_value->length, 0u);
        return status;
    }
}

static void spy_iter_close(void *user, ninlil_storage_iter_t iter)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;

    (void)iter;
    spy->iter_close_calls += 1u;
    spy->iter_live = 0;
    spy->iter_token = 0;
    trace_push(spy, NINLIL_SPY_OP_ITER_CLOSE, NINLIL_STORAGE_OK,
        0u, 0u, 0u, 0u, 0u, 0u, 0u);
}

static ninlil_storage_status_t spy_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;

    (void)handle;
    if (out_capacity != NULL) {
        (void)memset(out_capacity, 0, sizeof(*out_capacity));
    }
    trace_push(spy, NINLIL_SPY_OP_CAPACITY, NINLIL_STORAGE_UNSUPPORTED_SCHEMA,
        0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}

static ninlil_storage_status_t spy_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;

    (void)txn;
    (void)durability;
    spy->mutation_calls += 1u;
    trace_push(spy, NINLIL_SPY_OP_COMMIT, NINLIL_STORAGE_CORRUPT,
        0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return NINLIL_STORAGE_CORRUPT;
}

static ninlil_storage_status_t spy_rollback(
    void *user,
    ninlil_storage_txn_t txn)
{
    ninlil_scripted_storage_spy_t *spy = (ninlil_scripted_storage_spy_t *)user;
    ninlil_spy_fault_t *fault;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;

    spy->rollback_calls += 1u;
    (void)txn;
    fault = find_fault(spy, NINLIL_SPY_OP_ROLLBACK, spy->rollback_calls);
    if (fault != NULL) {
        fault->used = 1u;
        status = fault->status;
    }
    spy->txn_live = 0;
    spy->txn_token = 0;
    /* rollback implicitly consumes remaining children */
    spy->iter_live = 0;
    spy->iter_token = 0;
    trace_push(spy, NINLIL_SPY_OP_ROLLBACK, status, 0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return status;
}

void ninlil_spy_init(ninlil_scripted_storage_spy_t *spy)
{
    if (spy == NULL) {
        return;
    }
    (void)memset(spy, 0, sizeof(*spy));
    spy->ops.abi_version = NINLIL_ABI_VERSION;
    spy->ops.struct_size = (uint16_t)sizeof(spy->ops);
    spy->ops.user = spy;
    spy->ops.open = spy_open;
    spy->ops.close = spy_close;
    spy->ops.begin = spy_begin;
    spy->ops.get = spy_get;
    spy->ops.put = spy_put;
    spy->ops.erase = spy_erase;
    spy->ops.iter_open = spy_iter_open;
    spy->ops.iter_next = spy_iter_next;
    spy->ops.iter_close = spy_iter_close;
    spy->ops.capacity = spy_capacity;
    spy->ops.commit = spy_commit;
    spy->ops.rollback = spy_rollback;
}

int ninlil_spy_add_row(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *key,
    uint32_t key_length,
    const uint8_t *value,
    uint32_t value_length)
{
    ninlil_spy_row_t *row;

    if (spy == NULL || key == NULL || key_length == 0u
        || key_length > NINLIL_SPY_MAX_KEY
        || value_length > NINLIL_SPY_MAX_VALUE
        || (value_length != 0u && value == NULL)
        || spy->row_count >= NINLIL_SPY_MAX_ROWS) {
        return 0;
    }
    row = &spy->rows[spy->row_count++];
    (void)memcpy(row->key, key, key_length);
    row->key_length = key_length;
    if (value_length != 0u) {
        (void)memcpy(row->value, value, value_length);
    }
    row->value_length = value_length;
    return 1;
}

int ninlil_spy_add_fault(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_spy_op_t op,
    uint32_t on_call,
    ninlil_storage_status_t status,
    ninlil_spy_shape_t shape,
    uint32_t key_length,
    uint32_t value_length)
{
    ninlil_spy_fault_t *fault;

    if (spy == NULL || on_call == 0u
        || spy->fault_count >= NINLIL_SPY_MAX_FAULTS) {
        return 0;
    }
    fault = &spy->faults[spy->fault_count++];
    fault->op = op;
    fault->on_call = on_call;
    fault->status = status;
    fault->shape = shape;
    fault->key_length = key_length;
    fault->value_length = value_length;
    fault->used = 0u;
    return 1;
}

const ninlil_storage_ops_t *ninlil_spy_ops(
    ninlil_scripted_storage_spy_t *spy)
{
    return spy == NULL ? NULL : &spy->ops;
}

ninlil_storage_handle_t ninlil_spy_open_handle(
    ninlil_scripted_storage_spy_t *spy)
{
    if (spy == NULL) {
        return NULL;
    }
    spy->handle_live = 1;
    spy->closed = 0;
    spy->handle_token = 1;
    return (ninlil_storage_handle_t)&spy->handle_token;
}

uint64_t ninlil_spy_call_count(
    const ninlil_scripted_storage_spy_t *spy,
    ninlil_spy_op_t op)
{
    if (spy == NULL || op >= NINLIL_SPY_OP_COUNT) {
        return 0u;
    }
    return spy->call_counts[op];
}

int ninlil_spy_assert_no_mutations(const ninlil_scripted_storage_spy_t *spy)
{
    if (spy == NULL) {
        return 0;
    }
    /* get is a read and is not a mutation (S2 profiled begin requires gets). */
    return spy->mutation_calls == 0u
        && spy->call_counts[NINLIL_SPY_OP_PUT] == 0u
        && spy->call_counts[NINLIL_SPY_OP_ERASE] == 0u
        && spy->call_counts[NINLIL_SPY_OP_COMMIT] == 0u
        && spy->allocator_calls == 0u;
}

uint32_t ninlil_spy_close_count_for_handle(
    const ninlil_scripted_storage_spy_t *spy,
    ninlil_storage_handle_t handle)
{
    uint32_t index;
    uint32_t count = 0u;

    if (spy == NULL) {
        return 0u;
    }
    for (index = 0u; index < spy->closed_handle_count; ++index) {
        if (spy->closed_handles[index] == handle) {
            count += 1u;
        }
    }
    return count;
}

int ninlil_spy_iter_close_before_rollback(
    const ninlil_scripted_storage_spy_t *spy)
{
    size_t index;
    int iter_live = 0;

    if (spy == NULL) {
        return 0;
    }
    for (index = 0u; index < spy->trace_count; ++index) {
        ninlil_spy_op_t op = spy->trace[index].op;
        if (op == NINLIL_SPY_OP_ITER_OPEN
            && spy->trace[index].produced_handle != 0u) {
            iter_live = 1;
        } else if (op == NINLIL_SPY_OP_ITER_CLOSE) {
            iter_live = 0;
        } else if (op == NINLIL_SPY_OP_ROLLBACK) {
            if (iter_live != 0) {
                return 0;
            }
        }
    }
    return 1;
}
