/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_host_store.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define HOST_VALUE_POOL_BYTES \
    ((uint32_t)(NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX - \
                NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES))
#define HOST_STAGING_VALUE_POOL_BYTES \
    ((uint32_t)(NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX - \
                NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES))

typedef struct host_row {
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t value_offset;
    uint32_t value_len;
} host_row_t;

typedef struct host_bank {
    host_row_t rows[NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX];
    uint8_t value_pool[HOST_VALUE_POOL_BYTES];
    uint64_t logical_bytes;
    uint32_t value_pool_used;
    uint32_t row_count;
} host_bank_t;

typedef struct host_op {
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t value_offset;
    uint32_t value_len;
    uint8_t kind; /* 1=put, 2=erase */
} host_op_t;

typedef struct host_fault {
    ninlil_storage_status_t status;
    ninlil_mfdt_v1_host_store_commit_truth_t commit_truth;
    uint8_t armed;
} host_fault_t;

struct ninlil_mfdt_v1_host_store {
    ninlil_storage_ops_t typed_ops;
    host_bank_t banks[2];
    host_op_t staged[NINLIL_MFDT_V1_HOST_FULL_OPS_MAX];
    uint8_t staging_value_pool[HOST_STAGING_VALUE_POOL_BYTES];
    host_fault_t faults[NINLIL_MFDT_V1_HOST_STORE_OP_COUNT];
    uint64_t call_counts[NINLIL_MFDT_V1_HOST_STORE_OP_COUNT];
    uint64_t generation;
    uint64_t full_count;
    uint64_t staged_logical_bytes;
    uint32_t staging_value_pool_used;
    uint8_t active_bank;
    uint8_t leased;
    uint8_t txn_open;
    uint8_t txn_mode;
    uint8_t txn_poisoned;
    uint8_t staged_count;
    uint8_t staged_put_images;
    uint8_t snapshot_bank;
    uint8_t iter_open;
    uint8_t iter_position;
    uint8_t iter_prefix_len;
    uint8_t iter_prefix[NINLIL_MFDT_V1_KEY_BYTES];
    ninlil_storage_status_t txn_poison_status;
    uint64_t txn_token;
    uint64_t iter_token;
};

static const uint8_t g_host_namespace[] = {
    'N', 'M', '3', 'H', 'O', 'S', 'T', '1'
};

static const ninlil_mfdt_v1_store_guarantees_t g_host_guarantees = {
    sizeof(ninlil_mfdt_v1_store_guarantees_t),
    NINLIL_MFDT_V1_STORE_REQUIRED_FLAGS,
    NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX,
    NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX,
    NINLIL_MFDT_V1_HOST_FULL_OPS_MAX,
    0u,
    NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX,
    NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX,
    NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX
};

static ninlil_storage_status_t host_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle);
static void host_close(void *user, ninlil_storage_handle_t handle);
static ninlil_storage_status_t host_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn);
static ninlil_storage_status_t host_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value);
static ninlil_storage_status_t host_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);
static ninlil_storage_status_t host_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key);
static ninlil_storage_status_t host_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter);
static ninlil_storage_status_t host_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value);
static void host_iter_close(void *user, ninlil_storage_iter_t iter);
static ninlil_storage_status_t host_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity);
static ninlil_storage_status_t host_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability);
static ninlil_storage_status_t host_rollback(
    void *user,
    ninlil_storage_txn_t txn);

static void record_call(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_host_store_operation_t operation)
{
    if (operation >= NINLIL_MFDT_V1_HOST_STORE_OP_OPEN
        && operation < NINLIL_MFDT_V1_HOST_STORE_OP_COUNT
        && store->call_counts[operation] != UINT64_MAX) {
        store->call_counts[operation] += 1u;
    }
}

static int consume_fault(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_host_store_operation_t operation,
    host_fault_t *out)
{
    host_fault_t *fault = &store->faults[operation];

    if (fault->armed == 0u) {
        return 0;
    }
    *out = *fault;
    (void)memset(fault, 0, sizeof(*fault));
    return 1;
}

static int bytes_view_valid(
    ninlil_bytes_view_t view,
    uint32_t minimum,
    uint32_t maximum)
{
    if (view.length < minimum || view.length > maximum) {
        return 0;
    }
    return view.length == 0u ? view.data == NULL : view.data != NULL;
}

static int mut_bytes_valid(const ninlil_mut_bytes_t *value)
{
    if (value == NULL || value->length != 0u) {
        return 0;
    }
    return value->capacity == 0u
        ? value->data == NULL : value->data != NULL;
}

static int mutable_ranges_separate(
    const ninlil_mut_bytes_t *left,
    const ninlil_mut_bytes_t *right)
{
    uintptr_t left_start;
    uintptr_t right_start;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left->capacity == 0u || right->capacity == 0u) {
        return 1;
    }
    left_start = (uintptr_t)left->data;
    right_start = (uintptr_t)right->data;
    if ((uintptr_t)left->capacity > UINTPTR_MAX - left_start
        || (uintptr_t)right->capacity > UINTPTR_MAX - right_start) {
        return 0;
    }
    left_end = left_start + (uintptr_t)left->capacity;
    right_end = right_start + (uintptr_t)right->capacity;
    return left_end <= right_start || right_end <= left_start;
}

static int key_compare(
    const uint8_t left[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t right[NINLIL_MFDT_V1_KEY_BYTES])
{
    return memcmp(left, right, NINLIL_MFDT_V1_KEY_BYTES);
}

static void sort_bank_rows(host_bank_t *bank)
{
    uint32_t index;

    /*
     * The reference provider promises fixed operational memory. Do not rely
     * on an implementation-defined qsort() scratch allocation for 32 rows.
     */
    for (index = 1u; index < bank->row_count; ++index) {
        host_row_t moving = bank->rows[index];
        uint32_t position = index;

        while (position > 0u &&
               key_compare(bank->rows[position - 1u].key, moving.key) > 0) {
            bank->rows[position] = bank->rows[position - 1u];
            position -= 1u;
        }
        bank->rows[position] = moving;
    }
}

static int bank_find(
    const host_bank_t *bank,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES])
{
    uint32_t index;

    for (index = 0u; index < bank->row_count; ++index) {
        if (key_compare(bank->rows[index].key, key) == 0) {
            return (int)index;
        }
    }
    return -1;
}

static int staged_find(
    const ninlil_mfdt_v1_host_store_t *store,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES])
{
    uint8_t index;

    for (index = 0u; index < store->staged_count; ++index) {
        if (key_compare(store->staged[index].key, key) == 0) {
            return (int)index;
        }
    }
    return -1;
}

static uint64_t row_logical(uint32_t value_len)
{
    return (uint64_t)value_len
        + NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES;
}

static void reset_transaction(ninlil_mfdt_v1_host_store_t *store)
{
    (void)memset(store->staged, 0, sizeof(store->staged));
    (void)memset(
        store->staging_value_pool,
        0,
        store->staging_value_pool_used);
    store->staged_logical_bytes = 0u;
    store->staging_value_pool_used = 0u;
    store->txn_open = 0u;
    store->txn_mode = 0u;
    store->txn_poisoned = 0u;
    store->staged_count = 0u;
    store->staged_put_images = 0u;
    store->snapshot_bank = 0u;
    store->txn_poison_status = NINLIL_STORAGE_OK;
    store->iter_open = 0u;
    store->iter_position = 0u;
    store->iter_prefix_len = 0u;
    (void)memset(store->iter_prefix, 0, sizeof(store->iter_prefix));
}

static ninlil_storage_status_t poison_transaction(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_storage_status_t status)
{
    if (store->txn_poisoned == 0u) {
        store->txn_poisoned = 1u;
        store->txn_poison_status = status;
    }
    return status;
}

static int bank_add(
    host_bank_t *bank,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len)
{
    host_row_t *row;

    if (bank->row_count >= NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX
        || value_len > HOST_VALUE_POOL_BYTES - bank->value_pool_used) {
        return 0;
    }
    row = &bank->rows[bank->row_count];
    (void)memcpy(row->key, key, NINLIL_MFDT_V1_KEY_BYTES);
    row->value_offset = bank->value_pool_used;
    row->value_len = value_len;
    if (value_len != 0u) {
        (void)memcpy(
            bank->value_pool + bank->value_pool_used,
            value,
            value_len);
    }
    bank->value_pool_used += value_len;
    bank->logical_bytes += row_logical(value_len);
    bank->row_count += 1u;
    return 1;
}

static int final_view_preflight(
    const ninlil_mfdt_v1_host_store_t *store,
    uint32_t *row_count_out,
    uint64_t *logical_bytes_out)
{
    const host_bank_t *active = &store->banks[store->active_bank];
    uint32_t row_count = active->row_count;
    uint64_t logical_bytes = active->logical_bytes;
    uint8_t index;

    for (index = 0u; index < store->staged_count; ++index) {
        const host_op_t *op = &store->staged[index];
        int old_index = bank_find(active, op->key);

        if (op->kind == 1u) {
            if (old_index >= 0) {
                uint64_t old_charge =
                    row_logical(active->rows[old_index].value_len);
                if (logical_bytes < old_charge) {
                    return 0;
                }
                logical_bytes -= old_charge;
            } else {
                if (row_count == UINT32_MAX) {
                    return 0;
                }
                row_count += 1u;
            }
            if (logical_bytes > UINT64_MAX - row_logical(op->value_len)) {
                return 0;
            }
            logical_bytes += row_logical(op->value_len);
        } else if (op->kind == 2u) {
            if (old_index >= 0) {
                uint64_t old_charge =
                    row_logical(active->rows[old_index].value_len);
                if (row_count == 0u || logical_bytes < old_charge) {
                    return 0;
                }
                row_count -= 1u;
                logical_bytes -= old_charge;
            }
        } else {
            return 0;
        }
    }
    if (row_count > NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX
        || logical_bytes
            > NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX) {
        return 0;
    }
    *row_count_out = row_count;
    *logical_bytes_out = logical_bytes;
    return 1;
}

static int build_final_bank(
    ninlil_mfdt_v1_host_store_t *store,
    uint8_t destination_index,
    uint32_t expected_rows,
    uint64_t expected_logical)
{
    const host_bank_t *active = &store->banks[store->active_bank];
    host_bank_t *destination = &store->banks[destination_index];
    uint32_t index;
    uint8_t op_index;

    (void)memset(destination, 0, sizeof(*destination));
    for (index = 0u; index < active->row_count; ++index) {
        const host_row_t *row = &active->rows[index];
        int staged_index = staged_find(store, row->key);
        const uint8_t *value = active->value_pool + row->value_offset;
        uint32_t value_len = row->value_len;

        if (staged_index >= 0) {
            const host_op_t *op = &store->staged[staged_index];
            if (op->kind == 2u) {
                continue;
            }
            value = store->staging_value_pool + op->value_offset;
            value_len = op->value_len;
        }
        if (!bank_add(destination, row->key, value, value_len)) {
            return 0;
        }
    }
    for (op_index = 0u; op_index < store->staged_count; ++op_index) {
        const host_op_t *op = &store->staged[op_index];
        if (op->kind != 1u || bank_find(active, op->key) >= 0) {
            continue;
        }
        if (!bank_add(
                destination,
                op->key,
                store->staging_value_pool + op->value_offset,
                op->value_len)) {
            return 0;
        }
    }
    sort_bank_rows(destination);
    return destination->row_count == expected_rows
        && destination->logical_bytes == expected_logical;
}

static int prefix_matches(
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *prefix,
    uint8_t prefix_len)
{
    return prefix_len == 0u
        || memcmp(key, prefix, prefix_len) == 0;
}

ninlil_mfdt_v1_host_store_t *ninlil_mfdt_v1_host_store_create(void)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)calloc(1u, sizeof(*store));

    if (store == NULL) {
        return NULL;
    }
    store->typed_ops.abi_version = NINLIL_ABI_VERSION;
    store->typed_ops.struct_size = (uint16_t)sizeof(store->typed_ops);
    store->typed_ops.user = store;
    store->typed_ops.open = host_open;
    store->typed_ops.close = host_close;
    store->typed_ops.begin = host_begin;
    store->typed_ops.get = host_get;
    store->typed_ops.put = host_put;
    store->typed_ops.erase = host_erase;
    store->typed_ops.iter_open = host_iter_open;
    store->typed_ops.iter_next = host_iter_next;
    store->typed_ops.iter_close = host_iter_close;
    store->typed_ops.capacity = host_capacity;
    store->typed_ops.commit = host_commit;
    store->typed_ops.rollback = host_rollback;
    store->generation = 1u;
    store->txn_token = UINT64_C(0x4e4d33484f535431);
    store->iter_token = UINT64_C(0x4e4d334954455231);
    return store;
}

void ninlil_mfdt_v1_host_store_destroy(
    ninlil_mfdt_v1_host_store_t *store)
{
    if (store == NULL) {
        return;
    }
    (void)memset(store, 0, sizeof(*store));
    free(store);
}

const ninlil_storage_ops_t *ninlil_mfdt_v1_host_store_ops(
    ninlil_mfdt_v1_host_store_t *store)
{
    return store == NULL ? NULL : &store->typed_ops;
}

const ninlil_mfdt_v1_store_guarantees_t *
ninlil_mfdt_v1_host_store_guarantees(void)
{
    return &g_host_guarantees;
}

int ninlil_mfdt_v1_host_store_open_port(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_store_port_t *port)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_bytes_view_t storage_namespace;
    ninlil_storage_status_t status;
    int rc;

    if (store == NULL || port == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    storage_namespace.data = g_host_namespace;
    storage_namespace.length = (uint32_t)sizeof(g_host_namespace);
    status = store->typed_ops.open(
        store,
        storage_namespace,
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(status);
    }
    rc = ninlil_mfdt_v1_store_port_init(
        port,
        &store->typed_ops,
        handle,
        &g_host_guarantees);
    if (rc != NINLIL_MFDT_V1_OK) {
        store->typed_ops.close(store, handle);
    }
    return rc;
}

void ninlil_mfdt_v1_host_store_close_port(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_store_port_t *port)
{
    if (store == NULL || port == NULL
        || port->ops != &store->typed_ops
        || port->handle != (ninlil_storage_handle_t)store) {
        return;
    }
    if (port->full_open != 0u) {
        (void)ninlil_mfdt_v1_store_full_rollback(port);
    }
    /*
     * Snapshot owners must close through snapshot_end; fail-close a leaked
     * private snapshot at provider close as the typed close contract allows.
     */
    store->typed_ops.close(store, port->handle);
    (void)memset(port, 0, sizeof(*port));
}

int ninlil_mfdt_v1_host_store_fault_next(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_host_store_operation_t operation,
    ninlil_storage_status_t status,
    ninlil_mfdt_v1_host_store_commit_truth_t commit_truth)
{
    host_fault_t *fault;

    if (store == NULL
        || operation < NINLIL_MFDT_V1_HOST_STORE_OP_OPEN
        || operation >= NINLIL_MFDT_V1_HOST_STORE_OP_COUNT
        || status == NINLIL_STORAGE_OK
        || status == NINLIL_STORAGE_NOT_FOUND
        || status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        return 0;
    }
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        if (operation != NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT
            || (commit_truth != NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_OLD
                && commit_truth
                    != NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NEW)) {
            return 0;
        }
    } else if (commit_truth != NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NONE) {
        return 0;
    }
    fault = &store->faults[operation];
    if (fault->armed != 0u) {
        return 0;
    }
    fault->status = status;
    fault->commit_truth = commit_truth;
    fault->armed = 1u;
    return 1;
}

uint64_t ninlil_mfdt_v1_host_store_call_count(
    const ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_host_store_operation_t operation)
{
    if (store == NULL
        || operation < NINLIL_MFDT_V1_HOST_STORE_OP_OPEN
        || operation >= NINLIL_MFDT_V1_HOST_STORE_OP_COUNT) {
        return 0u;
    }
    return store->call_counts[operation];
}

int ninlil_mfdt_v1_host_store_inventory(
    const ninlil_mfdt_v1_host_store_t *store,
    uint32_t *committed_keys_out,
    uint64_t *committed_logical_bytes_out,
    uint64_t *generation_out,
    uint64_t *full_count_out)
{
    const host_bank_t *active;

    if (store == NULL || committed_keys_out == NULL
        || committed_logical_bytes_out == NULL || generation_out == NULL
        || full_count_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    active = &store->banks[store->active_bank];
    *committed_keys_out = active->row_count;
    *committed_logical_bytes_out = active->logical_bytes;
    *generation_out = store->generation;
    *full_count_out = store->full_count;
    return NINLIL_MFDT_V1_OK;
}

static ninlil_storage_status_t host_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    host_fault_t fault;

    if (store == NULL || out_handle == NULL || *out_handle != NULL
        || !bytes_view_valid(
            storage_namespace,
            (uint32_t)sizeof(g_host_namespace),
            (uint32_t)sizeof(g_host_namespace))
        || memcmp(
            storage_namespace.data,
            g_host_namespace,
            sizeof(g_host_namespace)) != 0) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_OPEN);
    if (expected_schema != NINLIL_STORAGE_SCHEMA_M1A) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_OPEN,
            &fault)) {
        return fault.status;
    }
    if (store->leased != 0u) {
        return NINLIL_STORAGE_BUSY;
    }
    store->leased = 1u;
    *out_handle = (ninlil_storage_handle_t)store;
    return NINLIL_STORAGE_OK;
}

static void host_close(void *user, ninlil_storage_handle_t handle)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;

    if (store == NULL || handle != (ninlil_storage_handle_t)store
        || store->leased == 0u) {
        return;
    }
    reset_transaction(store);
    store->leased = 0u;
}

static ninlil_storage_status_t host_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    host_fault_t fault;

    if (store == NULL || handle != (ninlil_storage_handle_t)store
        || store->leased == 0u || out_txn == NULL || *out_txn != NULL
        || (mode != NINLIL_STORAGE_READ_ONLY
            && mode != NINLIL_STORAGE_READ_WRITE)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_BEGIN);
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_BEGIN,
            &fault)) {
        return fault.status;
    }
    if (store->txn_open != 0u) {
        return NINLIL_STORAGE_BUSY;
    }
    reset_transaction(store);
    store->txn_open = 1u;
    store->txn_mode = (uint8_t)mode;
    store->snapshot_bank = store->active_bank;
    *out_txn = (ninlil_storage_txn_t)&store->txn_token;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t copy_value_out(
    const uint8_t *source,
    uint32_t source_len,
    ninlil_mut_bytes_t *inout_value)
{
    if (source_len > inout_value->capacity) {
        inout_value->length = source_len;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (source_len != 0u) {
        (void)memcpy(inout_value->data, source, source_len);
    }
    inout_value->length = source_len;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t host_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    const host_bank_t *bank;
    host_fault_t fault;
    int index;

    if (store == NULL || txn != (ninlil_storage_txn_t)&store->txn_token
        || store->txn_open == 0u
        || !bytes_view_valid(
            key,
            NINLIL_MFDT_V1_KEY_BYTES,
            NINLIL_MFDT_V1_KEY_BYTES)
        || !mut_bytes_valid(inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_GET);
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_GET,
            &fault)) {
        return fault.status;
    }
    if (store->txn_mode == NINLIL_STORAGE_READ_WRITE) {
        index = staged_find(store, key.data);
        if (index >= 0) {
            const host_op_t *op = &store->staged[index];
            if (op->kind == 2u) {
                return NINLIL_STORAGE_NOT_FOUND;
            }
            return copy_value_out(
                store->staging_value_pool + op->value_offset,
                op->value_len,
                inout_value);
        }
    }
    bank = &store->banks[store->snapshot_bank];
    index = bank_find(bank, key.data);
    if (index < 0) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    return copy_value_out(
        bank->value_pool + bank->rows[index].value_offset,
        bank->rows[index].value_len,
        inout_value);
}

static ninlil_storage_status_t host_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    const host_bank_t *active;
    host_op_t *op;
    host_fault_t fault;
    uint64_t logical;

    if (store == NULL || txn != (ninlil_storage_txn_t)&store->txn_token
        || store->txn_open == 0u
        || store->txn_mode != NINLIL_STORAGE_READ_WRITE
        || !bytes_view_valid(
            key,
            NINLIL_MFDT_V1_KEY_BYTES,
            NINLIL_MFDT_V1_KEY_BYTES)
        || !bytes_view_valid(value, 0u, UINT32_MAX)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_PUT);
    if (store->txn_poisoned != 0u) {
        return store->txn_poison_status;
    }
    if (store->staged_count >= NINLIL_MFDT_V1_HOST_FULL_OPS_MAX
        || store->staged_put_images
            >= NINLIL_MFDT_V1_HOST_FULL_PUT_IMAGES_MAX
        || staged_find(store, key.data) >= 0) {
        return poison_transaction(store, NINLIL_STORAGE_CORRUPT);
    }
    logical = row_logical(value.length);
    active = &store->banks[store->active_bank];
    if (logical > NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX
        || store->staged_logical_bytes
            > NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX - logical
        || active->row_count + store->staged_put_images + 1u
            > NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX
        || active->logical_bytes
            > NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX
                - (store->staged_logical_bytes + logical)
        || value.length
            > HOST_STAGING_VALUE_POOL_BYTES
                - store->staging_value_pool_used) {
        return poison_transaction(store, NINLIL_STORAGE_NO_SPACE);
    }
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_PUT,
            &fault)) {
        return poison_transaction(store, fault.status);
    }
    op = &store->staged[store->staged_count];
    (void)memcpy(op->key, key.data, NINLIL_MFDT_V1_KEY_BYTES);
    op->kind = 1u;
    op->value_offset = store->staging_value_pool_used;
    op->value_len = value.length;
    if (value.length != 0u) {
        (void)memcpy(
            store->staging_value_pool + store->staging_value_pool_used,
            value.data,
            value.length);
    }
    store->staging_value_pool_used += value.length;
    store->staged_logical_bytes += logical;
    store->staged_count += 1u;
    store->staged_put_images += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t host_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    host_op_t *op;
    host_fault_t fault;

    if (store == NULL || txn != (ninlil_storage_txn_t)&store->txn_token
        || store->txn_open == 0u
        || store->txn_mode != NINLIL_STORAGE_READ_WRITE
        || !bytes_view_valid(
            key,
            NINLIL_MFDT_V1_KEY_BYTES,
            NINLIL_MFDT_V1_KEY_BYTES)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_ERASE);
    if (store->txn_poisoned != 0u) {
        return store->txn_poison_status;
    }
    if (store->staged_count >= NINLIL_MFDT_V1_HOST_FULL_OPS_MAX
        || staged_find(store, key.data) >= 0) {
        return poison_transaction(store, NINLIL_STORAGE_CORRUPT);
    }
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_ERASE,
            &fault)) {
        return poison_transaction(store, fault.status);
    }
    op = &store->staged[store->staged_count];
    (void)memcpy(op->key, key.data, NINLIL_MFDT_V1_KEY_BYTES);
    op->kind = 2u;
    store->staged_count += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t host_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    host_fault_t fault;

    if (store == NULL || txn != (ninlil_storage_txn_t)&store->txn_token
        || store->txn_open == 0u
        || store->txn_mode != NINLIL_STORAGE_READ_ONLY
        || out_iter == NULL || *out_iter != NULL
        || !bytes_view_valid(prefix, 0u, NINLIL_MFDT_V1_KEY_BYTES)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_ITER_OPEN);
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_ITER_OPEN,
            &fault)) {
        return fault.status;
    }
    if (store->iter_open != 0u) {
        return NINLIL_STORAGE_BUSY;
    }
    store->iter_open = 1u;
    store->iter_position = 0u;
    store->iter_prefix_len = (uint8_t)prefix.length;
    if (prefix.length != 0u) {
        (void)memcpy(store->iter_prefix, prefix.data, prefix.length);
    }
    *out_iter = (ninlil_storage_iter_t)&store->iter_token;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t host_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    const host_bank_t *bank;
    const host_row_t *row = NULL;
    host_fault_t fault;
    uint32_t position;

    if (store == NULL || iter != (ninlil_storage_iter_t)&store->iter_token
        || store->txn_open == 0u || store->iter_open == 0u
        || !mut_bytes_valid(inout_key) || !mut_bytes_valid(inout_value)
        || !mutable_ranges_separate(inout_key, inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_ITER_NEXT);
    bank = &store->banks[store->snapshot_bank];
    position = store->iter_position;
    while (position < bank->row_count) {
        if (prefix_matches(
                bank->rows[position].key,
                store->iter_prefix,
                store->iter_prefix_len)) {
            row = &bank->rows[position];
            break;
        }
        position += 1u;
    }
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_ITER_NEXT,
            &fault)) {
        return fault.status;
    }
    if (row == NULL) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (inout_key->capacity < NINLIL_MFDT_V1_KEY_BYTES
        || inout_value->capacity < row->value_len) {
        inout_key->length = NINLIL_MFDT_V1_KEY_BYTES;
        inout_value->length = row->value_len;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    (void)memcpy(
        inout_key->data,
        row->key,
        NINLIL_MFDT_V1_KEY_BYTES);
    if (row->value_len != 0u) {
        (void)memcpy(
            inout_value->data,
            bank->value_pool + row->value_offset,
            row->value_len);
    }
    inout_key->length = NINLIL_MFDT_V1_KEY_BYTES;
    inout_value->length = row->value_len;
    store->iter_position = (uint8_t)(position + 1u);
    return NINLIL_STORAGE_OK;
}

static void host_iter_close(void *user, ninlil_storage_iter_t iter)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;

    if (store == NULL || iter != (ninlil_storage_iter_t)&store->iter_token) {
        return;
    }
    store->iter_open = 0u;
    store->iter_position = 0u;
    store->iter_prefix_len = 0u;
    (void)memset(store->iter_prefix, 0, sizeof(store->iter_prefix));
}

static ninlil_storage_status_t host_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    const host_bank_t *active;
    host_fault_t fault;

    if (store == NULL || handle != (ninlil_storage_handle_t)store
        || store->leased == 0u || out_capacity == NULL
        || out_capacity->abi_version != NINLIL_ABI_VERSION
        || out_capacity->struct_size < sizeof(*out_capacity)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_CAPACITY);
    if (consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_CAPACITY,
            &fault)) {
        return fault.status;
    }
    active = &store->banks[store->active_bank];
    out_capacity->max_entries = NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX;
    out_capacity->used_entries = active->row_count;
    out_capacity->max_bytes =
        NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX;
    out_capacity->used_bytes = active->logical_bytes;
    return NINLIL_STORAGE_OK;
}

static void publish_final(
    ninlil_mfdt_v1_host_store_t *store,
    uint8_t destination_index)
{
    store->active_bank = destination_index;
    if (store->generation != UINT64_MAX) {
        store->generation += 1u;
    }
    if (store->full_count != UINT64_MAX) {
        store->full_count += 1u;
    }
}

static ninlil_storage_status_t host_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    host_fault_t fault;
    uint32_t final_rows;
    uint64_t final_logical;
    uint8_t destination_index;
    int has_fault;

    if (store == NULL || txn != (ninlil_storage_txn_t)&store->txn_token
        || store->txn_open == 0u
        || (durability != NINLIL_DURABILITY_VOLATILE
            && durability != NINLIL_DURABILITY_CHECKPOINTED
            && durability != NINLIL_DURABILITY_FULL)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT);
    if (store->txn_mode == NINLIL_STORAGE_READ_ONLY) {
        has_fault = consume_fault(
            store,
            NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
            &fault);
        reset_transaction(store);
        return has_fault ? fault.status : NINLIL_STORAGE_OK;
    }
    if (durability != NINLIL_DURABILITY_FULL) {
        reset_transaction(store);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (store->txn_poisoned != 0u) {
        ninlil_storage_status_t status = store->txn_poison_status;
        reset_transaction(store);
        return status;
    }
    if (store->staged_count == 0u
        || !final_view_preflight(store, &final_rows, &final_logical)) {
        reset_transaction(store);
        return NINLIL_STORAGE_NO_SPACE;
    }
    has_fault = consume_fault(
        store,
        NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
        &fault);
    if (has_fault
        && (fault.status != NINLIL_STORAGE_COMMIT_UNKNOWN
            || fault.commit_truth
                == NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_OLD)) {
        ninlil_storage_status_t status = fault.status;
        reset_transaction(store);
        return status;
    }
    destination_index = (uint8_t)(store->active_bank ^ 1u);
    if (!build_final_bank(
            store,
            destination_index,
            final_rows,
            final_logical)) {
        reset_transaction(store);
        return NINLIL_STORAGE_CORRUPT;
    }
    publish_final(store, destination_index);
    reset_transaction(store);
    return has_fault ? fault.status : NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t host_rollback(
    void *user,
    ninlil_storage_txn_t txn)
{
    ninlil_mfdt_v1_host_store_t *store =
        (ninlil_mfdt_v1_host_store_t *)user;
    host_fault_t fault;
    int has_fault;

    if (store == NULL || txn != (ninlil_storage_txn_t)&store->txn_token
        || store->txn_open == 0u) {
        return NINLIL_STORAGE_CORRUPT;
    }
    record_call(store, NINLIL_MFDT_V1_HOST_STORE_OP_ROLLBACK);
    has_fault = consume_fault(
        store,
        NINLIL_MFDT_V1_HOST_STORE_OP_ROLLBACK,
        &fault);
    reset_transaction(store);
    return has_fault ? fault.status : NINLIL_STORAGE_OK;
}

_Static_assert(
    HOST_VALUE_POOL_BYTES == 384440u,
    "Host committed value pool exact");
_Static_assert(
    HOST_STAGING_VALUE_POOL_BYTES == 50267u,
    "Host serialized FULL staging values exact");
