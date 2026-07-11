#include "in_memory_storage.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct storage_entry {
    uint8_t *key;
    uint32_t key_length;
    uint8_t *value;
    uint32_t value_length;
} storage_entry_t;

typedef struct storage_namespace {
    int in_use;
    uint8_t name[255];
    uint32_t name_length;
    uint32_t schema;
    int leased;
    storage_entry_t *entries;
    size_t entry_count;
} storage_namespace_t;

typedef struct storage_handle storage_handle_t;
typedef struct storage_transaction storage_transaction_t;
typedef struct storage_iterator storage_iterator_t;

struct storage_iterator {
    uint64_t id;
    storage_transaction_t *transaction;
    storage_entry_t *rows;
    size_t row_count;
    size_t position;
    storage_iterator_t *next;
};

struct storage_transaction {
    uint64_t id;
    storage_handle_t *handle;
    ninlil_storage_mode_t mode;
    storage_entry_t *view;
    size_t view_count;
    storage_iterator_t *iterators;
    storage_transaction_t *next;
};

struct storage_handle {
    uint64_t id;
    struct ninlil_test_storage *storage;
    storage_namespace_t *name_space;
    storage_transaction_t *transactions;
    int has_writer;
    storage_handle_t *next;
};

typedef struct storage_fault {
    ninlil_storage_status_t status;
    uint32_t remaining_count;
    int commit_unknown_committed;
} storage_fault_t;

typedef struct storage_fault_queue {
    storage_fault_t entries[NINLIL_TEST_STORAGE_FAULT_QUEUE_CAPACITY];
    size_t head;
    size_t count;
} storage_fault_queue_t;

struct ninlil_test_storage {
    ninlil_storage_ops_t ops;
    ninlil_test_storage_config_t config;
    storage_namespace_t *namespaces;
    storage_handle_t *handles;
    storage_handle_t *retired_handles;
    storage_transaction_t *retired_transactions;
    storage_iterator_t *retired_iterators;
    storage_fault_queue_t faults[NINLIL_TEST_STORAGE_OP_COUNT];
    uint64_t call_counts[NINLIL_TEST_STORAGE_OP_COUNT];
    ninlil_test_storage_trace_record_t
        trace[NINLIL_TEST_STORAGE_TRACE_CAPACITY];
    size_t trace_count;
    int trace_overflowed;
    uint64_t next_trace_sequence;
    uint64_t next_handle_id;
    uint64_t next_transaction_id;
    uint64_t next_iterator_id;
    uint64_t live_handle_count;
    uint64_t live_transaction_count;
    uint64_t live_iterator_count;
};

static ninlil_storage_status_t fixture_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle);
static void fixture_close(void *user, ninlil_storage_handle_t handle);
static ninlil_storage_status_t fixture_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn);
static ninlil_storage_status_t fixture_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value);
static ninlil_storage_status_t fixture_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);
static ninlil_storage_status_t fixture_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key);
static ninlil_storage_status_t fixture_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter);
static ninlil_storage_status_t fixture_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value);
static void fixture_iter_close(void *user, ninlil_storage_iter_t iter);
static ninlil_storage_status_t fixture_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity);
static ninlil_storage_status_t fixture_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability);
static ninlil_storage_status_t fixture_rollback(
    void *user,
    ninlil_storage_txn_t txn);

static int operation_is_valid(ninlil_test_storage_operation_t operation)
{
    return operation >= NINLIL_TEST_STORAGE_OP_OPEN
        && operation < NINLIL_TEST_STORAGE_OP_COUNT;
}

static int operation_returns_status(
    ninlil_test_storage_operation_t operation)
{
    return operation_is_valid(operation)
        && operation != NINLIL_TEST_STORAGE_OP_CLOSE
        && operation != NINLIL_TEST_STORAGE_OP_ITER_CLOSE;
}

static uint64_t next_nonzero_id(uint64_t *next)
{
    uint64_t result = *next;

    if (result == 0u) {
        result = 1u;
    }
    *next = result == UINT64_MAX ? UINT64_MAX : result + 1u;
    return result;
}

static void record_call(
    ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation,
    ninlil_storage_status_t status,
    uint64_t handle_id,
    uint64_t transaction_id,
    uint64_t iterator_id,
    ninlil_durability_t durability)
{
    ninlil_test_storage_trace_record_t *record;

    if (operation_is_valid(operation)) {
        if (storage->call_counts[operation] != UINT64_MAX) {
            storage->call_counts[operation] += 1u;
        }
    }
    if (storage->trace_count >= NINLIL_TEST_STORAGE_TRACE_CAPACITY) {
        storage->trace_overflowed = 1;
        return;
    }
    record = &storage->trace[storage->trace_count];
    storage->trace_count += 1u;
    record->sequence = next_nonzero_id(&storage->next_trace_sequence);
    record->operation = operation;
    record->status = status;
    record->handle_id = handle_id;
    record->transaction_id = transaction_id;
    record->iterator_id = iterator_id;
    record->durability = durability;
}

static int view_shape_is_valid(
    ninlil_bytes_view_t view,
    uint32_t minimum,
    uint32_t maximum)
{
    if (view.length < minimum || view.length > maximum) {
        return 0;
    }
    if (view.length == 0u) {
        return view.data == NULL;
    }
    return view.data != NULL;
}

static int mut_shape_is_valid(const ninlil_mut_bytes_t *value)
{
    if (value == NULL || value->length != 0u) {
        return 0;
    }
    if (value->capacity == 0u) {
        return value->data == NULL;
    }
    return value->data != NULL;
}

static int mut_ranges_do_not_overlap(
    const ninlil_mut_bytes_t *left,
    const ninlil_mut_bytes_t *right)
{
    uintptr_t left_start;
    uintptr_t left_end;
    uintptr_t right_start;
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

static int capacity_output_is_valid(const ninlil_storage_capacity_t *capacity)
{
    return capacity != NULL
        && capacity->abi_version == NINLIL_ABI_VERSION
        && capacity->struct_size >= sizeof(*capacity);
}

static int bytes_compare(
    const uint8_t *left,
    uint32_t left_length,
    const uint8_t *right,
    uint32_t right_length)
{
    uint32_t common = left_length < right_length ? left_length : right_length;
    int compared = common == 0u ? 0 : memcmp(left, right, common);

    if (compared != 0) {
        return compared;
    }
    if (left_length < right_length) {
        return -1;
    }
    if (left_length > right_length) {
        return 1;
    }
    return 0;
}

static int entry_compare(const void *left, const void *right)
{
    const storage_entry_t *left_entry = (const storage_entry_t *)left;
    const storage_entry_t *right_entry = (const storage_entry_t *)right;

    return bytes_compare(
        left_entry->key,
        left_entry->key_length,
        right_entry->key,
        right_entry->key_length);
}

static void free_entry(storage_entry_t *entry)
{
    free(entry->key);
    free(entry->value);
    (void)memset(entry, 0, sizeof(*entry));
}

static void free_entries(storage_entry_t *entries, size_t count)
{
    size_t index;

    for (index = 0u; index < count; ++index) {
        free_entry(&entries[index]);
    }
    free(entries);
}

static int copy_bytes(const uint8_t *source, uint32_t length, uint8_t **out)
{
    uint8_t *copy;

    *out = NULL;
    if (length == 0u) {
        return 1;
    }
    copy = (uint8_t *)malloc((size_t)length);
    if (copy == NULL) {
        return 0;
    }
    (void)memcpy(copy, source, length);
    *out = copy;
    return 1;
}

static int clone_entries(
    const storage_entry_t *source,
    size_t count,
    storage_entry_t **out)
{
    storage_entry_t *copy;
    size_t index;

    *out = NULL;
    if (count == 0u) {
        return 1;
    }
    if (count > SIZE_MAX / sizeof(*copy)) {
        return 0;
    }
    copy = (storage_entry_t *)calloc(count, sizeof(*copy));
    if (copy == NULL) {
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        copy[index].key_length = source[index].key_length;
        copy[index].value_length = source[index].value_length;
        if (!copy_bytes(
                source[index].key,
                source[index].key_length,
                &copy[index].key)
            || !copy_bytes(
                source[index].value,
                source[index].value_length,
                &copy[index].value)) {
            free_entries(copy, count);
            return 0;
        }
    }
    *out = copy;
    return 1;
}

static size_t find_entry(
    const storage_entry_t *entries,
    size_t count,
    ninlil_bytes_view_t key,
    int *found)
{
    size_t low = 0u;
    size_t high = count;

    while (low < high) {
        size_t middle = low + ((high - low) / 2u);
        int compared = bytes_compare(
            entries[middle].key,
            entries[middle].key_length,
            key.data,
            key.length);

        if (compared < 0) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    *found = low < count
        && bytes_compare(
            entries[low].key,
            entries[low].key_length,
            key.data,
            key.length) == 0;
    return low;
}

static storage_handle_t *find_handle(
    ninlil_test_storage_t *storage,
    ninlil_storage_handle_t opaque)
{
    storage_handle_t *handle = storage->handles;

    while (handle != NULL) {
        if ((ninlil_storage_handle_t)handle == opaque) {
            return handle;
        }
        handle = handle->next;
    }
    return NULL;
}

static storage_transaction_t *find_transaction(
    ninlil_test_storage_t *storage,
    ninlil_storage_txn_t opaque)
{
    storage_handle_t *handle = storage->handles;

    while (handle != NULL) {
        storage_transaction_t *transaction = handle->transactions;
        while (transaction != NULL) {
            if ((ninlil_storage_txn_t)transaction == opaque) {
                return transaction;
            }
            transaction = transaction->next;
        }
        handle = handle->next;
    }
    return NULL;
}

static storage_iterator_t *find_iterator(
    ninlil_test_storage_t *storage,
    ninlil_storage_iter_t opaque)
{
    storage_handle_t *handle = storage->handles;

    while (handle != NULL) {
        storage_transaction_t *transaction = handle->transactions;
        while (transaction != NULL) {
            storage_iterator_t *iterator = transaction->iterators;
            while (iterator != NULL) {
                if ((ninlil_storage_iter_t)iterator == opaque) {
                    return iterator;
                }
                iterator = iterator->next;
            }
            transaction = transaction->next;
        }
        handle = handle->next;
    }
    return NULL;
}

static void retire_iterator(
    ninlil_test_storage_t *storage,
    storage_iterator_t *iterator)
{
    free_entries(iterator->rows, iterator->row_count);
    iterator->rows = NULL;
    iterator->row_count = 0u;
    iterator->position = 0u;
    iterator->next = storage->retired_iterators;
    storage->retired_iterators = iterator;
    storage->live_iterator_count -= 1u;
}

static void consume_iterators(
    ninlil_test_storage_t *storage,
    storage_transaction_t *transaction)
{
    storage_iterator_t *iterator = transaction->iterators;

    transaction->iterators = NULL;
    while (iterator != NULL) {
        storage_iterator_t *next = iterator->next;
        retire_iterator(storage, iterator);
        iterator = next;
    }
}

static void unlink_transaction(
    storage_handle_t *handle,
    storage_transaction_t *transaction)
{
    storage_transaction_t **link = &handle->transactions;

    while (*link != NULL && *link != transaction) {
        link = &(*link)->next;
    }
    if (*link == transaction) {
        *link = transaction->next;
    }
}

static void destroy_transaction(
    ninlil_test_storage_t *storage,
    storage_transaction_t *transaction,
    int keep_view)
{
    storage_handle_t *handle = transaction->handle;

    consume_iterators(storage, transaction);
    unlink_transaction(handle, transaction);
    if (transaction->mode == NINLIL_STORAGE_READ_WRITE) {
        handle->has_writer = 0;
    }
    if (!keep_view) {
        free_entries(transaction->view, transaction->view_count);
    }
    transaction->next = storage->retired_transactions;
    storage->retired_transactions = transaction;
    storage->live_transaction_count -= 1u;
}

static int take_fault(
    ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation,
    storage_fault_t *out)
{
    storage_fault_queue_t *queue = &storage->faults[operation];
    storage_fault_t *fault;

    if (queue->count == 0u) {
        return 0;
    }
    fault = &queue->entries[queue->head];
    *out = *fault;
    fault->remaining_count -= 1u;
    if (fault->remaining_count == 0u) {
        queue->head = (queue->head + 1u)
            % NINLIL_TEST_STORAGE_FAULT_QUEUE_CAPACITY;
        queue->count -= 1u;
    }
    return 1;
}

static storage_namespace_t *find_namespace(
    ninlil_test_storage_t *storage,
    ninlil_bytes_view_t name)
{
    uint32_t index;

    for (index = 0u; index < storage->config.max_namespaces; ++index) {
        storage_namespace_t *candidate = &storage->namespaces[index];
        if (candidate->in_use
            && candidate->name_length == name.length
            && memcmp(candidate->name, name.data, name.length) == 0) {
            return candidate;
        }
    }
    return NULL;
}

static storage_namespace_t *create_namespace(
    ninlil_test_storage_t *storage,
    ninlil_bytes_view_t name,
    uint32_t schema)
{
    uint32_t index;

    for (index = 0u; index < storage->config.max_namespaces; ++index) {
        storage_namespace_t *candidate = &storage->namespaces[index];
        if (!candidate->in_use) {
            candidate->in_use = 1;
            candidate->name_length = name.length;
            candidate->schema = schema;
            (void)memcpy(candidate->name, name.data, name.length);
            return candidate;
        }
    }
    return NULL;
}

static int logical_usage(
    const storage_entry_t *entries,
    size_t count,
    uint64_t *out_entries,
    uint64_t *out_bytes)
{
    uint64_t bytes = 0u;
    size_t index;

    if (count > UINT64_MAX) {
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        uint64_t row = 16u;
        if (row > UINT64_MAX - entries[index].key_length) {
            return 0;
        }
        row += entries[index].key_length;
        if (row > UINT64_MAX - entries[index].value_length) {
            return 0;
        }
        row += entries[index].value_length;
        if (bytes > UINT64_MAX - row) {
            return 0;
        }
        bytes += row;
    }
    *out_entries = (uint64_t)count;
    *out_bytes = bytes;
    return 1;
}

static int view_within_capacity(
    const ninlil_test_storage_t *storage,
    const storage_transaction_t *transaction)
{
    uint64_t entries;
    uint64_t bytes;

    return logical_usage(
            transaction->view,
            transaction->view_count,
            &entries,
            &bytes)
        && entries <= storage->config.max_entries_per_namespace
        && bytes <= storage->config.max_bytes_per_namespace;
}

static ninlil_storage_status_t fixture_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_namespace_t *name_space;
    storage_handle_t *handle;
    storage_fault_t fault;
    ninlil_storage_status_t status;
    int namespace_created = 0;

    if (storage == NULL || out_handle == NULL || *out_handle != NULL
        || !view_shape_is_valid(storage_namespace, 1u, 255u)) {
        if (storage != NULL) {
            record_call(storage, NINLIL_TEST_STORAGE_OP_OPEN,
                NINLIL_STORAGE_CORRUPT, 0u, 0u, 0u, 0u);
        }
        return NINLIL_STORAGE_CORRUPT;
    }
    if (expected_schema != NINLIL_STORAGE_SCHEMA_M1A) {
        status = NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
        record_call(storage, NINLIL_TEST_STORAGE_OP_OPEN,
            status, 0u, 0u, 0u, 0u);
        return status;
    }
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_OPEN, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_OPEN,
            fault.status, 0u, 0u, 0u, 0u);
        return fault.status;
    }
    name_space = find_namespace(storage, storage_namespace);
    if (name_space != NULL && name_space->schema != expected_schema) {
        status = NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    } else if (name_space != NULL && name_space->leased) {
        status = NINLIL_STORAGE_BUSY;
    } else {
        if (name_space == NULL) {
            name_space = create_namespace(
                storage, storage_namespace, expected_schema);
            namespace_created = name_space != NULL;
        }
        if (name_space == NULL) {
            status = NINLIL_STORAGE_NO_SPACE;
        } else {
            handle = (storage_handle_t *)calloc(1u, sizeof(*handle));
            if (handle == NULL) {
                if (namespace_created) {
                    (void)memset(name_space, 0, sizeof(*name_space));
                }
                status = NINLIL_STORAGE_NO_SPACE;
            } else {
                handle->id = next_nonzero_id(&storage->next_handle_id);
                handle->storage = storage;
                handle->name_space = name_space;
                handle->next = storage->handles;
                storage->handles = handle;
                name_space->leased = 1;
                storage->live_handle_count += 1u;
                *out_handle = (ninlil_storage_handle_t)handle;
                record_call(storage, NINLIL_TEST_STORAGE_OP_OPEN,
                    NINLIL_STORAGE_OK, handle->id, 0u, 0u, 0u);
                return NINLIL_STORAGE_OK;
            }
        }
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_OPEN,
        status, 0u, 0u, 0u, 0u);
    return status;
}

static void force_close_handle(
    ninlil_test_storage_t *storage,
    storage_handle_t *handle)
{
    storage_handle_t **link = &storage->handles;

    while (handle->transactions != NULL) {
        destroy_transaction(storage, handle->transactions, 0);
    }
    while (*link != NULL && *link != handle) {
        link = &(*link)->next;
    }
    if (*link == handle) {
        *link = handle->next;
    }
    handle->name_space->leased = 0;
    handle->next = storage->retired_handles;
    storage->retired_handles = handle;
    storage->live_handle_count -= 1u;
}

static void fixture_close(void *user, ninlil_storage_handle_t opaque)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_handle_t *handle;
    uint64_t handle_id = 0u;
    ninlil_storage_status_t diagnostic = NINLIL_STORAGE_CORRUPT;

    if (storage == NULL) {
        return;
    }
    handle = find_handle(storage, opaque);
    if (handle != NULL) {
        handle_id = handle->id;
        diagnostic = handle->transactions == NULL
            ? NINLIL_STORAGE_OK
            : NINLIL_STORAGE_CORRUPT;
        force_close_handle(storage, handle);
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_CLOSE,
        diagnostic, handle_id, 0u, 0u, 0u);
}

static ninlil_storage_status_t fixture_begin(
    void *user,
    ninlil_storage_handle_t opaque,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_handle_t *handle;
    storage_transaction_t *transaction;
    storage_fault_t fault;
    ninlil_storage_status_t status;

    if (storage == NULL || out_txn == NULL || *out_txn != NULL) {
        if (storage != NULL) {
            record_call(storage, NINLIL_TEST_STORAGE_OP_BEGIN,
                NINLIL_STORAGE_CORRUPT, 0u, 0u, 0u, 0u);
        }
        return NINLIL_STORAGE_CORRUPT;
    }
    handle = find_handle(storage, opaque);
    if (handle == NULL
        || (mode != NINLIL_STORAGE_READ_ONLY
            && mode != NINLIL_STORAGE_READ_WRITE)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_BEGIN,
            NINLIL_STORAGE_CORRUPT,
            handle == NULL ? 0u : handle->id, 0u, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_BEGIN, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_BEGIN,
            fault.status, handle->id, 0u, 0u, 0u);
        return fault.status;
    }
    if (mode == NINLIL_STORAGE_READ_WRITE && handle->has_writer) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_BEGIN,
            NINLIL_STORAGE_BUSY, handle->id, 0u, 0u, 0u);
        return NINLIL_STORAGE_BUSY;
    }
    transaction = (storage_transaction_t *)calloc(1u, sizeof(*transaction));
    if (transaction == NULL) {
        status = NINLIL_STORAGE_NO_SPACE;
    } else if (!clone_entries(
            handle->name_space->entries,
            handle->name_space->entry_count,
            &transaction->view)) {
        free(transaction);
        transaction = NULL;
        status = NINLIL_STORAGE_NO_SPACE;
    } else {
        transaction->id = next_nonzero_id(&storage->next_transaction_id);
        transaction->handle = handle;
        transaction->mode = mode;
        transaction->view_count = handle->name_space->entry_count;
        transaction->next = handle->transactions;
        handle->transactions = transaction;
        if (mode == NINLIL_STORAGE_READ_WRITE) {
            handle->has_writer = 1;
        }
        storage->live_transaction_count += 1u;
        *out_txn = (ninlil_storage_txn_t)transaction;
        record_call(storage, NINLIL_TEST_STORAGE_OP_BEGIN,
            NINLIL_STORAGE_OK, handle->id, transaction->id, 0u, 0u);
        return NINLIL_STORAGE_OK;
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_BEGIN,
        status, handle->id, 0u, 0u, 0u);
    return status;
}

static ninlil_storage_status_t fixture_get(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_transaction_t *transaction;
    storage_fault_t fault;
    ninlil_storage_status_t status;
    int found;
    size_t index;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || !view_shape_is_valid(key, 1u, 255u)
        || !mut_shape_is_valid(inout_value)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_GET,
            NINLIL_STORAGE_CORRUPT, 0u,
            transaction == NULL ? 0u : transaction->id, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    index = find_entry(transaction->view, transaction->view_count, key, &found);
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_GET, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        if (fault.status == NINLIL_STORAGE_BUFFER_TOO_SMALL && found) {
            inout_value->length = transaction->view[index].value_length;
        } else {
            inout_value->length = 0u;
        }
        record_call(storage, NINLIL_TEST_STORAGE_OP_GET,
            fault.status, transaction->handle->id, transaction->id, 0u, 0u);
        return fault.status;
    }
    if (!found) {
        status = NINLIL_STORAGE_NOT_FOUND;
    } else if (transaction->view[index].value_length > inout_value->capacity) {
        inout_value->length = transaction->view[index].value_length;
        status = NINLIL_STORAGE_BUFFER_TOO_SMALL;
    } else {
        if (transaction->view[index].value_length != 0u) {
            (void)memcpy(
                inout_value->data,
                transaction->view[index].value,
                transaction->view[index].value_length);
        }
        inout_value->length = transaction->view[index].value_length;
        status = NINLIL_STORAGE_OK;
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_GET,
        status, transaction->handle->id, transaction->id, 0u, 0u);
    return status;
}

static ninlil_storage_status_t fixture_put(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_transaction_t *transaction;
    storage_fault_t fault;
    storage_entry_t *entries;
    uint8_t *key_copy = NULL;
    uint8_t *value_copy = NULL;
    int found;
    size_t index;
    ninlil_storage_status_t status;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || transaction->mode != NINLIL_STORAGE_READ_WRITE
        || !view_shape_is_valid(key, 1u, 255u)
        || !view_shape_is_valid(value, 0u, UINT32_MAX)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_PUT,
            NINLIL_STORAGE_CORRUPT, 0u,
            transaction == NULL ? 0u : transaction->id, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_PUT, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_PUT,
            fault.status, transaction->handle->id,
            transaction->id, 0u, 0u);
        return fault.status;
    }
    if (value.length > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_PUT,
            NINLIL_STORAGE_NO_SPACE, transaction->handle->id,
            transaction->id, 0u, 0u);
        return NINLIL_STORAGE_NO_SPACE;
    }
    index = find_entry(transaction->view, transaction->view_count, key, &found);
    if (!copy_bytes(value.data, value.length, &value_copy)) {
        status = NINLIL_STORAGE_NO_SPACE;
    } else if (found) {
        free(transaction->view[index].value);
        transaction->view[index].value = value_copy;
        transaction->view[index].value_length = value.length;
        status = NINLIL_STORAGE_OK;
    } else if (!copy_bytes(key.data, key.length, &key_copy)) {
        free(value_copy);
        status = NINLIL_STORAGE_NO_SPACE;
    } else if (transaction->view_count == SIZE_MAX
        || transaction->view_count + 1u > SIZE_MAX / sizeof(*entries)) {
        free(key_copy);
        free(value_copy);
        status = NINLIL_STORAGE_NO_SPACE;
    } else {
        entries = (storage_entry_t *)realloc(
            transaction->view,
            (transaction->view_count + 1u) * sizeof(*entries));
        if (entries == NULL) {
            free(key_copy);
            free(value_copy);
            status = NINLIL_STORAGE_NO_SPACE;
        } else {
            transaction->view = entries;
            (void)memmove(
                &entries[index + 1u],
                &entries[index],
                (transaction->view_count - index) * sizeof(*entries));
            entries[index].key = key_copy;
            entries[index].key_length = key.length;
            entries[index].value = value_copy;
            entries[index].value_length = value.length;
            transaction->view_count += 1u;
            status = NINLIL_STORAGE_OK;
        }
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_PUT,
        status, transaction->handle->id, transaction->id, 0u, 0u);
    return status;
}

static ninlil_storage_status_t fixture_erase(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_transaction_t *transaction;
    storage_fault_t fault;
    int found;
    size_t index;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || transaction->mode != NINLIL_STORAGE_READ_WRITE
        || !view_shape_is_valid(key, 1u, 255u)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_ERASE,
            NINLIL_STORAGE_CORRUPT, 0u,
            transaction == NULL ? 0u : transaction->id, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_ERASE, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_ERASE,
            fault.status, transaction->handle->id,
            transaction->id, 0u, 0u);
        return fault.status;
    }
    index = find_entry(transaction->view, transaction->view_count, key, &found);
    if (found) {
        free_entry(&transaction->view[index]);
        (void)memmove(
            &transaction->view[index],
            &transaction->view[index + 1u],
            (transaction->view_count - index - 1u)
                * sizeof(*transaction->view));
        transaction->view_count -= 1u;
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_ERASE,
        NINLIL_STORAGE_OK, transaction->handle->id,
        transaction->id, 0u, 0u);
    return NINLIL_STORAGE_OK;
}

static int prefix_matches(
    const storage_entry_t *entry,
    ninlil_bytes_view_t prefix)
{
    return entry->key_length >= prefix.length
        && (prefix.length == 0u
            || memcmp(entry->key, prefix.data, prefix.length) == 0);
}

static ninlil_storage_status_t fixture_iter_open(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_transaction_t *transaction;
    storage_iterator_t *iterator;
    storage_fault_t fault;
    size_t matches = 0u;
    size_t index;
    size_t target = 0u;

    if (storage == NULL || out_iter == NULL || *out_iter != NULL) {
        if (storage != NULL) {
            record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN,
                NINLIL_STORAGE_CORRUPT, 0u, 0u, 0u, 0u);
        }
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || !view_shape_is_valid(prefix, 0u, 255u)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN,
            NINLIL_STORAGE_CORRUPT, 0u,
            transaction == NULL ? 0u : transaction->id, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN,
            fault.status, transaction->handle->id,
            transaction->id, 0u, 0u);
        return fault.status;
    }
    for (index = 0u; index < transaction->view_count; ++index) {
        if (prefix_matches(&transaction->view[index], prefix)) {
            matches += 1u;
        }
    }
    iterator = (storage_iterator_t *)calloc(1u, sizeof(*iterator));
    if (iterator == NULL) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN,
            NINLIL_STORAGE_NO_SPACE, transaction->handle->id,
            transaction->id, 0u, 0u);
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (matches != 0u) {
        iterator->rows = (storage_entry_t *)calloc(matches, sizeof(*iterator->rows));
        if (iterator->rows == NULL) {
            free(iterator);
            record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN,
                NINLIL_STORAGE_NO_SPACE, transaction->handle->id,
                transaction->id, 0u, 0u);
            return NINLIL_STORAGE_NO_SPACE;
        }
        iterator->row_count = matches;
        for (index = 0u; index < transaction->view_count; ++index) {
            const storage_entry_t *source = &transaction->view[index];
            storage_entry_t *destination;
            if (!prefix_matches(source, prefix)) {
                continue;
            }
            destination = &iterator->rows[target];
            destination->key_length = source->key_length;
            destination->value_length = source->value_length;
            if (!copy_bytes(source->key, source->key_length, &destination->key)
                || !copy_bytes(
                    source->value, source->value_length, &destination->value)) {
                free_entries(iterator->rows, matches);
                free(iterator);
                record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN,
                    NINLIL_STORAGE_NO_SPACE, transaction->handle->id,
                    transaction->id, 0u, 0u);
                return NINLIL_STORAGE_NO_SPACE;
            }
            target += 1u;
        }
        qsort(iterator->rows, iterator->row_count,
            sizeof(*iterator->rows), entry_compare);
    }
    iterator->id = next_nonzero_id(&storage->next_iterator_id);
    iterator->transaction = transaction;
    iterator->next = transaction->iterators;
    transaction->iterators = iterator;
    storage->live_iterator_count += 1u;
    *out_iter = (ninlil_storage_iter_t)iterator;
    record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_OPEN,
        NINLIL_STORAGE_OK, transaction->handle->id,
        transaction->id, iterator->id, 0u);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t fixture_iter_next(
    void *user,
    ninlil_storage_iter_t opaque,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_iterator_t *iterator;
    storage_fault_t fault;
    storage_entry_t *row;
    ninlil_storage_status_t status;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    iterator = find_iterator(storage, opaque);
    if (iterator == NULL || !mut_shape_is_valid(inout_key)
        || !mut_shape_is_valid(inout_value)
        || !mut_ranges_do_not_overlap(inout_key, inout_value)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_NEXT,
            NINLIL_STORAGE_CORRUPT, 0u, 0u,
            iterator == NULL ? 0u : iterator->id, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    row = iterator->position < iterator->row_count
        ? &iterator->rows[iterator->position] : NULL;
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_ITER_NEXT, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        if (fault.status == NINLIL_STORAGE_BUFFER_TOO_SMALL && row != NULL) {
            inout_key->length = row->key_length;
            inout_value->length = row->value_length;
        } else {
            inout_key->length = 0u;
            inout_value->length = 0u;
        }
        record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_NEXT,
            fault.status, iterator->transaction->handle->id,
            iterator->transaction->id, iterator->id, 0u);
        return fault.status;
    }
    if (row == NULL) {
        status = NINLIL_STORAGE_NOT_FOUND;
    } else if (row->key_length > inout_key->capacity
        || row->value_length > inout_value->capacity) {
        inout_key->length = row->key_length;
        inout_value->length = row->value_length;
        status = NINLIL_STORAGE_BUFFER_TOO_SMALL;
    } else {
        if (row->key_length != 0u) {
            (void)memcpy(inout_key->data, row->key, row->key_length);
        }
        if (row->value_length != 0u) {
            (void)memcpy(inout_value->data, row->value, row->value_length);
        }
        inout_key->length = row->key_length;
        inout_value->length = row->value_length;
        iterator->position += 1u;
        status = NINLIL_STORAGE_OK;
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_NEXT,
        status, iterator->transaction->handle->id,
        iterator->transaction->id, iterator->id, 0u);
    return status;
}

static void fixture_iter_close(void *user, ninlil_storage_iter_t opaque)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_iterator_t *iterator;
    storage_iterator_t **link;
    uint64_t handle_id = 0u;
    uint64_t transaction_id = 0u;
    uint64_t iterator_id = 0u;
    ninlil_storage_status_t diagnostic = NINLIL_STORAGE_CORRUPT;

    if (storage == NULL) {
        return;
    }
    iterator = find_iterator(storage, opaque);
    if (iterator != NULL) {
        storage_transaction_t *transaction = iterator->transaction;
        handle_id = transaction->handle->id;
        transaction_id = transaction->id;
        iterator_id = iterator->id;
        link = &transaction->iterators;
        while (*link != NULL && *link != iterator) {
            link = &(*link)->next;
        }
        if (*link == iterator) {
            *link = iterator->next;
        }
        retire_iterator(storage, iterator);
        diagnostic = NINLIL_STORAGE_OK;
    }
    record_call(storage, NINLIL_TEST_STORAGE_OP_ITER_CLOSE,
        diagnostic, handle_id, transaction_id, iterator_id, 0u);
}

static ninlil_storage_status_t fixture_capacity(
    void *user,
    ninlil_storage_handle_t opaque,
    ninlil_storage_capacity_t *out_capacity)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_handle_t *handle;
    storage_fault_t fault;
    uint64_t entries;
    uint64_t bytes;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    handle = find_handle(storage, opaque);
    if (handle == NULL || !capacity_output_is_valid(out_capacity)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_CAPACITY,
            NINLIL_STORAGE_CORRUPT,
            handle == NULL ? 0u : handle->id, 0u, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    out_capacity->max_entries = 0u;
    out_capacity->used_entries = 0u;
    out_capacity->max_bytes = 0u;
    out_capacity->used_bytes = 0u;
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_CAPACITY, &fault)
        && fault.status != NINLIL_STORAGE_OK) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_CAPACITY,
            fault.status, handle->id, 0u, 0u, 0u);
        return fault.status;
    }
    if (!logical_usage(
            handle->name_space->entries,
            handle->name_space->entry_count,
            &entries,
            &bytes)) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_CAPACITY,
            NINLIL_STORAGE_CORRUPT, handle->id, 0u, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    out_capacity->max_entries = storage->config.max_entries_per_namespace;
    out_capacity->used_entries = entries;
    out_capacity->max_bytes = storage->config.max_bytes_per_namespace;
    out_capacity->used_bytes = bytes;
    record_call(storage, NINLIL_TEST_STORAGE_OP_CAPACITY,
        NINLIL_STORAGE_OK, handle->id, 0u, 0u, 0u);
    return NINLIL_STORAGE_OK;
}

static void publish_transaction_view(storage_transaction_t *transaction)
{
    storage_namespace_t *name_space = transaction->handle->name_space;

    free_entries(name_space->entries, name_space->entry_count);
    name_space->entries = transaction->view;
    name_space->entry_count = transaction->view_count;
    transaction->view = NULL;
    transaction->view_count = 0u;
}

static ninlil_storage_status_t fixture_commit(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_durability_t durability)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_transaction_t *transaction;
    storage_fault_t fault;
    ninlil_storage_status_t status;
    uint64_t handle_id;
    uint64_t transaction_id;
    int publish = 0;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_COMMIT,
            NINLIL_STORAGE_CORRUPT, 0u, 0u, 0u, durability);
        return NINLIL_STORAGE_CORRUPT;
    }
    handle_id = transaction->handle->id;
    transaction_id = transaction->id;
    if (durability != NINLIL_DURABILITY_FULL) {
        status = NINLIL_STORAGE_CORRUPT;
    } else if (transaction->mode == NINLIL_STORAGE_READ_WRITE
        && !view_within_capacity(storage, transaction)) {
        /* A committed hidden truth cannot violate configured capacity. */
        status = NINLIL_STORAGE_NO_SPACE;
    } else if (take_fault(storage, NINLIL_TEST_STORAGE_OP_COMMIT, &fault)) {
        status = fault.status;
        if (status == NINLIL_STORAGE_OK) {
            publish = transaction->mode == NINLIL_STORAGE_READ_WRITE;
        } else if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            publish = transaction->mode == NINLIL_STORAGE_READ_WRITE
                && fault.commit_unknown_committed;
        }
    } else {
        status = NINLIL_STORAGE_OK;
        publish = transaction->mode == NINLIL_STORAGE_READ_WRITE;
    }
    if (publish && (status == NINLIL_STORAGE_OK
            || status == NINLIL_STORAGE_COMMIT_UNKNOWN)) {
        publish_transaction_view(transaction);
    }
    destroy_transaction(storage, transaction, publish);
    record_call(storage, NINLIL_TEST_STORAGE_OP_COMMIT,
        status, handle_id, transaction_id, 0u, durability);
    return status;
}

static ninlil_storage_status_t fixture_rollback(
    void *user,
    ninlil_storage_txn_t opaque)
{
    ninlil_test_storage_t *storage = (ninlil_test_storage_t *)user;
    storage_transaction_t *transaction;
    storage_fault_t fault;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;
    uint64_t handle_id;
    uint64_t transaction_id;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL) {
        record_call(storage, NINLIL_TEST_STORAGE_OP_ROLLBACK,
            NINLIL_STORAGE_CORRUPT, 0u, 0u, 0u, 0u);
        return NINLIL_STORAGE_CORRUPT;
    }
    handle_id = transaction->handle->id;
    transaction_id = transaction->id;
    if (take_fault(storage, NINLIL_TEST_STORAGE_OP_ROLLBACK, &fault)) {
        status = fault.status;
    }
    destroy_transaction(storage, transaction, 0);
    record_call(storage, NINLIL_TEST_STORAGE_OP_ROLLBACK,
        status, handle_id, transaction_id, 0u, 0u);
    return status;
}

ninlil_test_storage_t *ninlil_test_storage_create(
    const ninlil_test_storage_config_t *config)
{
    ninlil_test_storage_t *storage;

    if (config == NULL || config->max_namespaces == 0u
        || config->max_namespaces > NINLIL_TEST_STORAGE_MAX_NAMESPACES
        || config->max_entries_per_namespace == 0u
        || config->max_entries_per_namespace == UINT64_MAX
        || config->max_bytes_per_namespace == 0u
        || config->max_bytes_per_namespace == UINT64_MAX) {
        return NULL;
    }
    storage = (ninlil_test_storage_t *)calloc(1u, sizeof(*storage));
    if (storage == NULL) {
        return NULL;
    }
    storage->namespaces = (storage_namespace_t *)calloc(
        config->max_namespaces, sizeof(*storage->namespaces));
    if (storage->namespaces == NULL) {
        free(storage);
        return NULL;
    }
    storage->config = *config;
    storage->next_trace_sequence = 1u;
    storage->next_handle_id = 1u;
    storage->next_transaction_id = 1u;
    storage->next_iterator_id = 1u;
    storage->ops.abi_version = NINLIL_ABI_VERSION;
    storage->ops.struct_size = (uint16_t)sizeof(storage->ops);
    storage->ops.user = storage;
    storage->ops.open = fixture_open;
    storage->ops.close = fixture_close;
    storage->ops.begin = fixture_begin;
    storage->ops.get = fixture_get;
    storage->ops.put = fixture_put;
    storage->ops.erase = fixture_erase;
    storage->ops.iter_open = fixture_iter_open;
    storage->ops.iter_next = fixture_iter_next;
    storage->ops.iter_close = fixture_iter_close;
    storage->ops.capacity = fixture_capacity;
    storage->ops.commit = fixture_commit;
    storage->ops.rollback = fixture_rollback;
    return storage;
}

void ninlil_test_storage_simulate_crash(ninlil_test_storage_t *storage)
{
    if (storage == NULL) {
        return;
    }
    while (storage->handles != NULL) {
        force_close_handle(storage, storage->handles);
    }
}

void ninlil_test_storage_destroy(ninlil_test_storage_t *storage)
{
    uint32_t index;
    storage_iterator_t *iterator;
    storage_transaction_t *transaction;
    storage_handle_t *handle;

    if (storage == NULL) {
        return;
    }
    ninlil_test_storage_simulate_crash(storage);
    for (index = 0u; index < storage->config.max_namespaces; ++index) {
        storage_namespace_t *name_space = &storage->namespaces[index];
        free_entries(name_space->entries, name_space->entry_count);
    }
    iterator = storage->retired_iterators;
    while (iterator != NULL) {
        storage_iterator_t *next = iterator->next;
        free(iterator);
        iterator = next;
    }
    transaction = storage->retired_transactions;
    while (transaction != NULL) {
        storage_transaction_t *next = transaction->next;
        free(transaction);
        transaction = next;
    }
    handle = storage->retired_handles;
    while (handle != NULL) {
        storage_handle_t *next = handle->next;
        free(handle);
        handle = next;
    }
    free(storage->namespaces);
    free(storage);
}

const ninlil_storage_ops_t *ninlil_test_storage_ops(
    ninlil_test_storage_t *storage)
{
    return storage == NULL ? NULL : &storage->ops;
}

int ninlil_test_storage_fault_enqueue(
    ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation,
    ninlil_storage_status_t status,
    uint32_t remaining_count,
    int has_commit_unknown_truth,
    int commit_unknown_committed)
{
    storage_fault_queue_t *queue;
    storage_fault_t *fault;
    size_t tail;
    int is_commit_unknown;

    if (storage == NULL || !operation_returns_status(operation)
        || remaining_count == 0u
        || status == NINLIL_STORAGE_OK
        || status == NINLIL_STORAGE_NOT_FOUND
        || status == NINLIL_STORAGE_BUFFER_TOO_SMALL
        || (has_commit_unknown_truth != 0
            && has_commit_unknown_truth != 1)
        || (commit_unknown_committed != 0
            && commit_unknown_committed != 1)) {
        return 0;
    }
    is_commit_unknown = status == NINLIL_STORAGE_COMMIT_UNKNOWN
        && operation == NINLIL_TEST_STORAGE_OP_COMMIT;
    if ((is_commit_unknown && has_commit_unknown_truth != 1)
        || (!is_commit_unknown && has_commit_unknown_truth != 0)
        || (!is_commit_unknown && commit_unknown_committed != 0)) {
        return 0;
    }
    queue = &storage->faults[operation];
    if (queue->count >= NINLIL_TEST_STORAGE_FAULT_QUEUE_CAPACITY) {
        return 0;
    }
    tail = (queue->head + queue->count)
        % NINLIL_TEST_STORAGE_FAULT_QUEUE_CAPACITY;
    fault = &queue->entries[tail];
    fault->status = status;
    fault->remaining_count = remaining_count;
    fault->commit_unknown_committed = commit_unknown_committed != 0;
    queue->count += 1u;
    return 1;
}

int ninlil_test_storage_fault_next(
    ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation,
    ninlil_storage_status_t status)
{
    return ninlil_test_storage_fault_enqueue(
        storage, operation, status, 1u, 0, 0);
}

uint64_t ninlil_test_storage_call_count(
    const ninlil_test_storage_t *storage,
    ninlil_test_storage_operation_t operation)
{
    if (storage == NULL || !operation_is_valid(operation)) {
        return 0u;
    }
    return storage->call_counts[operation];
}

size_t ninlil_test_storage_trace_count(
    const ninlil_test_storage_t *storage)
{
    return storage == NULL ? 0u : storage->trace_count;
}

int ninlil_test_storage_trace_overflowed(
    const ninlil_test_storage_t *storage)
{
    return storage != NULL && storage->trace_overflowed;
}

const ninlil_test_storage_trace_record_t *ninlil_test_storage_trace_at(
    const ninlil_test_storage_t *storage,
    size_t index)
{
    if (storage == NULL || index >= storage->trace_count) {
        return NULL;
    }
    return &storage->trace[index];
}

uint64_t ninlil_test_storage_live_handles(
    const ninlil_test_storage_t *storage)
{
    return storage == NULL ? 0u : storage->live_handle_count;
}

uint64_t ninlil_test_storage_live_transactions(
    const ninlil_test_storage_t *storage)
{
    return storage == NULL ? 0u : storage->live_transaction_count;
}

uint64_t ninlil_test_storage_live_iterators(
    const ninlil_test_storage_t *storage)
{
    return storage == NULL ? 0u : storage->live_iterator_count;
}
