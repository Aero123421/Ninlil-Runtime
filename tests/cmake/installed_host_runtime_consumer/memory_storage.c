/* SPDX-License-Identifier: Apache-2.0 */
#include "memory_storage.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define CONSUMER_STORAGE_MAX_ENTRIES ((size_t)512u)
#define CONSUMER_STORAGE_MAX_BYTES ((uint64_t)1048576u)
#define CONSUMER_STORAGE_MAX_KEY_BYTES ((uint32_t)255u)
#define CONSUMER_STORAGE_MAX_ITERATORS ((size_t)8u)
#define CONSUMER_STORAGE_ENTRY_OVERHEAD ((uint64_t)16u)

typedef struct consumer_entry {
    uint8_t key[CONSUMER_STORAGE_MAX_KEY_BYTES];
    uint32_t key_length;
    uint8_t *value;
    uint32_t value_length;
} consumer_entry_t;

typedef struct consumer_iterator {
    int active;
    consumer_entry_t *rows;
    size_t row_count;
    size_t position;
} consumer_iterator_t;

struct consumer_memory_storage {
    ninlil_storage_ops_t ops;
    consumer_entry_t *committed;
    consumer_entry_t *working;
    size_t committed_count;
    size_t working_count;
    consumer_iterator_t iterators[CONSUMER_STORAGE_MAX_ITERATORS];
    uint8_t storage_namespace[CONSUMER_STORAGE_MAX_KEY_BYTES];
    uint32_t storage_namespace_length;
    uint32_t schema;
    ninlil_storage_mode_t transaction_mode;
    int handle_open;
    int transaction_active;
    uint64_t live_iterator_count;
};

static int view_is_valid(
    ninlil_bytes_view_t view,
    uint32_t minimum,
    uint32_t maximum)
{
    if (view.length < minimum || view.length > maximum) {
        return 0;
    }
    return view.length == 0u ? view.data == NULL : view.data != NULL;
}

static int mutable_view_is_valid(const ninlil_mut_bytes_t *value)
{
    if (value == NULL || value->length != 0u) {
        return 0;
    }
    return value->capacity == 0u
        ? value->data == NULL
        : value->data != NULL;
}

static int mutable_ranges_do_not_overlap(
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

static int bytes_compare(
    const uint8_t *left,
    uint32_t left_length,
    const uint8_t *right,
    uint32_t right_length)
{
    uint32_t common = left_length < right_length
        ? left_length : right_length;
    int compared = common == 0u
        ? 0 : memcmp(left, right, (size_t)common);

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

static void entry_reset(consumer_entry_t *entry)
{
    free(entry->value);
    (void)memset(entry, 0, sizeof(*entry));
}

static void entries_reset(consumer_entry_t *entries, size_t count)
{
    size_t index;

    if (entries == NULL) {
        return;
    }
    for (index = 0u; index < count; ++index) {
        entry_reset(&entries[index]);
    }
    free(entries);
}

static int value_copy(
    const uint8_t *source,
    uint32_t length,
    uint8_t **out)
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
    (void)memcpy(copy, source, (size_t)length);
    *out = copy;
    return 1;
}

static int entries_clone(
    const consumer_entry_t *source,
    size_t count,
    consumer_entry_t **out)
{
    consumer_entry_t *copy;
    size_t index;

    *out = NULL;
    if (count == 0u) {
        return 1;
    }
    copy = (consumer_entry_t *)calloc(count, sizeof(*copy));
    if (copy == NULL) {
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        copy[index].key_length = source[index].key_length;
        (void)memcpy(
            copy[index].key,
            source[index].key,
            (size_t)source[index].key_length);
        copy[index].value_length = source[index].value_length;
        if (!value_copy(
                source[index].value,
                source[index].value_length,
                &copy[index].value)) {
            entries_reset(copy, count);
            return 0;
        }
    }
    *out = copy;
    return 1;
}

static size_t entry_find(
    const consumer_entry_t *entries,
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

static int usage_is_valid(
    const consumer_entry_t *entries,
    size_t count,
    uint64_t *out_bytes)
{
    uint64_t bytes = 0u;
    size_t index;

    if (count > CONSUMER_STORAGE_MAX_ENTRIES) {
        return 0;
    }
    for (index = 0u; index < count; ++index) {
        uint64_t row_bytes = CONSUMER_STORAGE_ENTRY_OVERHEAD
            + (uint64_t)entries[index].key_length
            + (uint64_t)entries[index].value_length;
        if (row_bytes > UINT64_MAX - bytes) {
            return 0;
        }
        bytes += row_bytes;
    }
    *out_bytes = bytes;
    return bytes <= CONSUMER_STORAGE_MAX_BYTES;
}

static void iterator_reset(consumer_iterator_t *iterator)
{
    if (!iterator->active) {
        return;
    }
    entries_reset(iterator->rows, iterator->row_count);
    (void)memset(iterator, 0, sizeof(*iterator));
}

static void iterators_reset(consumer_memory_storage_t *storage)
{
    size_t index;

    for (index = 0u; index < CONSUMER_STORAGE_MAX_ITERATORS; ++index) {
        iterator_reset(&storage->iterators[index]);
    }
    storage->live_iterator_count = 0u;
}

static void transaction_reset(consumer_memory_storage_t *storage)
{
    iterators_reset(storage);
    entries_reset(storage->working, storage->working_count);
    storage->working = NULL;
    storage->working_count = 0u;
    storage->transaction_active = 0;
    storage->transaction_mode = 0u;
}

static int handle_matches(
    const consumer_memory_storage_t *storage,
    ninlil_storage_handle_t handle)
{
    return storage->handle_open
        && handle == (ninlil_storage_handle_t)storage;
}

static int transaction_matches(
    const consumer_memory_storage_t *storage,
    ninlil_storage_txn_t transaction)
{
    return storage->transaction_active
        && transaction == (ninlil_storage_txn_t)&storage->transaction_active;
}

static consumer_iterator_t *iterator_find(
    consumer_memory_storage_t *storage,
    ninlil_storage_iter_t opaque)
{
    size_t index;

    for (index = 0u; index < CONSUMER_STORAGE_MAX_ITERATORS; ++index) {
        consumer_iterator_t *iterator = &storage->iterators[index];
        if (iterator->active
            && opaque == (ninlil_storage_iter_t)iterator) {
            return iterator;
        }
    }
    return NULL;
}

static ninlil_storage_status_t memory_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;

    if (storage == NULL || out_handle == NULL || *out_handle != NULL
        || !view_is_valid(
            storage_namespace, 1u, CONSUMER_STORAGE_MAX_KEY_BYTES)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (expected_schema != NINLIL_STORAGE_SCHEMA_M1A) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (storage->handle_open) {
        return NINLIL_STORAGE_BUSY;
    }
    if (storage->storage_namespace_length != 0u
        && (storage->schema != expected_schema
            || storage->storage_namespace_length
                != storage_namespace.length
            || memcmp(
                storage->storage_namespace,
                storage_namespace.data,
                storage_namespace.length) != 0)) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (storage->storage_namespace_length == 0u) {
        (void)memcpy(
            storage->storage_namespace,
            storage_namespace.data,
            storage_namespace.length);
        storage->storage_namespace_length = storage_namespace.length;
        storage->schema = expected_schema;
    }
    storage->handle_open = 1;
    *out_handle = (ninlil_storage_handle_t)storage;
    return NINLIL_STORAGE_OK;
}

static void memory_close(void *user, ninlil_storage_handle_t handle)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;

    if (storage == NULL || !handle_matches(storage, handle)) {
        return;
    }
    if (storage->transaction_active) {
        transaction_reset(storage);
    }
    storage->handle_open = 0;
}

static ninlil_storage_status_t memory_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;

    if (storage == NULL || !handle_matches(storage, handle)
        || out_transaction == NULL || *out_transaction != NULL
        || (mode != NINLIL_STORAGE_READ_ONLY
            && mode != NINLIL_STORAGE_READ_WRITE)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (storage->transaction_active) {
        return NINLIL_STORAGE_BUSY;
    }
    if (!entries_clone(
            storage->committed,
            storage->committed_count,
            &storage->working)) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    storage->working_count = storage->committed_count;
    storage->transaction_mode = mode;
    storage->transaction_active = 1;
    *out_transaction =
        (ninlil_storage_txn_t)&storage->transaction_active;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t memory_get(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    size_t index;
    int found;

    if (storage == NULL || !transaction_matches(storage, transaction)
        || !view_is_valid(key, 1u, CONSUMER_STORAGE_MAX_KEY_BYTES)
        || !mutable_view_is_valid(inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    index = entry_find(
        storage->working, storage->working_count, key, &found);
    if (!found) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    inout_value->length = storage->working[index].value_length;
    if (inout_value->capacity < inout_value->length) {
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (inout_value->length != 0u) {
        (void)memcpy(
            inout_value->data,
            storage->working[index].value,
            (size_t)inout_value->length);
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t memory_put(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    consumer_entry_t *entries;
    uint8_t *replacement = NULL;
    size_t index;
    int found;

    if (storage == NULL || !transaction_matches(storage, transaction)
        || storage->transaction_mode != NINLIL_STORAGE_READ_WRITE
        || !view_is_valid(key, 1u, CONSUMER_STORAGE_MAX_KEY_BYTES)
        || !view_is_valid(value, 0u, UINT32_MAX)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (value.length > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    index = entry_find(
        storage->working, storage->working_count, key, &found);
    if (!value_copy(value.data, value.length, &replacement)) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (found) {
        free(storage->working[index].value);
        storage->working[index].value = replacement;
        storage->working[index].value_length = value.length;
        return NINLIL_STORAGE_OK;
    }
    if (storage->working_count >= CONSUMER_STORAGE_MAX_ENTRIES) {
        free(replacement);
        return NINLIL_STORAGE_NO_SPACE;
    }
    entries = (consumer_entry_t *)realloc(
        storage->working,
        (storage->working_count + 1u) * sizeof(*entries));
    if (entries == NULL) {
        free(replacement);
        return NINLIL_STORAGE_NO_SPACE;
    }
    storage->working = entries;
    (void)memmove(
        &entries[index + 1u],
        &entries[index],
        (storage->working_count - index) * sizeof(*entries));
    (void)memset(&entries[index], 0, sizeof(entries[index]));
    (void)memcpy(entries[index].key, key.data, key.length);
    entries[index].key_length = key.length;
    entries[index].value = replacement;
    entries[index].value_length = value.length;
    storage->working_count += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t memory_erase(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    size_t index;
    int found;

    if (storage == NULL || !transaction_matches(storage, transaction)
        || storage->transaction_mode != NINLIL_STORAGE_READ_WRITE
        || !view_is_valid(key, 1u, CONSUMER_STORAGE_MAX_KEY_BYTES)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    index = entry_find(
        storage->working, storage->working_count, key, &found);
    if (found) {
        entry_reset(&storage->working[index]);
        (void)memmove(
            &storage->working[index],
            &storage->working[index + 1u],
            (storage->working_count - index - 1u)
                * sizeof(*storage->working));
        storage->working_count -= 1u;
        (void)memset(
            &storage->working[storage->working_count],
            0,
            sizeof(*storage->working));
    }
    return NINLIL_STORAGE_OK;
}

static int prefix_matches(
    const consumer_entry_t *entry,
    ninlil_bytes_view_t prefix)
{
    return entry->key_length >= prefix.length
        && (prefix.length == 0u
            || memcmp(entry->key, prefix.data, prefix.length) == 0);
}

static ninlil_storage_status_t memory_iter_open(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iterator)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    consumer_iterator_t *iterator = NULL;
    size_t match_count = 0u;
    size_t source_index;
    size_t target_index = 0u;
    size_t slot;

    if (storage == NULL || !transaction_matches(storage, transaction)
        || !view_is_valid(prefix, 0u, CONSUMER_STORAGE_MAX_KEY_BYTES)
        || out_iterator == NULL || *out_iterator != NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    for (slot = 0u; slot < CONSUMER_STORAGE_MAX_ITERATORS; ++slot) {
        if (!storage->iterators[slot].active) {
            iterator = &storage->iterators[slot];
            break;
        }
    }
    if (iterator == NULL) {
        return NINLIL_STORAGE_BUSY;
    }
    for (source_index = 0u;
         source_index < storage->working_count;
         ++source_index) {
        if (prefix_matches(&storage->working[source_index], prefix)) {
            match_count += 1u;
        }
    }
    if (match_count != 0u) {
        iterator->rows = (consumer_entry_t *)calloc(
            match_count, sizeof(*iterator->rows));
        if (iterator->rows == NULL) {
            return NINLIL_STORAGE_NO_SPACE;
        }
        for (source_index = 0u;
             source_index < storage->working_count;
             ++source_index) {
            const consumer_entry_t *source =
                &storage->working[source_index];
            consumer_entry_t *target;
            if (!prefix_matches(source, prefix)) {
                continue;
            }
            target = &iterator->rows[target_index];
            target->key_length = source->key_length;
            (void)memcpy(
                target->key,
                source->key,
                (size_t)source->key_length);
            target->value_length = source->value_length;
            if (!value_copy(
                    source->value,
                    source->value_length,
                    &target->value)) {
                entries_reset(iterator->rows, match_count);
                (void)memset(iterator, 0, sizeof(*iterator));
                return NINLIL_STORAGE_NO_SPACE;
            }
            target_index += 1u;
        }
    }
    iterator->row_count = match_count;
    iterator->position = 0u;
    iterator->active = 1;
    storage->live_iterator_count += 1u;
    *out_iterator = (ninlil_storage_iter_t)iterator;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t memory_iter_next(
    void *user,
    ninlil_storage_iter_t opaque,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    consumer_iterator_t *iterator;
    const consumer_entry_t *entry;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    iterator = iterator_find(storage, opaque);
    if (iterator == NULL || !mutable_view_is_valid(inout_key)
        || !mutable_view_is_valid(inout_value)
        || !mutable_ranges_do_not_overlap(inout_key, inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (iterator->position >= iterator->row_count) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    entry = &iterator->rows[iterator->position];
    inout_key->length = entry->key_length;
    inout_value->length = entry->value_length;
    if (inout_key->capacity < entry->key_length
        || inout_value->capacity < entry->value_length) {
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    (void)memcpy(inout_key->data, entry->key, entry->key_length);
    if (entry->value_length != 0u) {
        (void)memcpy(
            inout_value->data,
            entry->value,
            (size_t)entry->value_length);
    }
    iterator->position += 1u;
    return NINLIL_STORAGE_OK;
}

static void memory_iter_close(
    void *user,
    ninlil_storage_iter_t opaque)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    consumer_iterator_t *iterator;

    if (storage == NULL) {
        return;
    }
    iterator = iterator_find(storage, opaque);
    if (iterator != NULL) {
        iterator_reset(iterator);
        storage->live_iterator_count -= 1u;
    }
}

static ninlil_storage_status_t memory_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    uint64_t used_bytes;

    if (storage == NULL || !handle_matches(storage, handle)
        || out_capacity == NULL
        || out_capacity->abi_version != NINLIL_ABI_VERSION
        || out_capacity->struct_size < sizeof(*out_capacity)
        || !usage_is_valid(
            storage->committed,
            storage->committed_count,
            &used_bytes)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    out_capacity->max_entries = CONSUMER_STORAGE_MAX_ENTRIES;
    out_capacity->used_entries = storage->committed_count;
    out_capacity->max_bytes = CONSUMER_STORAGE_MAX_BYTES;
    out_capacity->used_bytes = used_bytes;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t memory_commit(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_durability_t durability)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;
    uint64_t used_bytes;

    if (storage == NULL || !transaction_matches(storage, transaction)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (durability != NINLIL_DURABILITY_FULL) {
        transaction_reset(storage);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (!usage_is_valid(
            storage->working, storage->working_count, &used_bytes)) {
        transaction_reset(storage);
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (storage->transaction_mode == NINLIL_STORAGE_READ_WRITE) {
        entries_reset(storage->committed, storage->committed_count);
        storage->committed = storage->working;
        storage->committed_count = storage->working_count;
        storage->working = NULL;
        storage->working_count = 0u;
    }
    transaction_reset(storage);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t memory_rollback(
    void *user,
    ninlil_storage_txn_t transaction)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)user;

    if (storage == NULL || !transaction_matches(storage, transaction)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction_reset(storage);
    return NINLIL_STORAGE_OK;
}

consumer_memory_storage_t *consumer_memory_storage_create(void)
{
    consumer_memory_storage_t *storage =
        (consumer_memory_storage_t *)calloc(1u, sizeof(*storage));

    if (storage == NULL) {
        return NULL;
    }
    storage->ops.abi_version = NINLIL_ABI_VERSION;
    storage->ops.struct_size = (uint16_t)sizeof(storage->ops);
    storage->ops.user = storage;
    storage->ops.open = memory_open;
    storage->ops.close = memory_close;
    storage->ops.begin = memory_begin;
    storage->ops.get = memory_get;
    storage->ops.put = memory_put;
    storage->ops.erase = memory_erase;
    storage->ops.iter_open = memory_iter_open;
    storage->ops.iter_next = memory_iter_next;
    storage->ops.iter_close = memory_iter_close;
    storage->ops.capacity = memory_capacity;
    storage->ops.commit = memory_commit;
    storage->ops.rollback = memory_rollback;
    return storage;
}

void consumer_memory_storage_destroy(consumer_memory_storage_t *storage)
{
    if (storage == NULL) {
        return;
    }
    if (storage->transaction_active) {
        transaction_reset(storage);
    }
    entries_reset(storage->committed, storage->committed_count);
    free(storage);
}

const ninlil_storage_ops_t *consumer_memory_storage_ops(
    consumer_memory_storage_t *storage)
{
    return storage == NULL ? NULL : &storage->ops;
}

uint64_t consumer_memory_storage_live_handles(
    const consumer_memory_storage_t *storage)
{
    return storage != NULL && storage->handle_open ? 1u : 0u;
}

uint64_t consumer_memory_storage_live_transactions(
    const consumer_memory_storage_t *storage)
{
    return storage != NULL && storage->transaction_active ? 1u : 0u;
}

uint64_t consumer_memory_storage_live_iterators(
    const consumer_memory_storage_t *storage)
{
    return storage == NULL ? 0u : storage->live_iterator_count;
}
