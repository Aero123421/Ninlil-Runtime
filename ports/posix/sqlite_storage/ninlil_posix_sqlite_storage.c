#include "ninlil_posix_sqlite_storage.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

/*
 * POSIX SQLite durable storage port (production candidate for host PC).
 *
 * Durability claim (docs/08, docs/14):
 *   PRAGMA journal_mode=WAL;
 *   PRAGMA synchronous=FULL;
 *   PRAGMA foreign_keys=ON;
 * FULL commit success means the atomic group crossed the SQLite durability
 * boundary under those settings. Filesystem or hardware that lies about flush
 * is outside the claim.
 *
 * Fault model:
 *   BUSY       - lock/busy after configured timeout, or exclusive lease/RW held
 *   NO_SPACE   - logical capacity, single-value bound, SQLITE_FULL/ENOSPC
 *   IO_ERROR   - definite I/O failure with non-commit guarantee
 *   CORRUPT    - integrity / contract shape failure
 *   COMMIT_UNKNOWN - commit result not classifiable as committed or not
 *   UNSUPPORTED_SCHEMA - meta schema_version mismatch (no auto-migration)
 *
 * Namespace identity is exact BLOB bytes (1..255), never a path string.
 * KGuard vocabulary is absent from this translation unit.
 */

typedef struct storage_entry {
    uint8_t *key;
    uint32_t key_length;
    uint8_t *value;
    uint32_t value_length;
} storage_entry_t;

typedef struct storage_handle storage_handle_t;
typedef struct storage_transaction storage_transaction_t;
typedef struct storage_iterator storage_iterator_t;

struct storage_iterator {
    int in_use;
    storage_transaction_t *transaction;
    storage_entry_t *rows;
    size_t row_count;
    size_t position;
};

struct storage_transaction {
    int in_use;
    storage_handle_t *handle;
    ninlil_storage_mode_t mode;
    storage_entry_t *view;
    size_t view_count;
    size_t view_capacity;
    uint32_t open_iterator_mask;
};

struct storage_handle {
    int in_use;
    int leased;
    uint8_t name[255];
    uint32_t name_length;
    uint32_t schema;
    int has_writer;
    uint32_t open_txn_mask;
};

struct ninlil_posix_sqlite_storage {
    ninlil_storage_ops_t ops;
    ninlil_posix_sqlite_storage_config_t config;
    sqlite3 *db;
    storage_handle_t *handles;
    storage_transaction_t *transactions;
    storage_iterator_t *iterators;
    uint32_t max_handles;
    uint32_t max_transactions;
    uint32_t max_iterators;
    uint64_t live_handles;
    uint64_t live_transactions;
    uint64_t live_iterators;
    ninlil_posix_sqlite_commit_fault_t commit_fault;
    char *path_copy;
};

static ninlil_storage_status_t port_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle);
static void port_close(void *user, ninlil_storage_handle_t handle);
static ninlil_storage_status_t port_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn);
static ninlil_storage_status_t port_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value);
static ninlil_storage_status_t port_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);
static ninlil_storage_status_t port_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key);
static ninlil_storage_status_t port_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter);
static ninlil_storage_status_t port_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value);
static void port_iter_close(void *user, ninlil_storage_iter_t iter);
static ninlil_storage_status_t port_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity);
static ninlil_storage_status_t port_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability);
static ninlil_storage_status_t port_rollback(
    void *user,
    ninlil_storage_txn_t txn);

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
    int compared = common == 0u ? 0 : memcmp(left, right, (size_t)common);

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

static void free_entry(storage_entry_t *entry)
{
    free(entry->key);
    free(entry->value);
    (void)memset(entry, 0, sizeof(*entry));
}

static void free_entries(storage_entry_t *entries, size_t count)
{
    size_t index;

    if (entries == NULL) {
        return;
    }
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
    (void)memcpy(copy, source, (size_t)length);
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

static int prefix_matches(
    const storage_entry_t *entry,
    ninlil_bytes_view_t prefix)
{
    return entry->key_length >= prefix.length
        && (prefix.length == 0u
            || memcmp(entry->key, prefix.data, (size_t)prefix.length) == 0);
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

static ninlil_storage_status_t map_sqlite_rc(int rc)
{
    switch (rc) {
    case SQLITE_OK:
    case SQLITE_DONE:
    case SQLITE_ROW:
        return NINLIL_STORAGE_OK;
    case SQLITE_BUSY:
    case SQLITE_LOCKED:
        return NINLIL_STORAGE_BUSY;
    case SQLITE_FULL:
    case SQLITE_NOMEM:
        return NINLIL_STORAGE_NO_SPACE;
    case SQLITE_CORRUPT:
    case SQLITE_NOTADB:
    case SQLITE_FORMAT:
        return NINLIL_STORAGE_CORRUPT;
    case SQLITE_IOERR:
        return NINLIL_STORAGE_IO_ERROR;
    default:
        return NINLIL_STORAGE_IO_ERROR;
    }
}

static ninlil_storage_status_t exec_sql(
    sqlite3 *db,
    const char *sql)
{
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);

    if (errmsg != NULL) {
        sqlite3_free(errmsg);
    }
    return map_sqlite_rc(rc);
}

static ninlil_storage_status_t configure_connection(
    sqlite3 *db,
    uint32_t busy_timeout_ms)
{
    ninlil_storage_status_t status;
    int rc;
    sqlite3_stmt *stmt = NULL;
    const char *mode = NULL;

    rc = sqlite3_busy_timeout(db, (int)busy_timeout_ms);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    status = exec_sql(db, "PRAGMA foreign_keys = ON;");
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    status = exec_sql(db, "PRAGMA journal_mode = WAL;");
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    status = exec_sql(db, "PRAGMA synchronous = FULL;");
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    rc = sqlite3_prepare_v2(db, "PRAGMA journal_mode;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        (void)sqlite3_finalize(stmt);
        return map_sqlite_rc(rc == SQLITE_DONE ? SQLITE_ERROR : rc);
    }
    mode = (const char *)sqlite3_column_text(stmt, 0);
    if (mode == NULL
        || (strcmp(mode, "wal") != 0 && strcmp(mode, "WAL") != 0)) {
        (void)sqlite3_finalize(stmt);
        return NINLIL_STORAGE_IO_ERROR;
    }
    (void)sqlite3_finalize(stmt);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t read_schema_version(
    sqlite3 *db,
    uint32_t *out_version,
    int *out_present)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    *out_version = 0u;
    *out_present = 0;
    rc = sqlite3_prepare_v2(
        db,
        "SELECT value FROM ninlil_meta WHERE key = 'schema_version';",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_ERROR) {
        return NINLIL_STORAGE_OK; /* table missing => new database path */
    }
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        sqlite3_int64 value = sqlite3_column_int64(stmt, 0);
        if (value < 0 || value > (sqlite3_int64)UINT32_MAX) {
            (void)sqlite3_finalize(stmt);
            return NINLIL_STORAGE_CORRUPT;
        }
        *out_version = (uint32_t)value;
        *out_present = 1;
        (void)sqlite3_finalize(stmt);
        return NINLIL_STORAGE_OK;
    }
    (void)sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) {
        return NINLIL_STORAGE_OK;
    }
    return map_sqlite_rc(rc);
}

static ninlil_storage_status_t initialize_schema(sqlite3 *db)
{
    static const char *const ddl =
        "BEGIN IMMEDIATE;"
        "CREATE TABLE IF NOT EXISTS ninlil_meta ("
        "  key TEXT PRIMARY KEY NOT NULL,"
        "  value INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS ninlil_kv ("
        "  namespace BLOB NOT NULL,"
        "  key BLOB NOT NULL,"
        "  value BLOB NOT NULL,"
        "  PRIMARY KEY (namespace, key)"
        ") WITHOUT ROWID;"
        "CREATE TABLE IF NOT EXISTS ninlil_lease ("
        "  namespace BLOB PRIMARY KEY NOT NULL,"
        "  generation INTEGER NOT NULL"
        ") WITHOUT ROWID;"
        "INSERT OR REPLACE INTO ninlil_meta(key, value)"
        "  VALUES('schema_version', 1);"
        "INSERT OR REPLACE INTO ninlil_meta(key, value)"
        "  VALUES('migration_state', 0);"
        "COMMIT;";

    return exec_sql(db, ddl);
}

static ninlil_storage_status_t ensure_schema(sqlite3 *db)
{
    uint32_t version = 0u;
    int present = 0;
    ninlil_storage_status_t status = read_schema_version(db, &version, &present);

    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    if (!present) {
        /* Distinguish missing meta table from empty meta after partial create. */
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(
            db,
            "SELECT 1 FROM sqlite_master"
            " WHERE type='table' AND name='ninlil_meta';",
            -1,
            &stmt,
            NULL);
        if (rc != SQLITE_OK) {
            return map_sqlite_rc(rc);
        }
        rc = sqlite3_step(stmt);
        (void)sqlite3_finalize(stmt);
        if (rc == SQLITE_ROW) {
            /* meta table exists without schema_version => corrupt/unsupported */
            return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
        }
        if (rc != SQLITE_DONE) {
            return map_sqlite_rc(rc);
        }
        return initialize_schema(db);
    }
    if (version != NINLIL_POSIX_SQLITE_SCHEMA_VERSION) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    return NINLIL_STORAGE_OK;
}

static storage_handle_t *find_handle(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_handle_t opaque)
{
    uintptr_t index;

    if (opaque == NULL || storage == NULL) {
        return NULL;
    }
    index = (uintptr_t)opaque - 1u;
    if (index >= storage->max_handles) {
        return NULL;
    }
    if (!storage->handles[index].in_use) {
        return NULL;
    }
    return &storage->handles[index];
}

static storage_transaction_t *find_transaction(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_txn_t opaque)
{
    uintptr_t index;

    if (opaque == NULL || storage == NULL) {
        return NULL;
    }
    index = (uintptr_t)opaque - 1u;
    if (index >= storage->max_transactions) {
        return NULL;
    }
    if (!storage->transactions[index].in_use) {
        return NULL;
    }
    return &storage->transactions[index];
}

static storage_iterator_t *find_iterator(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_iter_t opaque)
{
    uintptr_t index;

    if (opaque == NULL || storage == NULL) {
        return NULL;
    }
    index = (uintptr_t)opaque - 1u;
    if (index >= storage->max_iterators) {
        return NULL;
    }
    if (!storage->iterators[index].in_use) {
        return NULL;
    }
    return &storage->iterators[index];
}

static ninlil_storage_handle_t handle_to_opaque(
    ninlil_posix_sqlite_storage_t *storage,
    storage_handle_t *handle)
{
    return (ninlil_storage_handle_t)(
        (uintptr_t)(handle - storage->handles) + 1u);
}

static ninlil_storage_txn_t txn_to_opaque(
    ninlil_posix_sqlite_storage_t *storage,
    storage_transaction_t *transaction)
{
    return (ninlil_storage_txn_t)(
        (uintptr_t)(transaction - storage->transactions) + 1u);
}

static ninlil_storage_iter_t iter_to_opaque(
    ninlil_posix_sqlite_storage_t *storage,
    storage_iterator_t *iterator)
{
    return (ninlil_storage_iter_t)(
        (uintptr_t)(iterator - storage->iterators) + 1u);
}

static storage_handle_t *find_leased_namespace(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_bytes_view_t name)
{
    uint32_t index;

    for (index = 0u; index < storage->max_handles; ++index) {
        storage_handle_t *candidate = &storage->handles[index];
        if (candidate->in_use
            && candidate->leased
            && candidate->name_length == name.length
            && memcmp(candidate->name, name.data, name.length) == 0) {
            return candidate;
        }
    }
    return NULL;
}

static void release_iterator(
    ninlil_posix_sqlite_storage_t *storage,
    storage_iterator_t *iterator)
{
    storage_transaction_t *transaction;
    uint32_t index;

    if (iterator == NULL || !iterator->in_use) {
        return;
    }
    transaction = iterator->transaction;
    index = (uint32_t)(iterator - storage->iterators);
    if (transaction != NULL && transaction->in_use) {
        transaction->open_iterator_mask &= ~(1u << index);
    }
    free_entries(iterator->rows, iterator->row_count);
    (void)memset(iterator, 0, sizeof(*iterator));
    if (storage->live_iterators > 0u) {
        storage->live_iterators -= 1u;
    }
}

static void consume_iterators(
    ninlil_posix_sqlite_storage_t *storage,
    storage_transaction_t *transaction)
{
    uint32_t index;

    for (index = 0u; index < storage->max_iterators; ++index) {
        if ((transaction->open_iterator_mask & (1u << index)) != 0u) {
            release_iterator(storage, &storage->iterators[index]);
        }
    }
    transaction->open_iterator_mask = 0u;
}

static void release_transaction(
    ninlil_posix_sqlite_storage_t *storage,
    storage_transaction_t *transaction,
    int keep_view)
{
    storage_handle_t *handle;
    uint32_t index;

    if (transaction == NULL || !transaction->in_use) {
        return;
    }
    handle = transaction->handle;
    consume_iterators(storage, transaction);
    if (transaction->mode == NINLIL_STORAGE_READ_WRITE && handle != NULL) {
        handle->has_writer = 0;
    }
    if (handle != NULL && handle->in_use) {
        index = (uint32_t)(transaction - storage->transactions);
        handle->open_txn_mask &= ~(1u << index);
    }
    if (!keep_view) {
        free_entries(transaction->view, transaction->view_count);
    }
    (void)memset(transaction, 0, sizeof(*transaction));
    if (storage->live_transactions > 0u) {
        storage->live_transactions -= 1u;
    }
}

static void force_close_handle(
    ninlil_posix_sqlite_storage_t *storage,
    storage_handle_t *handle)
{
    uint32_t index;

    if (handle == NULL || !handle->in_use) {
        return;
    }
    for (index = 0u; index < storage->max_transactions; ++index) {
        if ((handle->open_txn_mask & (1u << index)) != 0u) {
            release_transaction(
                storage, &storage->transactions[index], 0);
        }
    }
    (void)memset(handle, 0, sizeof(*handle));
    if (storage->live_handles > 0u) {
        storage->live_handles -= 1u;
    }
}

static ninlil_storage_status_t load_namespace_view(
    ninlil_posix_sqlite_storage_t *storage,
    const storage_handle_t *handle,
    storage_entry_t **out_entries,
    size_t *out_count)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    storage_entry_t *entries = NULL;
    size_t count = 0u;
    size_t capacity = 0u;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;

    *out_entries = NULL;
    *out_count = 0u;
    rc = sqlite3_prepare_v2(
        storage->db,
        "SELECT key, value FROM ninlil_kv"
        " WHERE namespace = ?1 ORDER BY key ASC;",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    rc = sqlite3_bind_blob(
        stmt, 1, handle->name, (int)handle->name_length, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return map_sqlite_rc(rc);
    }
    for (;;) {
        const void *key_ptr;
        const void *value_ptr;
        int key_len;
        int value_len;
        storage_entry_t *slot;

        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            status = map_sqlite_rc(rc);
            break;
        }
        key_ptr = sqlite3_column_blob(stmt, 0);
        key_len = sqlite3_column_bytes(stmt, 0);
        value_ptr = sqlite3_column_blob(stmt, 1);
        value_len = sqlite3_column_bytes(stmt, 1);
        if (key_len < 1 || key_len > 255
            || value_len < 0
            || (uint32_t)value_len > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES
            || (key_len > 0 && key_ptr == NULL)) {
            status = NINLIL_STORAGE_CORRUPT;
            break;
        }
        if ((uint64_t)count >= storage->config.max_entries_per_namespace) {
            status = NINLIL_STORAGE_CORRUPT;
            break;
        }
        if (count == capacity) {
            size_t next = capacity == 0u ? 8u : capacity * 2u;
            storage_entry_t *grown;

            if (next < capacity
                || next > (size_t)storage->config.max_entries_per_namespace) {
                next = (size_t)storage->config.max_entries_per_namespace;
            }
            if (next <= capacity) {
                status = NINLIL_STORAGE_NO_SPACE;
                break;
            }
            if (next > SIZE_MAX / sizeof(*grown)) {
                status = NINLIL_STORAGE_NO_SPACE;
                break;
            }
            grown = (storage_entry_t *)realloc(
                entries, next * sizeof(*grown));
            if (grown == NULL) {
                status = NINLIL_STORAGE_NO_SPACE;
                break;
            }
            (void)memset(
                grown + capacity, 0, (next - capacity) * sizeof(*grown));
            entries = grown;
            capacity = next;
        }
        slot = &entries[count];
        slot->key_length = (uint32_t)key_len;
        slot->value_length = (uint32_t)value_len;
        if (!copy_bytes((const uint8_t *)key_ptr, slot->key_length, &slot->key)
            || !copy_bytes(
                value_len == 0 ? NULL : (const uint8_t *)value_ptr,
                slot->value_length,
                &slot->value)) {
            free_entry(slot);
            status = NINLIL_STORAGE_NO_SPACE;
            break;
        }
        count += 1u;
    }
    (void)sqlite3_finalize(stmt);
    if (status != NINLIL_STORAGE_OK) {
        free_entries(entries, count);
        return status;
    }
    *out_entries = entries;
    *out_count = count;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t persist_namespace_view(
    ninlil_posix_sqlite_storage_t *storage,
    const storage_handle_t *handle,
    const storage_entry_t *entries,
    size_t count)
{
    sqlite3_stmt *del = NULL;
    sqlite3_stmt *ins = NULL;
    int rc;
    size_t index;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;

    rc = sqlite3_exec(storage->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    rc = sqlite3_prepare_v2(
        storage->db,
        "DELETE FROM ninlil_kv WHERE namespace = ?1;",
        -1,
        &del,
        NULL);
    if (rc != SQLITE_OK) {
        status = map_sqlite_rc(rc);
        goto abort_tx;
    }
    rc = sqlite3_bind_blob(
        del, 1, handle->name, (int)handle->name_length, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        status = map_sqlite_rc(rc);
        goto abort_tx;
    }
    rc = sqlite3_step(del);
    if (rc != SQLITE_DONE) {
        status = map_sqlite_rc(rc);
        goto abort_tx;
    }
    (void)sqlite3_finalize(del);
    del = NULL;

    rc = sqlite3_prepare_v2(
        storage->db,
        "INSERT INTO ninlil_kv(namespace, key, value) VALUES(?1, ?2, ?3);",
        -1,
        &ins,
        NULL);
    if (rc != SQLITE_OK) {
        status = map_sqlite_rc(rc);
        goto abort_tx;
    }
    for (index = 0u; index < count; ++index) {
        rc = sqlite3_reset(ins);
        if (rc != SQLITE_OK) {
            status = map_sqlite_rc(rc);
            goto abort_tx;
        }
        rc = sqlite3_clear_bindings(ins);
        if (rc != SQLITE_OK) {
            status = map_sqlite_rc(rc);
            goto abort_tx;
        }
        rc = sqlite3_bind_blob(
            ins, 1, handle->name, (int)handle->name_length, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            status = map_sqlite_rc(rc);
            goto abort_tx;
        }
        rc = sqlite3_bind_blob(
            ins,
            2,
            entries[index].key,
            (int)entries[index].key_length,
            SQLITE_TRANSIENT);
        if (rc != SQLITE_OK) {
            status = map_sqlite_rc(rc);
            goto abort_tx;
        }
        if (entries[index].value_length == 0u) {
            rc = sqlite3_bind_zeroblob(ins, 3, 0);
        } else {
            rc = sqlite3_bind_blob(
                ins,
                3,
                entries[index].value,
                (int)entries[index].value_length,
                SQLITE_TRANSIENT);
        }
        if (rc != SQLITE_OK) {
            status = map_sqlite_rc(rc);
            goto abort_tx;
        }
        rc = sqlite3_step(ins);
        if (rc != SQLITE_DONE) {
            status = map_sqlite_rc(rc);
            goto abort_tx;
        }
    }
    (void)sqlite3_finalize(ins);
    ins = NULL;
    rc = sqlite3_exec(storage->db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        /*
         * Once COMMIT has been attempted, a non-OK result may leave the
         * durable outcome unclassified. Prefer COMMIT_UNKNOWN over guessing.
         */
        if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
            (void)sqlite3_exec(storage->db, "ROLLBACK;", NULL, NULL, NULL);
            return NINLIL_STORAGE_BUSY;
        }
        if (rc == SQLITE_FULL) {
            (void)sqlite3_exec(storage->db, "ROLLBACK;", NULL, NULL, NULL);
            return NINLIL_STORAGE_NO_SPACE;
        }
        if (rc == SQLITE_CORRUPT || rc == SQLITE_NOTADB) {
            (void)sqlite3_exec(storage->db, "ROLLBACK;", NULL, NULL, NULL);
            return NINLIL_STORAGE_CORRUPT;
        }
        (void)sqlite3_exec(storage->db, "ROLLBACK;", NULL, NULL, NULL);
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    return NINLIL_STORAGE_OK;

abort_tx:
    if (del != NULL) {
        (void)sqlite3_finalize(del);
    }
    if (ins != NULL) {
        (void)sqlite3_finalize(ins);
    }
    (void)sqlite3_exec(storage->db, "ROLLBACK;", NULL, NULL, NULL);
    return status;
}

static ninlil_storage_status_t port_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_handle_t *handle = NULL;
    uint32_t index;

    if (storage == NULL || out_handle == NULL || *out_handle != NULL
        || !view_shape_is_valid(storage_namespace, 1u, 255u)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (expected_schema != NINLIL_STORAGE_SCHEMA_M1A) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (find_leased_namespace(storage, storage_namespace) != NULL) {
        return NINLIL_STORAGE_BUSY;
    }
    for (index = 0u; index < storage->max_handles; ++index) {
        if (!storage->handles[index].in_use) {
            handle = &storage->handles[index];
            break;
        }
    }
    if (handle == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    (void)memset(handle, 0, sizeof(*handle));
    handle->in_use = 1;
    handle->leased = 1;
    handle->name_length = storage_namespace.length;
    handle->schema = expected_schema;
    (void)memcpy(
        handle->name, storage_namespace.data, storage_namespace.length);
    storage->live_handles += 1u;
    *out_handle = handle_to_opaque(storage, handle);
    return NINLIL_STORAGE_OK;
}

static void port_close(void *user, ninlil_storage_handle_t opaque)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_handle_t *handle;

    if (storage == NULL) {
        return;
    }
    handle = find_handle(storage, opaque);
    if (handle != NULL) {
        force_close_handle(storage, handle);
    }
}

static ninlil_storage_status_t port_begin(
    void *user,
    ninlil_storage_handle_t opaque,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_handle_t *handle;
    storage_transaction_t *transaction = NULL;
    storage_entry_t *view = NULL;
    size_t view_count = 0u;
    ninlil_storage_status_t status;
    uint32_t index;

    if (storage == NULL || out_txn == NULL || *out_txn != NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    handle = find_handle(storage, opaque);
    if (handle == NULL
        || (mode != NINLIL_STORAGE_READ_ONLY
            && mode != NINLIL_STORAGE_READ_WRITE)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (mode == NINLIL_STORAGE_READ_WRITE && handle->has_writer) {
        return NINLIL_STORAGE_BUSY;
    }
    for (index = 0u; index < storage->max_transactions; ++index) {
        if (!storage->transactions[index].in_use) {
            transaction = &storage->transactions[index];
            break;
        }
    }
    if (transaction == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    status = load_namespace_view(storage, handle, &view, &view_count);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    (void)memset(transaction, 0, sizeof(*transaction));
    transaction->in_use = 1;
    transaction->handle = handle;
    transaction->mode = mode;
    transaction->view = view;
    transaction->view_count = view_count;
    transaction->view_capacity = view_count;
    handle->open_txn_mask |= 1u << index;
    if (mode == NINLIL_STORAGE_READ_WRITE) {
        handle->has_writer = 1;
    }
    storage->live_transactions += 1u;
    *out_txn = txn_to_opaque(storage, transaction);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_get(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_transaction_t *transaction;
    int found;
    size_t index;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || !view_shape_is_valid(key, 1u, 255u)
        || !mut_shape_is_valid(inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    index = find_entry(transaction->view, transaction->view_count, key, &found);
    if (!found) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (transaction->view[index].value_length > inout_value->capacity) {
        inout_value->length = transaction->view[index].value_length;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (transaction->view[index].value_length != 0u) {
        (void)memcpy(
            inout_value->data,
            transaction->view[index].value,
            transaction->view[index].value_length);
    }
    inout_value->length = transaction->view[index].value_length;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_put(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_transaction_t *transaction;
    storage_entry_t *entries;
    uint8_t *key_copy = NULL;
    uint8_t *value_copy = NULL;
    int found;
    size_t index;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || transaction->mode != NINLIL_STORAGE_READ_WRITE
        || !view_shape_is_valid(key, 1u, 255u)
        || !view_shape_is_valid(value, 0u, UINT32_MAX)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (value.length > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    index = find_entry(transaction->view, transaction->view_count, key, &found);
    if (!copy_bytes(value.data, value.length, &value_copy)) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (found) {
        free(transaction->view[index].value);
        transaction->view[index].value = value_copy;
        transaction->view[index].value_length = value.length;
        return NINLIL_STORAGE_OK;
    }
    if (!copy_bytes(key.data, key.length, &key_copy)) {
        free(value_copy);
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (transaction->view_count
        >= (size_t)storage->config.max_entries_per_namespace) {
        free(key_copy);
        free(value_copy);
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (transaction->view_count == transaction->view_capacity) {
        size_t next = transaction->view_capacity == 0u
            ? 4u
            : transaction->view_capacity * 2u;
        if (next < transaction->view_capacity
            || next > (size_t)storage->config.max_entries_per_namespace) {
            next = (size_t)storage->config.max_entries_per_namespace;
        }
        if (next <= transaction->view_capacity
            || next > SIZE_MAX / sizeof(*entries)) {
            free(key_copy);
            free(value_copy);
            return NINLIL_STORAGE_NO_SPACE;
        }
        entries = (storage_entry_t *)realloc(
            transaction->view, next * sizeof(*entries));
        if (entries == NULL) {
            free(key_copy);
            free(value_copy);
            return NINLIL_STORAGE_NO_SPACE;
        }
        (void)memset(
            entries + transaction->view_capacity,
            0,
            (next - transaction->view_capacity) * sizeof(*entries));
        transaction->view = entries;
        transaction->view_capacity = next;
    } else {
        entries = transaction->view;
    }
    (void)memmove(
        &entries[index + 1u],
        &entries[index],
        (transaction->view_count - index) * sizeof(*entries));
    entries[index].key = key_copy;
    entries[index].key_length = key.length;
    entries[index].value = value_copy;
    entries[index].value_length = value.length;
    transaction->view_count += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_erase(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_transaction_t *transaction;
    int found;
    size_t index;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || transaction->mode != NINLIL_STORAGE_READ_WRITE
        || !view_shape_is_valid(key, 1u, 255u)) {
        return NINLIL_STORAGE_CORRUPT;
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
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_iter_open(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_transaction_t *transaction;
    storage_iterator_t *iterator = NULL;
    storage_entry_t *rows = NULL;
    size_t matches = 0u;
    size_t index;
    size_t target = 0u;
    uint32_t slot;

    if (storage == NULL || out_iter == NULL || *out_iter != NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL || !view_shape_is_valid(prefix, 0u, 255u)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    for (slot = 0u; slot < storage->max_iterators; ++slot) {
        if (!storage->iterators[slot].in_use) {
            iterator = &storage->iterators[slot];
            break;
        }
    }
    if (iterator == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    for (index = 0u; index < transaction->view_count; ++index) {
        if (prefix_matches(&transaction->view[index], prefix)) {
            matches += 1u;
        }
    }
    if (matches != 0u) {
        if (matches > SIZE_MAX / sizeof(*rows)) {
            return NINLIL_STORAGE_NO_SPACE;
        }
        rows = (storage_entry_t *)calloc(matches, sizeof(*rows));
        if (rows == NULL) {
            return NINLIL_STORAGE_NO_SPACE;
        }
        for (index = 0u; index < transaction->view_count; ++index) {
            const storage_entry_t *source = &transaction->view[index];
            storage_entry_t *destination;
            if (!prefix_matches(source, prefix)) {
                continue;
            }
            destination = &rows[target];
            destination->key_length = source->key_length;
            destination->value_length = source->value_length;
            if (!copy_bytes(
                    source->key, source->key_length, &destination->key)
                || !copy_bytes(
                    source->value,
                    source->value_length,
                    &destination->value)) {
                free_entries(rows, matches);
                return NINLIL_STORAGE_NO_SPACE;
            }
            target += 1u;
        }
    }
    (void)memset(iterator, 0, sizeof(*iterator));
    iterator->in_use = 1;
    iterator->transaction = transaction;
    iterator->rows = rows;
    iterator->row_count = matches;
    iterator->position = 0u;
    transaction->open_iterator_mask |= 1u << slot;
    storage->live_iterators += 1u;
    *out_iter = iter_to_opaque(storage, iterator);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_iter_next(
    void *user,
    ninlil_storage_iter_t opaque,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_iterator_t *iterator;
    storage_entry_t *row;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    iterator = find_iterator(storage, opaque);
    if (iterator == NULL || !mut_shape_is_valid(inout_key)
        || !mut_shape_is_valid(inout_value)
        || !mut_ranges_do_not_overlap(inout_key, inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (iterator->position >= iterator->row_count) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    row = &iterator->rows[iterator->position];
    if (row->key_length > inout_key->capacity
        || row->value_length > inout_value->capacity) {
        inout_key->length = row->key_length;
        inout_value->length = row->value_length;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (row->key_length != 0u) {
        (void)memcpy(inout_key->data, row->key, row->key_length);
    }
    if (row->value_length != 0u) {
        (void)memcpy(inout_value->data, row->value, row->value_length);
    }
    inout_key->length = row->key_length;
    inout_value->length = row->value_length;
    iterator->position += 1u;
    return NINLIL_STORAGE_OK;
}

static void port_iter_close(void *user, ninlil_storage_iter_t opaque)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_iterator_t *iterator;

    if (storage == NULL) {
        return;
    }
    iterator = find_iterator(storage, opaque);
    if (iterator != NULL) {
        release_iterator(storage, iterator);
    }
}

static ninlil_storage_status_t port_capacity(
    void *user,
    ninlil_storage_handle_t opaque,
    ninlil_storage_capacity_t *out_capacity)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_handle_t *handle;
    storage_entry_t *entries = NULL;
    size_t count = 0u;
    uint64_t used_entries = 0u;
    uint64_t used_bytes = 0u;
    ninlil_storage_status_t status;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    handle = find_handle(storage, opaque);
    if (handle == NULL || !capacity_output_is_valid(out_capacity)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    out_capacity->max_entries = 0u;
    out_capacity->used_entries = 0u;
    out_capacity->max_bytes = 0u;
    out_capacity->used_bytes = 0u;
    status = load_namespace_view(storage, handle, &entries, &count);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    if (!logical_usage(entries, count, &used_entries, &used_bytes)) {
        free_entries(entries, count);
        return NINLIL_STORAGE_CORRUPT;
    }
    free_entries(entries, count);
    out_capacity->max_entries = storage->config.max_entries_per_namespace;
    out_capacity->used_entries = used_entries;
    out_capacity->max_bytes = storage->config.max_bytes_per_namespace;
    out_capacity->used_bytes = used_bytes;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_commit(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_durability_t durability)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_transaction_t *transaction;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;
    ninlil_posix_sqlite_commit_fault_t fault;
    storage_entry_t *view;
    size_t view_count;
    storage_handle_t *handle;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (durability != NINLIL_DURABILITY_FULL) {
        release_transaction(storage, transaction, 0);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (transaction->mode != NINLIL_STORAGE_READ_WRITE) {
        release_transaction(storage, transaction, 0);
        return NINLIL_STORAGE_OK;
    }
    {
        uint64_t entries = 0u;
        uint64_t bytes = 0u;
        if (!logical_usage(
                transaction->view,
                transaction->view_count,
                &entries,
                &bytes)) {
            release_transaction(storage, transaction, 0);
            return NINLIL_STORAGE_CORRUPT;
        }
        if (entries > storage->config.max_entries_per_namespace
            || bytes > storage->config.max_bytes_per_namespace) {
            release_transaction(storage, transaction, 0);
            return NINLIL_STORAGE_NO_SPACE;
        }
    }
    fault = storage->commit_fault;
    storage->commit_fault = NINLIL_POSIX_SQLITE_COMMIT_FAULT_NONE;
    if (fault == NINLIL_POSIX_SQLITE_COMMIT_FAULT_UNKNOWN_NOT_COMMITTED) {
        release_transaction(storage, transaction, 0);
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    view = transaction->view;
    view_count = transaction->view_count;
    handle = transaction->handle;
    transaction->view = NULL;
    transaction->view_count = 0u;
    transaction->view_capacity = 0u;
    status = persist_namespace_view(storage, handle, view, view_count);
    free_entries(view, view_count);
    release_transaction(storage, transaction, 0);
    if (fault == NINLIL_POSIX_SQLITE_COMMIT_FAULT_UNKNOWN_COMMITTED
        && status == NINLIL_STORAGE_OK) {
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    return status;
}

static ninlil_storage_status_t port_rollback(
    void *user,
    ninlil_storage_txn_t opaque)
{
    ninlil_posix_sqlite_storage_t *storage =
        (ninlil_posix_sqlite_storage_t *)user;
    storage_transaction_t *transaction;

    if (storage == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    transaction = find_transaction(storage, opaque);
    if (transaction == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    release_transaction(storage, transaction, 0);
    return NINLIL_STORAGE_OK;
}

static int config_is_valid(const ninlil_posix_sqlite_storage_config_t *config)
{
    if (config == NULL || config->database_path == NULL
        || config->database_path[0] == '\0') {
        return 0;
    }
    if (config->max_entries_per_namespace == 0u
        || config->max_entries_per_namespace == UINT64_MAX
        || config->max_bytes_per_namespace == 0u
        || config->max_bytes_per_namespace == UINT64_MAX) {
        return 0;
    }
    if (config->max_handles == 0u
        || config->max_handles > NINLIL_POSIX_SQLITE_MAX_POOL
        || config->max_transactions == 0u
        || config->max_transactions > NINLIL_POSIX_SQLITE_MAX_POOL
        || config->max_iterators == 0u
        || config->max_iterators > NINLIL_POSIX_SQLITE_MAX_POOL) {
        return 0;
    }
    /* Bitmasks for open txn/iterator tracking require pool size <= 32. */
    if (config->max_transactions > 32u || config->max_iterators > 32u) {
        return 0;
    }
    return 1;
}

ninlil_posix_sqlite_storage_t *ninlil_posix_sqlite_storage_create(
    const ninlil_posix_sqlite_storage_config_t *config)
{
    ninlil_posix_sqlite_storage_t *storage;
    sqlite3 *db = NULL;
    int rc;
    ninlil_storage_status_t status;
    size_t path_len;

    if (!config_is_valid(config)) {
        return NULL;
    }
    path_len = strlen(config->database_path);
    if (path_len == 0u || path_len > 4096u) {
        return NULL;
    }
    storage = (ninlil_posix_sqlite_storage_t *)calloc(1u, sizeof(*storage));
    if (storage == NULL) {
        return NULL;
    }
    storage->path_copy = (char *)malloc(path_len + 1u);
    if (storage->path_copy == NULL) {
        free(storage);
        return NULL;
    }
    (void)memcpy(storage->path_copy, config->database_path, path_len + 1u);
    storage->config = *config;
    storage->config.database_path = storage->path_copy;
    if (storage->config.busy_timeout_ms == 0u) {
        storage->config.busy_timeout_ms =
            NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS;
    }
    storage->max_handles = config->max_handles;
    storage->max_transactions = config->max_transactions;
    storage->max_iterators = config->max_iterators;
    storage->handles = (storage_handle_t *)calloc(
        storage->max_handles, sizeof(*storage->handles));
    storage->transactions = (storage_transaction_t *)calloc(
        storage->max_transactions, sizeof(*storage->transactions));
    storage->iterators = (storage_iterator_t *)calloc(
        storage->max_iterators, sizeof(*storage->iterators));
    if (storage->handles == NULL || storage->transactions == NULL
        || storage->iterators == NULL) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    rc = sqlite3_open_v2(
        storage->path_copy,
        &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        NULL);
    if (rc != SQLITE_OK) {
        if (db != NULL) {
            (void)sqlite3_close(db);
        }
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    status = configure_connection(db, storage->config.busy_timeout_ms);
    if (status != NINLIL_STORAGE_OK) {
        (void)sqlite3_close(db);
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    status = ensure_schema(db);
    if (status != NINLIL_STORAGE_OK) {
        (void)sqlite3_close(db);
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    storage->db = db;
    storage->ops.abi_version = NINLIL_ABI_VERSION;
    storage->ops.struct_size = (uint16_t)sizeof(storage->ops);
    storage->ops.user = storage;
    storage->ops.open = port_open;
    storage->ops.close = port_close;
    storage->ops.begin = port_begin;
    storage->ops.get = port_get;
    storage->ops.put = port_put;
    storage->ops.erase = port_erase;
    storage->ops.iter_open = port_iter_open;
    storage->ops.iter_next = port_iter_next;
    storage->ops.iter_close = port_iter_close;
    storage->ops.capacity = port_capacity;
    storage->ops.commit = port_commit;
    storage->ops.rollback = port_rollback;
    return storage;
}

void ninlil_posix_sqlite_storage_destroy(ninlil_posix_sqlite_storage_t *storage)
{
    uint32_t index;

    if (storage == NULL) {
        return;
    }
    if (storage->handles != NULL) {
        for (index = 0u; index < storage->max_handles; ++index) {
            if (storage->handles[index].in_use) {
                force_close_handle(storage, &storage->handles[index]);
            }
        }
    }
    if (storage->db != NULL) {
        (void)sqlite3_close(storage->db);
        storage->db = NULL;
    }
    free(storage->handles);
    free(storage->transactions);
    free(storage->iterators);
    free(storage->path_copy);
    free(storage);
}

const ninlil_storage_ops_t *ninlil_posix_sqlite_storage_ops(
    ninlil_posix_sqlite_storage_t *storage)
{
    if (storage == NULL) {
        return NULL;
    }
    return &storage->ops;
}

void ninlil_posix_sqlite_storage_simulate_crash(
    ninlil_posix_sqlite_storage_t *storage)
{
    uint32_t index;

    if (storage == NULL) {
        return;
    }
    for (index = 0u; index < storage->max_handles; ++index) {
        if (storage->handles[index].in_use) {
            force_close_handle(storage, &storage->handles[index]);
        }
    }
}

void ninlil_posix_sqlite_storage_set_commit_fault(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_posix_sqlite_commit_fault_t fault)
{
    if (storage == NULL) {
        return;
    }
    storage->commit_fault = fault;
}

uint64_t ninlil_posix_sqlite_storage_live_handles(
    const ninlil_posix_sqlite_storage_t *storage)
{
    return storage == NULL ? 0u : storage->live_handles;
}

uint64_t ninlil_posix_sqlite_storage_live_transactions(
    const ninlil_posix_sqlite_storage_t *storage)
{
    return storage == NULL ? 0u : storage->live_transactions;
}

uint64_t ninlil_posix_sqlite_storage_live_iterators(
    const ninlil_posix_sqlite_storage_t *storage)
{
    return storage == NULL ? 0u : storage->live_iterators;
}
