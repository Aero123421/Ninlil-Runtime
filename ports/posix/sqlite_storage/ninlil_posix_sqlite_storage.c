#include "ninlil_posix_sqlite_storage.h"
#include "ninlil_posix_sqlite_token_advance.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#define NINLIL_POSIX_SQLITE_NO_O_NOFOLLOW 1
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/*
 * POSIX SQLite durable storage port (V1-LAB complete on host).
 *
 * Durability claim (docs/08, docs/14):
 *   PRAGMA journal_mode=WAL;
 *   PRAGMA synchronous=FULL;
 *   PRAGMA foreign_keys=ON;
 * FULL commit success means the atomic group crossed the SQLite durability
 * boundary under those settings. Filesystem or hardware that lies about flush
 * is outside the claim.
 *
 * Exclusive authority (docs/08): main DB identity is pinned by a nofollow fd;
 * an adjacent st_dev/st_ino-keyed nofollow sidecar carries the process-crash-
 * safe flock. Direct main-file flock is not used because it conflicts with
 * SQLite record locks on macOS. Main and sidecar pathname identity are checked
 * after SQLite open and during durable persist (after BEGIN IMMEDIATE, before
 * mutation, before COMMIT, and after COMMIT success before OK).
 *
 * Opaque values are never-dereferenced addresses in a pre-reserved PROT_NONE
 * virtual arena. Addresses are never reissued during a provider lifetime, so
 * stale/fabricated values fail closed without per-operation heap growth.
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
 * product-specific vocabulary is absent from this translation unit.
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
typedef struct identity_registry_entry identity_registry_entry_t;

struct identity_registry_entry {
    dev_t dev;
    ino_t ino;
    identity_registry_entry_t *next;
};

static atomic_flag identity_registry_guard = ATOMIC_FLAG_INIT;
static identity_registry_entry_t *identity_registry;

struct storage_iterator {
    int in_use;
    uint64_t generation;
    void *active_cookie;
    storage_transaction_t *transaction;
    uint64_t transaction_generation;
    storage_entry_t *rows;
    size_t row_count;
    size_t position;
};

struct storage_transaction {
    int in_use;
    uint64_t generation;
    void *active_cookie;
    storage_handle_t *handle;
    uint64_t handle_generation;
    uint64_t lease_token;
    ninlil_storage_mode_t mode;
    storage_entry_t *view;
    size_t view_count;
    size_t view_capacity;
    uint32_t open_iterator_mask;
};

struct storage_handle {
    int in_use;
    uint64_t generation;
    void *active_cookie;
    uint64_t lease_token;
    int lease_fd;
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
    void *token_arena;
    size_t token_arena_size;
    uint64_t next_token_offset;
    uint32_t max_handles;
    uint32_t max_transactions;
    uint32_t max_iterators;
    uint64_t live_handles;
    uint64_t live_transactions;
    uint64_t live_iterators;
    uint64_t last_lease_token;
    int lease_tokens_fenced;
    int connection_fenced;
    char *path_copy;
    dev_t db_dev;
    ino_t db_ino;
    dev_t lock_dev;
    ino_t lock_ino;
    int identity_bound;
    int db_identity_fd;
    int db_lock_fd;
    char *lock_path;
    identity_registry_entry_t *identity_registry_entry;
};

#define NINLIL_POSIX_TOKEN_GEN_MAX UINT64_MAX
#define NINLIL_POSIX_TOKEN_ARENA_BYTES UINT64_C(17592186044416)

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

static int table_exists(sqlite3 *db, const char *name, int *out_exists)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    *out_exists = 0;
    rc = sqlite3_prepare_v2(
        db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1;",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }
    rc = sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return 0;
    }
    rc = sqlite3_step(stmt);
    *out_exists = rc == SQLITE_ROW;
    (void)sqlite3_finalize(stmt);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static int column_xinfo_matches(
    sqlite3 *db,
    const char *table,
    int expected_cid,
    const char *expected_name,
    const char *expected_type,
    int expected_notnull,
    int expected_pk)
{
    sqlite3_stmt *stmt = NULL;
    char sql[192];
    int rc;
    int ok = 0;
    int matches = 0;

    if (snprintf(sql, sizeof(sql), "PRAGMA table_xinfo(%s);", table) <= 0) {
        return 0;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        /* Fall back to table_info when table_xinfo is unavailable. */
        if (snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table) <= 0) {
            return 0;
        }
        rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            return 0;
        }
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int cid = sqlite3_column_int(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        const char *type = (const char *)sqlite3_column_text(stmt, 2);
        int notnull = sqlite3_column_int(stmt, 3);
        int pk = sqlite3_column_int(stmt, 5);

        if (cid != expected_cid) {
            continue;
        }
        matches += 1;
        ok = name != NULL && type != NULL
            && strcmp(name, expected_name) == 0
            && strcmp(type, expected_type) == 0
            && notnull == expected_notnull
            && pk == expected_pk;
    }
    (void)sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && matches == 1 && ok;
}

static int table_column_count_exact(
    sqlite3 *db,
    const char *table,
    int expected_count)
{
    sqlite3_stmt *stmt = NULL;
    char sql[192];
    int rc;
    int count = 0;

    if (snprintf(sql, sizeof(sql), "PRAGMA table_xinfo(%s);", table) <= 0) {
        return 0;
    }
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        if (snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table) <= 0) {
            return 0;
        }
        rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            return 0;
        }
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        count += 1;
    }
    (void)sqlite3_finalize(stmt);
    return rc == SQLITE_DONE && count == expected_count;
}

static int table_flags_match(sqlite3 *db, const char *table)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    int matches = 0;

    /* Schema v1 requires both STRICT and WITHOUT ROWID. */
    rc = sqlite3_prepare_v2(
        db,
        "SELECT wr, strict FROM pragma_table_list"
        " WHERE schema='main' AND type='table' AND name=?1;",
        -1,
        &stmt,
        NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 1, table, -1, SQLITE_STATIC);
        if (rc == SQLITE_OK) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                matches = sqlite3_column_int(stmt, 0) == 1
                    && sqlite3_column_int(stmt, 1) == 1;
                rc = sqlite3_step(stmt);
                matches = matches && rc == SQLITE_DONE;
            }
        }
        (void)sqlite3_finalize(stmt);
    }
    return matches;
}

static int schema_objects_are_exact(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    int meta_seen = 0;
    int kv_seen = 0;
    int count = 0;

    rc = sqlite3_prepare_v2(
        db,
        "SELECT type, name, tbl_name, sql FROM sqlite_master"
        " ORDER BY type, name;",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *type = (const char *)sqlite3_column_text(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        const char *table = (const char *)sqlite3_column_text(stmt, 2);
        const char *sql = (const char *)sqlite3_column_text(stmt, 3);

        count += 1;
        if (type == NULL || name == NULL || table == NULL || sql == NULL
            || strcmp(type, "table") != 0 || strcmp(name, table) != 0) {
            break;
        }
        if (strcmp(name, "ninlil_meta") == 0) {
            if (meta_seen != 0) {
                break;
            }
            meta_seen += 1;
        } else if (strcmp(name, "ninlil_kv") == 0) {
            if (kv_seen != 0) {
                break;
            }
            kv_seen += 1;
        } else {
            break;
        }
    }
    (void)sqlite3_finalize(stmt);
    /*
     * Both v1 tables are WITHOUT ROWID, so their PRIMARY KEY is the table
     * b-tree itself and sqlite_master contains no required sqlite_autoindex.
     * The exact closed object set is therefore these two table rows. Any
     * trigger, view, explicit index, sqlite_stat/sqlite_sequence residue, or
     * future object is unsupported until a versioned migration defines it.
     */
    return rc == SQLITE_DONE && count == 2 && meta_seen == 1 && kv_seen == 1;
}

static int meta_rows_are_exact(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    int ok = 0;

    rc = sqlite3_prepare_v2(
        db,
        "SELECT COUNT(*),"
        " SUM(key='schema_version' AND typeof(value)='integer' AND value=1),"
        " SUM(key='migration_state' AND typeof(value)='integer' AND value=0)"
        " FROM ninlil_meta;",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        ok = sqlite3_column_int(stmt, 0) == 2
            && sqlite3_column_int(stmt, 1) == 1
            && sqlite3_column_int(stmt, 2) == 1;
    }
    (void)sqlite3_finalize(stmt);
    return ok;
}

static ninlil_storage_status_t validate_kv_row_storage_classes(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    int rc;

    rc = sqlite3_prepare_v2(
        db,
        "SELECT 1 FROM ninlil_kv WHERE"
        " typeof(namespace) != 'blob'"
        " OR typeof(key) != 'blob'"
        " OR typeof(value) != 'blob'"
        " OR length(namespace) NOT BETWEEN 1 AND 255"
        " OR length(key) NOT BETWEEN 1 AND 255"
        " OR length(value) > 65536"
        " LIMIT 1;",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    rc = sqlite3_step(stmt);
    (void)sqlite3_finalize(stmt);
    if (rc == SQLITE_ROW) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (rc != SQLITE_DONE) {
        return map_sqlite_rc(rc);
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t read_strict_meta_integer(
    sqlite3 *db,
    const char *key,
    int required,
    int64_t *out_value,
    int *out_present)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    const char *type_name;

    *out_present = 0;
    *out_value = 0;
    rc = sqlite3_prepare_v2(
        db,
        "SELECT typeof(value), value FROM ninlil_meta WHERE key = ?1;",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    rc = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        (void)sqlite3_finalize(stmt);
        return map_sqlite_rc(rc);
    }
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        (void)sqlite3_finalize(stmt);
        if (required) {
            return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
        }
        return NINLIL_STORAGE_OK;
    }
    if (rc != SQLITE_ROW) {
        (void)sqlite3_finalize(stmt);
        return map_sqlite_rc(rc);
    }
    type_name = (const char *)sqlite3_column_text(stmt, 0);
    /*
     * Reject TEXT coercions such as '1garbage' that sqlite3_column_int64 would
     * partially parse as 1.
     */
    if (type_name == NULL || strcmp(type_name, "integer") != 0) {
        (void)sqlite3_finalize(stmt);
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    *out_value = (int64_t)sqlite3_column_int64(stmt, 1);
    *out_present = 1;
    (void)sqlite3_finalize(stmt);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t validate_schema_definition_shape(sqlite3 *db)
{
    int meta_exists = 0;
    int kv_exists = 0;
    int64_t schema_version = 0;
    int64_t migration_state = 0;
    int present = 0;
    ninlil_storage_status_t status;

    if (!table_exists(db, "ninlil_meta", &meta_exists)
        || !table_exists(db, "ninlil_kv", &kv_exists)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (!meta_exists || !kv_exists || !schema_objects_are_exact(db)) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (!table_column_count_exact(db, "ninlil_meta", 2)
        || !table_column_count_exact(db, "ninlil_kv", 3)) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (!column_xinfo_matches(db, "ninlil_meta", 0, "key", "TEXT", 1, 1)
        || !column_xinfo_matches(db, "ninlil_meta", 1, "value", "INTEGER", 1, 0)
        || !column_xinfo_matches(db, "ninlil_kv", 0, "namespace", "BLOB", 1, 1)
        || !column_xinfo_matches(db, "ninlil_kv", 1, "key", "BLOB", 1, 2)
        || !column_xinfo_matches(db, "ninlil_kv", 2, "value", "BLOB", 1, 0)) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (!table_flags_match(db, "ninlil_meta")
        || !table_flags_match(db, "ninlil_kv")) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    status = read_strict_meta_integer(
        db, "schema_version", 1, &schema_version, &present);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    if (!present
        || schema_version != (int64_t)NINLIL_POSIX_SQLITE_SCHEMA_VERSION) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    status = read_strict_meta_integer(
        db, "migration_state", 1, &migration_state, &present);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    if (!present || migration_state != 0) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (!meta_rows_are_exact(db)) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t validate_existing_schema_shape(sqlite3 *db)
{
    ninlil_storage_status_t status = validate_schema_definition_shape(db);

    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    return validate_kv_row_storage_classes(db);
}

static ninlil_storage_status_t initialize_schema(sqlite3 *db)
{
    static const char *const ddl =
        "BEGIN IMMEDIATE;"
        "CREATE TABLE ninlil_meta ("
        "  key TEXT PRIMARY KEY NOT NULL,"
        "  value INTEGER NOT NULL"
        ") STRICT, WITHOUT ROWID;"
        "CREATE TABLE ninlil_kv ("
        "  namespace BLOB NOT NULL CHECK(typeof(namespace) = 'blob'),"
        "  key BLOB NOT NULL CHECK(typeof(key) = 'blob'),"
        "  value BLOB NOT NULL CHECK(typeof(value) = 'blob'),"
        "  PRIMARY KEY (namespace, key)"
        ") STRICT, WITHOUT ROWID;"
        "INSERT INTO ninlil_meta(key, value)"
        "  VALUES('schema_version', 1);"
        "INSERT INTO ninlil_meta(key, value)"
        "  VALUES('migration_state', 0);"
        "COMMIT;";
    ninlil_storage_status_t status = exec_sql(db, ddl);

    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    return validate_existing_schema_shape(db);
}

static ninlil_storage_status_t ensure_schema(sqlite3 *db)
{
    int meta_exists = 0;
    int kv_exists = 0;
    ninlil_storage_status_t status;

    if (!table_exists(db, "ninlil_meta", &meta_exists)
        || !table_exists(db, "ninlil_kv", &kv_exists)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (!meta_exists && !kv_exists) {
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(
            db,
            "SELECT 1 FROM sqlite_master"
            " LIMIT 1;",
            -1,
            &stmt,
            NULL);
        if (rc != SQLITE_OK) {
            return map_sqlite_rc(rc);
        }
        rc = sqlite3_step(stmt);
        (void)sqlite3_finalize(stmt);
        if (rc == SQLITE_ROW) {
            return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
        }
        if (rc != SQLITE_DONE) {
            return map_sqlite_rc(rc);
        }
        return initialize_schema(db);
    }
    /* Partial or foreign shape is unsupported at create/open, not delayed. */
    if (!meta_exists || !kv_exists) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    status = validate_existing_schema_shape(db);
    return status;
}

static int slot_can_issue_generation(
    uint64_t current_generation,
    uint64_t gen_max)
{
    return ninlil_posix_sqlite_generation_advance(current_generation, gen_max)
        != 0u;
}

static uint64_t issue_slot_generation(
    uint64_t *slot_generation,
    uint64_t gen_max)
{
    uint64_t next;

    if (slot_generation == NULL) {
        return 0u;
    }
    next = ninlil_posix_sqlite_generation_advance(*slot_generation, gen_max);
    if (next == 0u) {
        return 0u;
    }
    *slot_generation = next;
    return next;
}

static uint64_t issue_lease_token(ninlil_posix_sqlite_storage_t *storage)
{
    uint64_t next;

    if (storage == NULL || storage->lease_tokens_fenced) {
        return 0u;
    }
    /* Production uses a fixed UINT64_MAX token domain (no runtime ceiling). */
    next = ninlil_posix_sqlite_lease_token_advance(
        storage->last_lease_token, UINT64_MAX);
    if (next == 0u) {
        storage->lease_tokens_fenced = 1;
        return 0u;
    }
    storage->last_lease_token = next;
    if (next == UINT64_MAX) {
        /* Last issuable token consumed: fence further allocations. */
        storage->lease_tokens_fenced = 1;
    }
    return next;
}

static void *cookie_issue(ninlil_posix_sqlite_storage_t *storage)
{
    uint8_t *cookie;

    if (storage == NULL || storage->token_arena == NULL
        || storage->next_token_offset >= storage->token_arena_size) {
        return NULL;
    }
    cookie = (uint8_t *)storage->token_arena + storage->next_token_offset;
    storage->next_token_offset += 1u;
    return (void *)cookie;
}

static int cookie_was_issued(
    const ninlil_posix_sqlite_storage_t *storage,
    const void *opaque)
{
    uintptr_t base;
    uintptr_t address;

    if (storage == NULL || storage->token_arena == NULL || opaque == NULL) {
        return 0;
    }
    base = (uintptr_t)storage->token_arena;
    address = (uintptr_t)opaque;
    return address >= base
        && (uint64_t)(address - base) < storage->next_token_offset;
}

static storage_handle_t *find_handle(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_handle_t opaque)
{
    uint32_t index;

    if (!cookie_was_issued(storage, opaque)) {
        return NULL;
    }
    for (index = 0u; index < storage->max_handles; ++index) {
        storage_handle_t *handle = &storage->handles[index];
        if (handle->in_use && handle->active_cookie == opaque) {
            return handle;
        }
    }
    return NULL;
}

static storage_transaction_t *find_transaction(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_txn_t opaque)
{
    uint32_t index;

    if (!cookie_was_issued(storage, opaque)) {
        return NULL;
    }
    for (index = 0u; index < storage->max_transactions; ++index) {
        storage_transaction_t *transaction = &storage->transactions[index];
        if (transaction->in_use && transaction->active_cookie == opaque
            && transaction->handle != NULL
            && transaction->handle->in_use
            && transaction->handle->generation
                == transaction->handle_generation
            && transaction->handle->active_cookie != NULL) {
            return transaction;
        }
    }
    return NULL;
}

static storage_iterator_t *find_iterator(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_iter_t opaque)
{
    uint32_t index;

    if (!cookie_was_issued(storage, opaque)) {
        return NULL;
    }
    for (index = 0u; index < storage->max_iterators; ++index) {
        storage_iterator_t *iterator = &storage->iterators[index];
        if (iterator->in_use && iterator->active_cookie == opaque
            && iterator->transaction != NULL
            && iterator->transaction->in_use
            && iterator->transaction->generation
                == iterator->transaction_generation
            && iterator->transaction->active_cookie != NULL) {
            return iterator;
        }
    }
    return NULL;
}

static ninlil_storage_handle_t handle_to_opaque(
    ninlil_posix_sqlite_storage_t *storage,
    storage_handle_t *handle)
{
    if (storage == NULL || handle == NULL) {
        return NULL;
    }
    handle->active_cookie = cookie_issue(storage);
    if (handle->active_cookie == NULL) {
        return NULL;
    }
    return (ninlil_storage_handle_t)handle->active_cookie;
}

static ninlil_storage_txn_t txn_to_opaque(
    ninlil_posix_sqlite_storage_t *storage,
    storage_transaction_t *transaction)
{
    if (storage == NULL || transaction == NULL) {
        return NULL;
    }
    transaction->active_cookie = cookie_issue(storage);
    if (transaction->active_cookie == NULL) {
        return NULL;
    }
    return (ninlil_storage_txn_t)transaction->active_cookie;
}

static ninlil_storage_iter_t iter_to_opaque(
    ninlil_posix_sqlite_storage_t *storage,
    storage_iterator_t *iterator)
{
    if (storage == NULL || iterator == NULL) {
        return NULL;
    }
    iterator->active_cookie = cookie_issue(storage);
    if (iterator->active_cookie == NULL) {
        return NULL;
    }
    return (ninlil_storage_iter_t)iterator->active_cookie;
}

static int handle_lease_is_live(const storage_handle_t *handle)
{
    return handle != NULL
        && handle->in_use
        && handle->lease_fd >= 0
        && handle->lease_token != 0u
        && handle->generation != 0u;
}

static ninlil_storage_status_t verify_db_file_identity(
    const ninlil_posix_sqlite_storage_t *storage)
{
    struct stat path_st = {0};
    struct stat fd_st = {0};
    struct stat lock_path_st = {0};
    struct stat lock_fd_st = {0};

    if (storage == NULL || !storage->identity_bound
        || storage->path_copy == NULL || storage->db_identity_fd < 0) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (lstat(storage->path_copy, &path_st) != 0
        || fstat(storage->db_identity_fd, &fd_st) != 0
        || storage->lock_path == NULL
        || lstat(storage->lock_path, &lock_path_st) != 0
        || fstat(storage->db_lock_fd, &lock_fd_st) != 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (!S_ISREG(path_st.st_mode) || !S_ISREG(fd_st.st_mode)
        || path_st.st_nlink != 1 || fd_st.st_nlink != 1
        || path_st.st_dev != storage->db_dev
        || path_st.st_ino != storage->db_ino
        || fd_st.st_dev != storage->db_dev
        || fd_st.st_ino != storage->db_ino
        || !S_ISREG(lock_path_st.st_mode)
        || !S_ISREG(lock_fd_st.st_mode)
        || lock_path_st.st_nlink != 1 || lock_fd_st.st_nlink != 1
        || lock_path_st.st_uid != geteuid()
        || lock_fd_st.st_uid != geteuid()
        || (lock_path_st.st_mode & (mode_t)07777) != (mode_t)0600
        || (lock_fd_st.st_mode & (mode_t)07777) != (mode_t)0600
        || lock_path_st.st_dev != storage->lock_dev
        || lock_path_st.st_ino != storage->lock_ino
        || lock_fd_st.st_dev != storage->lock_dev
        || lock_fd_st.st_ino != storage->lock_ino) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return NINLIL_STORAGE_OK;
}

/*
 * Acquire authority before SQLite derives WAL/SHM sidecar pathnames. Existing
 * hardlinks are rejected rather than selecting one alias as the authority.
 */
static ninlil_storage_status_t acquire_db_identity_and_lock(
    ninlil_posix_sqlite_storage_t *storage)
{
    struct stat st = {0};
    struct stat lock_st = {0};
    identity_registry_entry_t *entry;
    identity_registry_entry_t *cursor;
    int fd;
    int lock_fd = -1;
    int rc;
    char *canonical = NULL;
    char *lock_path = NULL;
    size_t lock_path_length;
    const char *slash;
    size_t parent_length;

    if (storage == NULL || storage->path_copy == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
#if defined(NINLIL_POSIX_SQLITE_NO_O_NOFOLLOW)
    if (lstat(storage->path_copy, &st) == 0 && S_ISLNK(st.st_mode)) {
        return NINLIL_STORAGE_CORRUPT;
    }
#endif
    fd = open(
        storage->path_copy,
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        0600);
    if (fd < 0) {
        if (errno == ELOOP) {
            return NINLIL_STORAGE_CORRUPT;
        }
        if (errno == ENOSPC || errno == EMFILE || errno == ENFILE) {
            return NINLIL_STORAGE_NO_SPACE;
        }
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (fstat(fd, &st) != 0) {
        (void)close(fd);
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1) {
        (void)close(fd);
        return NINLIL_STORAGE_CORRUPT;
    }
    entry = (identity_registry_entry_t *)calloc(1u, sizeof(*entry));
    if (entry == NULL) {
        (void)close(fd);
        return NINLIL_STORAGE_NO_SPACE;
    }
    while (atomic_flag_test_and_set_explicit(
        &identity_registry_guard, memory_order_acquire)) {
    }
    for (cursor = identity_registry; cursor != NULL; cursor = cursor->next) {
        if (cursor->dev == st.st_dev && cursor->ino == st.st_ino) {
            atomic_flag_clear_explicit(
                &identity_registry_guard, memory_order_release);
            free(entry);
            (void)close(fd);
            return NINLIL_STORAGE_BUSY;
        }
    }
    canonical = realpath(storage->path_copy, NULL);
    if (canonical == NULL) {
        atomic_flag_clear_explicit(
            &identity_registry_guard, memory_order_release);
        free(entry);
        (void)close(fd);
        return NINLIL_STORAGE_IO_ERROR;
    }
    slash = strrchr(canonical, '/');
    if (slash == NULL) {
        atomic_flag_clear_explicit(
            &identity_registry_guard, memory_order_release);
        free(canonical);
        free(entry);
        (void)close(fd);
        return NINLIL_STORAGE_IO_ERROR;
    }
    parent_length = slash == canonical ? 1u : (size_t)(slash - canonical);
    lock_path_length = parent_length + 80u;
    lock_path = (char *)malloc(lock_path_length);
    if (lock_path == NULL) {
        atomic_flag_clear_explicit(
            &identity_registry_guard, memory_order_release);
        free(canonical);
        free(entry);
        (void)close(fd);
        return NINLIL_STORAGE_NO_SPACE;
    }
    (void)snprintf(
        lock_path,
        lock_path_length,
        "%.*s/.ninlil-sqlite-%llx-%llx.lock",
        (int)parent_length,
        canonical,
        (unsigned long long)st.st_dev,
        (unsigned long long)st.st_ino);
    free(storage->path_copy);
    storage->path_copy = canonical;
    storage->config.database_path = storage->path_copy;
    canonical = NULL;
    lock_fd = open(
        lock_path,
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        0600);
    if (lock_fd < 0 || fstat(lock_fd, &lock_st) != 0) {
        int saved = errno;
        atomic_flag_clear_explicit(
            &identity_registry_guard, memory_order_release);
        if (lock_fd >= 0) {
            (void)close(lock_fd);
        }
        free(lock_path);
        free(entry);
        (void)close(fd);
        return saved == ELOOP
            ? NINLIL_STORAGE_CORRUPT
            : NINLIL_STORAGE_IO_ERROR;
    }
    if (!S_ISREG(lock_st.st_mode) || lock_st.st_nlink != 1
        || lock_st.st_uid != geteuid()
        || (lock_st.st_mode & (mode_t)07777) != (mode_t)0600) {
        atomic_flag_clear_explicit(
            &identity_registry_guard, memory_order_release);
        (void)close(lock_fd);
        free(lock_path);
        free(entry);
        (void)close(fd);
        return NINLIL_STORAGE_CORRUPT;
    }
    rc = flock(lock_fd, LOCK_EX | LOCK_NB);
    if (rc != 0) {
        int saved = errno;
        atomic_flag_clear_explicit(
            &identity_registry_guard, memory_order_release);
        free(entry);
        (void)close(lock_fd);
        free(lock_path);
        (void)close(fd);
        if (saved == EWOULDBLOCK || saved == EAGAIN) {
            return NINLIL_STORAGE_BUSY;
        }
        return NINLIL_STORAGE_IO_ERROR;
    }
    {
        struct stat after_path = {0};
        struct stat after_fd = {0};
        if (lstat(lock_path, &after_path) != 0
            || fstat(lock_fd, &after_fd) != 0
            || !S_ISREG(after_path.st_mode) || !S_ISREG(after_fd.st_mode)
            || after_path.st_nlink != 1 || after_fd.st_nlink != 1
            || after_path.st_uid != geteuid()
            || after_fd.st_uid != geteuid()
            || (after_path.st_mode & (mode_t)07777) != (mode_t)0600
            || (after_fd.st_mode & (mode_t)07777) != (mode_t)0600
            || after_path.st_dev != after_fd.st_dev
            || after_path.st_ino != after_fd.st_ino) {
            atomic_flag_clear_explicit(
                &identity_registry_guard, memory_order_release);
            (void)flock(lock_fd, LOCK_UN);
            (void)close(lock_fd);
            free(lock_path);
            free(entry);
            (void)close(fd);
            return NINLIL_STORAGE_CORRUPT;
        }
        lock_st = after_fd;
    }
    entry->dev = st.st_dev;
    entry->ino = st.st_ino;
    entry->next = identity_registry;
    identity_registry = entry;
    atomic_flag_clear_explicit(
        &identity_registry_guard, memory_order_release);
    storage->db_dev = st.st_dev;
    storage->db_ino = st.st_ino;
    storage->lock_dev = lock_st.st_dev;
    storage->lock_ino = lock_st.st_ino;
    storage->identity_bound = 1;
    storage->db_identity_fd = fd;
    storage->db_lock_fd = lock_fd;
    storage->lock_path = lock_path;
    storage->identity_registry_entry = entry;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t acquire_namespace_lease(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_bytes_view_t storage_namespace,
    int *out_fd)
{
    ninlil_storage_status_t status;
    uint32_t index;

    *out_fd = -1;
    if (storage != NULL
        && (storage->connection_fenced || storage->lease_tokens_fenced)) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    status = verify_db_file_identity(storage);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    for (index = 0u; index < storage->max_handles; ++index) {
        const storage_handle_t *handle = &storage->handles[index];
        if (handle->in_use
            && handle->name_length == storage_namespace.length
            && memcmp(handle->name, storage_namespace.data,
                storage_namespace.length) == 0) {
            return NINLIL_STORAGE_BUSY;
        }
    }
    /* The DB-wide flock already provides cross-process exclusion. */
    *out_fd = storage->db_lock_fd;
    return NINLIL_STORAGE_OK;
}

static void release_namespace_lease_fd(int *lease_fd)
{
    if (lease_fd == NULL || *lease_fd < 0) {
        return;
    }
    /* Borrowed from storage->db_lock_fd; released only by provider destroy. */
    *lease_fd = -1;
}

static void release_iterator(
    ninlil_posix_sqlite_storage_t *storage,
    storage_iterator_t *iterator)
{
    storage_transaction_t *transaction;
    uint32_t index;
    uint64_t generation;

    if (iterator == NULL || !iterator->in_use) {
        return;
    }
    transaction = iterator->transaction;
    index = (uint32_t)(iterator - storage->iterators);
    if (transaction != NULL && transaction->in_use
        && transaction->generation == iterator->transaction_generation) {
        transaction->open_iterator_mask &= ~(1u << index);
    }
    free_entries(iterator->rows, iterator->row_count);
    iterator->active_cookie = NULL;
    generation = iterator->generation;
    (void)memset(iterator, 0, sizeof(*iterator));
    iterator->generation = generation;
    iterator->in_use = 0;
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
    uint64_t generation;

    if (transaction == NULL || !transaction->in_use) {
        return;
    }
    handle = transaction->handle;
    consume_iterators(storage, transaction);
    if (transaction->mode == NINLIL_STORAGE_READ_WRITE
        && handle != NULL
        && handle->in_use
        && handle->generation == transaction->handle_generation) {
        handle->has_writer = 0;
    }
    if (handle != NULL
        && handle->in_use
        && handle->generation == transaction->handle_generation) {
        index = (uint32_t)(transaction - storage->transactions);
        handle->open_txn_mask &= ~(1u << index);
    }
    if (!keep_view) {
        free_entries(transaction->view, transaction->view_count);
    }
    transaction->active_cookie = NULL;
    generation = transaction->generation;
    (void)memset(transaction, 0, sizeof(*transaction));
    transaction->generation = generation;
    transaction->in_use = 0;
    if (storage->live_transactions > 0u) {
        storage->live_transactions -= 1u;
    }
}

static void force_close_handle(
    ninlil_posix_sqlite_storage_t *storage,
    storage_handle_t *handle)
{
    uint32_t index;
    uint64_t generation;
    int lease_fd;

    if (handle == NULL || !handle->in_use) {
        return;
    }
    for (index = 0u; index < storage->max_transactions; ++index) {
        if ((handle->open_txn_mask & (1u << index)) != 0u) {
            release_transaction(
                storage, &storage->transactions[index], 0);
        }
    }
    handle->active_cookie = NULL;
    generation = handle->generation;
    lease_fd = handle->lease_fd;
    handle->lease_fd = -1;
    release_namespace_lease_fd(&lease_fd);
    (void)memset(handle, 0, sizeof(*handle));
    handle->generation = generation;
    handle->lease_fd = -1;
    handle->in_use = 0;
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
        if (count == capacity) {
            size_t next = capacity == 0u ? 8u : capacity * 2u;
            storage_entry_t *grown;

            if (next < capacity) {
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

static ninlil_storage_status_t confirm_autocommit_after_rollback(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_status_t candidate_definite)
{
    int rc;

    if (storage == NULL || storage->db == NULL) {
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    rc = sqlite3_exec(storage->db, "ROLLBACK;", NULL, NULL, NULL);
    /*
     * ROLLBACK may return OK or a benign "no transaction is active" error.
     * Only treat non-commit as definite when autocommit confirms no open txn.
     */
    if (sqlite3_get_autocommit(storage->db) != 0
        && (rc == SQLITE_OK || rc == SQLITE_ERROR)) {
        return candidate_definite;
    }
    storage->connection_fenced = 1;
    return NINLIL_STORAGE_COMMIT_UNKNOWN;
}

static ninlil_storage_status_t classify_pre_commit_identity_failure(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_storage_status_t identity_status)
{
    storage->connection_fenced = 1;
    if (identity_status == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return NINLIL_STORAGE_COMMIT_UNKNOWN;
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
    ninlil_storage_status_t identity_status;
    ninlil_storage_status_t schema_status;

    if (storage->connection_fenced) {
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    identity_status = verify_db_file_identity(storage);
    if (identity_status != NINLIL_STORAGE_OK) {
        return classify_pre_commit_identity_failure(storage, identity_status);
    }

    /*
     * docs/08 durable persist ordering:
     *   BEGIN IMMEDIATE → closed schema revalidation (same txn) →
     *   identity revalidation → DELETE/INSERT → identity → COMMIT →
     *   identity before OK publication.
     * Schema/path checks after BEGIN close the validate-then-BEGIN TOCTOU
     * window. Raw external SQLite access remains unsupported; these checks are
     * defense-in-depth and never justify publishing OK after replacement.
     * Windows between revalidations are not closed atomically: a rename after
     * the last pre-COMMIT check is reported only post-COMMIT as COMMIT_UNKNOWN.
     */
    rc = sqlite3_exec(storage->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }

    identity_status = verify_db_file_identity(storage);
    if (identity_status != NINLIL_STORAGE_OK) {
        status = classify_pre_commit_identity_failure(
            storage, identity_status);
        goto abort_tx;
    }

    schema_status = validate_schema_definition_shape(storage->db);
    if (schema_status != NINLIL_STORAGE_OK) {
        storage->connection_fenced = 1;
        status = schema_status == NINLIL_STORAGE_UNSUPPORTED_SCHEMA
            ? NINLIL_STORAGE_CORRUPT
            : schema_status;
        goto abort_tx;
    }

    identity_status = verify_db_file_identity(storage);
    if (identity_status != NINLIL_STORAGE_OK) {
        status = classify_pre_commit_identity_failure(
            storage, identity_status);
        goto abort_tx;
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

    identity_status = verify_db_file_identity(storage);
    if (identity_status != NINLIL_STORAGE_OK) {
        status = classify_pre_commit_identity_failure(
            storage, identity_status);
        goto abort_tx;
    }

    rc = sqlite3_exec(storage->db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        ninlil_storage_status_t candidate = NINLIL_STORAGE_COMMIT_UNKNOWN;
        if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
            candidate = NINLIL_STORAGE_BUSY;
        } else if (rc == SQLITE_FULL) {
            candidate = NINLIL_STORAGE_NO_SPACE;
        } else if (rc == SQLITE_CORRUPT || rc == SQLITE_NOTADB) {
            candidate = NINLIL_STORAGE_CORRUPT;
        }
        return confirm_autocommit_after_rollback(storage, candidate);
    }
    if (sqlite3_get_autocommit(storage->db) == 0) {
        storage->connection_fenced = 1;
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }

    /*
     * Post-commit identity is linearization evidence. Path replacement after
     * COMMIT must never publish OK against a different inode at the pathname.
     */
    identity_status = verify_db_file_identity(storage);
    if (identity_status != NINLIL_STORAGE_OK) {
        storage->connection_fenced = 1;
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
    return confirm_autocommit_after_rollback(storage, status);
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
    int lease_fd = -1;
    ninlil_storage_status_t status;
    uint64_t generation;
    uint64_t lease_token;
    ninlil_storage_handle_t opaque;
    uint64_t gen_ceiling;

    if (storage == NULL || out_handle == NULL || *out_handle != NULL
        || !view_shape_is_valid(storage_namespace, 1u, 255u)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (expected_schema != NINLIL_STORAGE_SCHEMA_M1A) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (storage->connection_fenced) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (storage->lease_tokens_fenced) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    gen_ceiling = NINLIL_POSIX_TOKEN_GEN_MAX;
    for (index = 0u; index < storage->max_handles; ++index) {
        storage_handle_t *candidate = &storage->handles[index];
        if (!candidate->in_use
            && slot_can_issue_generation(candidate->generation, gen_ceiling)) {
            handle = candidate;
            break;
        }
    }
    if (handle == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    status = acquire_namespace_lease(storage, storage_namespace, &lease_fd);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    generation = issue_slot_generation(&handle->generation, gen_ceiling);
    if (generation == 0u) {
        release_namespace_lease_fd(&lease_fd);
        return NINLIL_STORAGE_NO_SPACE;
    }
    lease_token = issue_lease_token(storage);
    if (lease_token == 0u) {
        release_namespace_lease_fd(&lease_fd);
        return NINLIL_STORAGE_NO_SPACE;
    }
    handle->in_use = 1;
    handle->lease_token = lease_token;
    handle->lease_fd = lease_fd;
    handle->name_length = storage_namespace.length;
    handle->schema = expected_schema;
    handle->has_writer = 0;
    handle->open_txn_mask = 0u;
    (void)memcpy(
        handle->name, storage_namespace.data, storage_namespace.length);
    opaque = handle_to_opaque(storage, handle);
    if (opaque == NULL) {
        handle->in_use = 0;
        handle->lease_fd = -1;
        handle->lease_token = 0u;
        release_namespace_lease_fd(&lease_fd);
        return NINLIL_STORAGE_NO_SPACE;
    }
    storage->live_handles += 1u;
    *out_handle = opaque;
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
    {
        uint64_t gen_ceiling = NINLIL_POSIX_TOKEN_GEN_MAX;

        for (index = 0u; index < storage->max_transactions; ++index) {
            storage_transaction_t *candidate = &storage->transactions[index];
            if (!candidate->in_use
                && slot_can_issue_generation(
                    candidate->generation, gen_ceiling)) {
                transaction = candidate;
                break;
            }
        }
    }
    if (transaction == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (!handle_lease_is_live(handle)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    status = load_namespace_view(storage, handle, &view, &view_count);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    {
        uint64_t generation = issue_slot_generation(
            &transaction->generation,
            NINLIL_POSIX_TOKEN_GEN_MAX);
        ninlil_storage_txn_t txn_opaque;

        if (generation == 0u) {
            free_entries(view, view_count);
            return NINLIL_STORAGE_NO_SPACE;
        }
        transaction->in_use = 1;
        transaction->handle = handle;
        transaction->handle_generation = handle->generation;
        transaction->lease_token = handle->lease_token;
        transaction->mode = mode;
        transaction->view = view;
        transaction->view_count = view_count;
        transaction->view_capacity = view_count;
        transaction->open_iterator_mask = 0u;
        txn_opaque = txn_to_opaque(storage, transaction);
        if (txn_opaque == NULL) {
            free_entries(view, view_count);
            transaction->in_use = 0;
            transaction->view = NULL;
            transaction->view_count = 0u;
            return NINLIL_STORAGE_NO_SPACE;
        }
        handle->open_txn_mask |= 1u << index;
        if (mode == NINLIL_STORAGE_READ_WRITE) {
            handle->has_writer = 1;
        }
        storage->live_transactions += 1u;
        *out_txn = txn_opaque;
    }
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
    /*
     * docs/14: capacity is evaluated on the final transaction view at commit,
     * not at each put. Accept into the working view while the staging area can
     * grow; OOM of the staging area is the only put-time NO_SPACE for counts.
     */
    if (transaction->view_count == transaction->view_capacity) {
        size_t next = transaction->view_capacity == 0u
            ? 4u
            : transaction->view_capacity * 2u;
        if (next < transaction->view_capacity
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
    {
        uint64_t gen_ceiling = NINLIL_POSIX_TOKEN_GEN_MAX;

        for (slot = 0u; slot < storage->max_iterators; ++slot) {
            storage_iterator_t *candidate = &storage->iterators[slot];
            if (!candidate->in_use
                && slot_can_issue_generation(
                    candidate->generation, gen_ceiling)) {
                iterator = candidate;
                break;
            }
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
    {
        uint64_t generation = issue_slot_generation(
            &iterator->generation,
            NINLIL_POSIX_TOKEN_GEN_MAX);
        ninlil_storage_iter_t iter_opaque;

        if (generation == 0u) {
            free_entries(rows, matches);
            return NINLIL_STORAGE_NO_SPACE;
        }
        iterator->in_use = 1;
        iterator->transaction = transaction;
        iterator->transaction_generation = transaction->generation;
        iterator->rows = rows;
        iterator->row_count = matches;
        iterator->position = 0u;
        iter_opaque = iter_to_opaque(storage, iterator);
        if (iter_opaque == NULL) {
            free_entries(rows, matches);
            iterator->in_use = 0;
            iterator->rows = NULL;
            iterator->row_count = 0u;
            return NINLIL_STORAGE_NO_SPACE;
        }
        transaction->open_iterator_mask |= 1u << slot;
        storage->live_iterators += 1u;
        *out_iter = iter_opaque;
    }
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
    handle = transaction->handle;
    /*
     * Fence stale writers: handle must still own the same OS lease and
     * generation captured at begin. Lost lease / ABA / close mid-txn cannot
     * publish mutations.
     */
    if (!handle_lease_is_live(handle)
        || handle->generation != transaction->handle_generation
        || handle->lease_token != transaction->lease_token) {
        release_transaction(storage, transaction, 0);
        return NINLIL_STORAGE_CORRUPT;
    }
    view = transaction->view;
    view_count = transaction->view_count;
    transaction->view = NULL;
    transaction->view_count = 0u;
    transaction->view_capacity = 0u;
    if (!handle_lease_is_live(handle)
        || handle->generation != transaction->handle_generation
        || handle->lease_token != transaction->lease_token) {
        free_entries(view, view_count);
        release_transaction(storage, transaction, 0);
        return NINLIL_STORAGE_CORRUPT;
    }
    status = persist_namespace_view(storage, handle, view, view_count);
    free_entries(view, view_count);
    release_transaction(storage, transaction, 0);
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
    if (config->busy_timeout_ms > (uint32_t)INT_MAX) {
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

static ninlil_storage_status_t validate_committed_capacity(
    ninlil_posix_sqlite_storage_t *storage)
{
    sqlite3_stmt *stmt = NULL;
    int rc;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;

    /*
     * SH4: reject configurations where any existing namespace already exceeds
     * configured max_entries / max_bytes (logical 16+key+value units).
     */
    rc = sqlite3_prepare_v2(
        storage->db,
        "SELECT namespace, key, value FROM ninlil_kv ORDER BY namespace, key;",
        -1,
        &stmt,
        NULL);
    if (rc != SQLITE_OK) {
        return map_sqlite_rc(rc);
    }
    {
        uint8_t current_ns[255];
        uint32_t current_ns_len = 0u;
        int have_ns = 0;
        uint64_t used_entries = 0u;
        uint64_t used_bytes = 0u;

        for (;;) {
            const void *ns_ptr;
            const void *key_ptr;
            const void *value_ptr;
            int ns_len;
            int key_len;
            int value_len;
            uint64_t row_bytes;

            rc = sqlite3_step(stmt);
            if (rc == SQLITE_DONE) {
                break;
            }
            if (rc != SQLITE_ROW) {
                status = map_sqlite_rc(rc);
                break;
            }
            ns_ptr = sqlite3_column_blob(stmt, 0);
            ns_len = sqlite3_column_bytes(stmt, 0);
            key_ptr = sqlite3_column_blob(stmt, 1);
            key_len = sqlite3_column_bytes(stmt, 1);
            value_ptr = sqlite3_column_blob(stmt, 2);
            value_len = sqlite3_column_bytes(stmt, 2);
            (void)value_ptr;
            if (ns_len < 1 || ns_len > 255 || key_len < 1 || key_len > 255
                || value_len < 0
                || (uint32_t)value_len > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES
                || ns_ptr == NULL || key_ptr == NULL) {
                status = NINLIL_STORAGE_CORRUPT;
                break;
            }
            if (!have_ns
                || current_ns_len != (uint32_t)ns_len
                || memcmp(current_ns, ns_ptr, (size_t)ns_len) != 0) {
                if (have_ns
                    && (used_entries
                            > storage->config.max_entries_per_namespace
                        || used_bytes
                            > storage->config.max_bytes_per_namespace)) {
                    status = NINLIL_STORAGE_NO_SPACE;
                    break;
                }
                current_ns_len = (uint32_t)ns_len;
                (void)memcpy(current_ns, ns_ptr, (size_t)ns_len);
                have_ns = 1;
                used_entries = 0u;
                used_bytes = 0u;
            }
            row_bytes = 16u + (uint64_t)key_len + (uint64_t)value_len;
            if (used_entries == UINT64_MAX
                || used_bytes > UINT64_MAX - row_bytes) {
                status = NINLIL_STORAGE_CORRUPT;
                break;
            }
            used_entries += 1u;
            used_bytes += row_bytes;
        }
        if (status == NINLIL_STORAGE_OK && have_ns
            && (used_entries > storage->config.max_entries_per_namespace
                || used_bytes > storage->config.max_bytes_per_namespace)) {
            status = NINLIL_STORAGE_NO_SPACE;
        }
    }
    (void)sqlite3_finalize(stmt);
    return status;
}

ninlil_posix_sqlite_storage_t *ninlil_posix_sqlite_storage_create(
    const ninlil_posix_sqlite_storage_config_t *config)
{
    ninlil_posix_sqlite_storage_t *storage;
    sqlite3 *db = NULL;
    int rc;
    ninlil_storage_status_t status;
    size_t path_len;
    uint32_t index;

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
    storage->db_identity_fd = -1;
    storage->db_lock_fd = -1;
    storage->config.database_path = storage->path_copy;
    if (storage->config.busy_timeout_ms == 0u) {
        storage->config.busy_timeout_ms =
            NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS;
    }
    storage->max_handles = config->max_handles;
    storage->max_transactions = config->max_transactions;
    storage->max_iterators = config->max_iterators;
    storage->last_lease_token = 0u;
    storage->lease_tokens_fenced = 0;
    storage->connection_fenced = 0;
    if (UINTPTR_MAX <= UINT32_MAX
        || (uint64_t)SIZE_MAX < NINLIL_POSIX_TOKEN_ARENA_BYTES) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    storage->token_arena_size = (size_t)NINLIL_POSIX_TOKEN_ARENA_BYTES;
    storage->token_arena = mmap(
        NULL,
        storage->token_arena_size,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (storage->token_arena == MAP_FAILED) {
        storage->token_arena = NULL;
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
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
    for (index = 0u; index < storage->max_handles; ++index) {
        storage->handles[index].lease_fd = -1;
    }
    status = acquire_db_identity_and_lock(storage);
    if (status != NINLIL_STORAGE_OK) {
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
    storage->db = db;
    rc = sqlite3_busy_timeout(db, (int)storage->config.busy_timeout_ms);
    if (rc != SQLITE_OK) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    /*
     * Revalidate the pinned pathname before any schema or PRAGMA mutation.
     * Without a custom VFS this cannot close an adversarial rename race inside
     * sqlite3_open_v2 itself; the supported live-path precondition is stated
     * in the port profile.  It does ensure an already-replaced path is never
     * initialized or configured by this provider.
     */
    status = verify_db_file_identity(storage);
    if (status != NINLIL_STORAGE_OK) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    status = ensure_schema(db);
    if (status != NINLIL_STORAGE_OK) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    /* Schema initialization can cross a durable boundary; fence before the
     * subsequent persistent journal-mode configuration as well. */
    status = verify_db_file_identity(storage);
    if (status != NINLIL_STORAGE_OK) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    status = configure_connection(db, storage->config.busy_timeout_ms);
    if (status != NINLIL_STORAGE_OK) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
    status = validate_committed_capacity(storage);
    if (status != NINLIL_STORAGE_OK) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return NULL;
    }
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
    if (storage->db_lock_fd >= 0) {
        identity_registry_entry_t **link;

        while (atomic_flag_test_and_set_explicit(
            &identity_registry_guard, memory_order_acquire)) {
        }
        link = &identity_registry;
        while (*link != NULL) {
            if (*link == storage->identity_registry_entry) {
                *link = (*link)->next;
                break;
            }
            link = &(*link)->next;
        }
        atomic_flag_clear_explicit(
            &identity_registry_guard, memory_order_release);
        free(storage->identity_registry_entry);
        storage->identity_registry_entry = NULL;
        (void)flock(storage->db_lock_fd, LOCK_UN);
        (void)close(storage->db_lock_fd);
        storage->db_lock_fd = -1;
    }
    if (storage->db_identity_fd >= 0) {
        (void)close(storage->db_identity_fd);
        storage->db_identity_fd = -1;
    }
    if (storage->token_arena != NULL && storage->token_arena_size != 0u) {
        (void)munmap(storage->token_arena, storage->token_arena_size);
        storage->token_arena = NULL;
        storage->token_arena_size = 0u;
    }
    free(storage->handles);
    free(storage->transactions);
    free(storage->iterators);
    free(storage->path_copy);
    free(storage->lock_path);
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

int ninlil_posix_sqlite_storage_lease_tokens_fenced(
    const ninlil_posix_sqlite_storage_t *storage)
{
    return storage != NULL && storage->lease_tokens_fenced != 0;
}

int ninlil_posix_sqlite_storage_connection_fenced(
    const ninlil_posix_sqlite_storage_t *storage)
{
    return storage != NULL && storage->connection_fenced != 0;
}
