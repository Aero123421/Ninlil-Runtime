/*
 * Minimal host example: open a temp SQLite store, put/get one key, exit.
 * Not a public Runtime demo. Build only when NINLIL_BUILD_POSIX_SQLITE_STORAGE
 * finds SQLite3.
 */

#include "ninlil_posix_sqlite_storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(void)
{
    char path[640];
    const char *tmpdir = getenv("TMPDIR");
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_bytes_view_t ns;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    uint8_t out_raw[16];
    ninlil_mut_bytes_t out;
    static const uint8_t ns_bytes[] = {0x65u, 0x78u, 0x00u, 0xffu};
    static const uint8_t key_bytes[] = {0x6bu, 0x31u};
    static const uint8_t value_bytes[] = {0x68u, 0x69u};

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    if (snprintf(
            path,
            sizeof(path),
            "%s/ninlil-sqlite-example-%lu.db",
            tmpdir,
            (unsigned long)time(NULL))
        < 0) {
        return 1;
    }

    (void)memset(&config, 0, sizeof(config));
    config.database_path = path;
    config.busy_timeout_ms = 100u;
    config.max_entries_per_namespace = 64u;
    config.max_bytes_per_namespace = 65536u;
    config.max_handles = 4u;
    config.max_transactions = 4u;
    config.max_iterators = 4u;

    storage = ninlil_posix_sqlite_storage_create(&config);
    if (storage == NULL) {
        return 1;
    }
    ops = ninlil_posix_sqlite_storage_ops(storage);
    ns.data = ns_bytes;
    ns.length = (uint32_t)sizeof(ns_bytes);
    if (ops->open(ops->user, ns, NINLIL_STORAGE_SCHEMA_M1A, &handle)
        != NINLIL_STORAGE_OK) {
        ninlil_posix_sqlite_storage_destroy(storage);
        return 1;
    }
    if (ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        != NINLIL_STORAGE_OK) {
        ops->close(ops->user, handle);
        ninlil_posix_sqlite_storage_destroy(storage);
        return 1;
    }
    key.data = key_bytes;
    key.length = (uint32_t)sizeof(key_bytes);
    value.data = value_bytes;
    value.length = (uint32_t)sizeof(value_bytes);
    if (ops->put(ops->user, txn, key, value) != NINLIL_STORAGE_OK
        || ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        ops->close(ops->user, handle);
        ninlil_posix_sqlite_storage_destroy(storage);
        return 1;
    }
    txn = NULL;
    if (ops->begin(ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
        != NINLIL_STORAGE_OK) {
        ops->close(ops->user, handle);
        ninlil_posix_sqlite_storage_destroy(storage);
        return 1;
    }
    out.data = out_raw;
    out.capacity = (uint32_t)sizeof(out_raw);
    out.length = 0u;
    if (ops->get(ops->user, txn, key, &out) != NINLIL_STORAGE_OK
        || out.length != value.length
        || memcmp(out_raw, value_bytes, value.length) != 0) {
        (void)ops->rollback(ops->user, txn);
        ops->close(ops->user, handle);
        ninlil_posix_sqlite_storage_destroy(storage);
        return 1;
    }
    (void)ops->rollback(ops->user, txn);
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);
    (void)remove(path);
    (void)printf("posix sqlite storage minimal example ok\n");
    return 0;
}
