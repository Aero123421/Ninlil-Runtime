/*
 * Minimal host example: open a temp SQLite store, put/get one key, exit.
 * Not a public Runtime demo. Build only when NINLIL_BUILD_POSIX_SQLITE_STORAGE
 * finds SQLite3.
 */

#include "ninlil_posix_sqlite_storage.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int make_temp_path(char *out, size_t out_size)
{
    const char *tmpdir = getenv("TMPDIR");
    int written;
    int fd;

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    written = snprintf(
        out, out_size, "%s/ninlil-sqlite-example-XXXXXX", tmpdir);
    if (written <= 0 || (size_t)written >= out_size) {
        return 0;
    }
    fd = mkstemp(out);
    if (fd < 0) {
        return 0;
    }
    if (close(fd) != 0) {
        (void)unlink(out);
        return 0;
    }
    return 1;
}

static int make_authority_path(
    const char *path,
    char *out,
    size_t out_size)
{
    struct stat st;
    char *canonical;
    char *slash;
    size_t parent_length;
    int written;

    if (stat(path, &st) != 0) {
        return 0;
    }
    canonical = realpath(path, NULL);
    if (canonical == NULL) {
        return 0;
    }
    slash = strrchr(canonical, '/');
    if (slash == NULL) {
        free(canonical);
        return 0;
    }
    parent_length = slash == canonical ? 1u : (size_t)(slash - canonical);
    written = snprintf(
        out,
        out_size,
        "%.*s/.ninlil-sqlite-%llx-%llx.lock",
        (int)parent_length,
        canonical,
        (unsigned long long)st.st_dev,
        (unsigned long long)st.st_ino);
    free(canonical);
    return written > 0 && (size_t)written < out_size;
}

static void remove_artifacts(const char *path)
{
    char authority[768];
    char sidecar[704];
    int have_authority;
    static const char *const suffixes[] = {"-wal", "-shm", "-journal"};
    size_t index;

    if (path == NULL || path[0] == '\0') {
        return;
    }
    have_authority = make_authority_path(
        path, authority, sizeof(authority));
    for (index = 0u; index < sizeof(suffixes) / sizeof(suffixes[0]); ++index) {
        int written = snprintf(
            sidecar, sizeof(sidecar), "%s%s", path, suffixes[index]);
        if (written > 0 && (size_t)written < sizeof(sidecar)) {
            (void)unlink(sidecar);
        }
    }
    (void)unlink(path);
    if (have_authority) {
        (void)unlink(authority);
    }
}

int main(void)
{
    char path[640] = {0};
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage = NULL;
    const ninlil_storage_ops_t *ops = NULL;
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
    ninlil_storage_status_t status;
    int exit_code = 1;

    if (!make_temp_path(path, sizeof(path))) {
        goto cleanup;
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
        goto cleanup;
    }
    ops = ninlil_posix_sqlite_storage_ops(storage);
    ns.data = ns_bytes;
    ns.length = (uint32_t)sizeof(ns_bytes);
    if (ops->open(ops->user, ns, NINLIL_STORAGE_SCHEMA_M1A, &handle)
        != NINLIL_STORAGE_OK) {
        goto cleanup;
    }
    if (ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        != NINLIL_STORAGE_OK) {
        goto cleanup;
    }
    key.data = key_bytes;
    key.length = (uint32_t)sizeof(key_bytes);
    value.data = value_bytes;
    value.length = (uint32_t)sizeof(value_bytes);
    if (ops->put(ops->user, txn, key, value) != NINLIL_STORAGE_OK) {
        goto cleanup;
    }
    status = ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL);
    txn = NULL;
    if (status != NINLIL_STORAGE_OK) {
        goto cleanup;
    }
    if (ops->begin(ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
        != NINLIL_STORAGE_OK) {
        goto cleanup;
    }
    out.data = out_raw;
    out.capacity = (uint32_t)sizeof(out_raw);
    out.length = 0u;
    if (ops->get(ops->user, txn, key, &out) != NINLIL_STORAGE_OK
        || out.length != value.length
        || memcmp(out_raw, value_bytes, value.length) != 0) {
        goto cleanup;
    }
    (void)ops->rollback(ops->user, txn);
    txn = NULL;
    exit_code = 0;

cleanup:
    if (txn != NULL && ops != NULL) {
        (void)ops->rollback(ops->user, txn);
    }
    if (handle != NULL && ops != NULL) {
        ops->close(ops->user, handle);
    }
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_artifacts(path);
    if (exit_code == 0) {
        (void)printf("posix sqlite storage minimal example ok\n");
    }
    return exit_code;
}
