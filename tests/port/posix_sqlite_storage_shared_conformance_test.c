#include "ninlil_posix_sqlite_storage.h"
#include "storage_conformance.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int make_authority_lock_path(
    const char *path,
    char *out,
    size_t out_size)
{
    struct stat st = {0};
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
    char sidecar[768];
    char lock_path[768];
    int have_lock_path = make_authority_lock_path(
        path, lock_path, sizeof(lock_path));

    (void)remove(path);
    if (snprintf(sidecar, sizeof(sidecar), "%s-wal", path) > 0) {
        (void)remove(sidecar);
    }
    if (snprintf(sidecar, sizeof(sidecar), "%s-shm", path) > 0) {
        (void)remove(sidecar);
    }
    if (have_lock_path) {
        (void)remove(lock_path);
    }
}

int main(void)
{
    static const uint8_t storage_namespace[] = {
        0x73u, 0x68u, 0x61u, 0x72u, 0x65u, 0x64u, 0x00u, 0xffu
    };
    char path[640];
    const char *tmpdir = getenv("TMPDIR");
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    int result;
    int written;

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    written = snprintf(path, sizeof(path),
        "%s/ninlil-shared-conformance-XXXXXX", tmpdir);
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return 1;
    }
    {
        int fd = mkstemp(path);
        if (fd < 0 || close(fd) != 0) {
            if (fd >= 0) {
                (void)unlink(path);
            }
            return 1;
        }
    }
    (void)memset(&config, 0, sizeof(config));
    config.database_path = path;
    config.busy_timeout_ms = 100u;
    config.max_entries_per_namespace = 32u;
    config.max_bytes_per_namespace = 65536u;
    config.max_handles = 4u;
    config.max_transactions = 4u;
    config.max_iterators = 4u;
    storage = ninlil_posix_sqlite_storage_create(&config);
    if (storage == NULL) {
        remove_artifacts(path);
        return 1;
    }
    result = ninlil_test_storage_conformance_run(
        ninlil_posix_sqlite_storage_ops(storage),
        storage_namespace,
        (uint32_t)sizeof(storage_namespace),
        NINLIL_STORAGE_SCHEMA_M1A);
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_artifacts(path);
    if (result == 0) {
        (void)printf("POSIX SQLite shared storage conformance ok\n");
    }
    return result;
}
