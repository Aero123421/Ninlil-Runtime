#ifndef NINLIL_POSIX_SQLITE_STORAGE_H
#define NINLIL_POSIX_SQLITE_STORAGE_H

/*
 * Port-owned factory for the POSIX SQLite durable storage provider.
 * This header is not part of the public Ninlil ABI under include/ninlil/.
 *
 * Contract sources: docs/08 §SQLite POSIX port, docs/12 storage ABI,
 * docs/14 storage port contract. Namespace bytes are opaque 1..255 and are
 * never interpreted as filesystem path text.
 */

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_SQLITE_SCHEMA_VERSION ((uint32_t)1u)
#define NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS ((uint32_t)1000u)
#define NINLIL_POSIX_SQLITE_MAX_POOL ((uint32_t)64u)

typedef struct ninlil_posix_sqlite_storage ninlil_posix_sqlite_storage_t;

typedef struct ninlil_posix_sqlite_storage_config {
    /*
     * Absolute or relative filesystem path of a single SQLite database file.
     * The path is host configuration, not a storage namespace.
     */
    const char *database_path;
    uint32_t busy_timeout_ms;
    uint64_t max_entries_per_namespace;
    uint64_t max_bytes_per_namespace;
    uint32_t max_handles;
    uint32_t max_transactions;
    uint32_t max_iterators;
} ninlil_posix_sqlite_storage_config_t;

/*
 * Thin test-only commit fault seam. Production callers leave the default
 * (none). When set, the next otherwise-valid FULL commit consumes the fault
 * exactly once and returns COMMIT_UNKNOWN with the indicated hidden truth.
 */
typedef enum ninlil_posix_sqlite_commit_fault {
    NINLIL_POSIX_SQLITE_COMMIT_FAULT_NONE = 0,
    NINLIL_POSIX_SQLITE_COMMIT_FAULT_UNKNOWN_COMMITTED = 1,
    NINLIL_POSIX_SQLITE_COMMIT_FAULT_UNKNOWN_NOT_COMMITTED = 2
} ninlil_posix_sqlite_commit_fault_t;

/*
 * Open/create the configured database file, apply WAL / synchronous=FULL /
 * foreign_keys, and verify or initialize schema version 1. Returns NULL on
 * invalid config, I/O failure, or unsupported schema (migration is rejected).
 */
ninlil_posix_sqlite_storage_t *ninlil_posix_sqlite_storage_create(
    const ninlil_posix_sqlite_storage_config_t *config);

void ninlil_posix_sqlite_storage_destroy(ninlil_posix_sqlite_storage_t *storage);

const ninlil_storage_ops_t *ninlil_posix_sqlite_storage_ops(
    ninlil_posix_sqlite_storage_t *storage);

/* Drop volatile leases/handles as if the process crashed mid-flight. */
void ninlil_posix_sqlite_storage_simulate_crash(
    ninlil_posix_sqlite_storage_t *storage);

void ninlil_posix_sqlite_storage_set_commit_fault(
    ninlil_posix_sqlite_storage_t *storage,
    ninlil_posix_sqlite_commit_fault_t fault);

uint64_t ninlil_posix_sqlite_storage_live_handles(
    const ninlil_posix_sqlite_storage_t *storage);

uint64_t ninlil_posix_sqlite_storage_live_transactions(
    const ninlil_posix_sqlite_storage_t *storage);

uint64_t ninlil_posix_sqlite_storage_live_iterators(
    const ninlil_posix_sqlite_storage_t *storage);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_SQLITE_STORAGE_H */
