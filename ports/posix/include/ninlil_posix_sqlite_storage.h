#ifndef NINLIL_POSIX_SQLITE_STORAGE_H
#define NINLIL_POSIX_SQLITE_STORAGE_H

/*
 * Port-owned factory for the POSIX SQLite durable storage provider.
 * This header is not part of the public Ninlil ABI under include/ninlil/.
 *
 * Contract sources: docs/08 §SQLite POSIX port, docs/12 storage ABI,
 * docs/14 storage port contract. Namespace bytes are opaque 1..255 and are
 * never interpreted as filesystem path text.
 *
 * Before SQLite open, the provider opens the final database path with
 * O_NOFOLLOW|O_CLOEXEC, rejects symlinks/hardlinks, and locks an adjacent
 * st_dev/st_ino-keyed authority sidecar with O_NOFOLLOW|O_CLOEXEC. The
 * sidecar must be owned by the current effective UID with exact mode 0600.
 * Main and sidecar path↔fd identity/owner/mode/nlink are rechecked after open
 * and during durable namespace persist at least: after BEGIN IMMEDIATE, before
 * DELETE/INSERT, immediately before COMMIT, and after COMMIT success before
 * public OK. Replacement observed at a pre-COMMIT revalidation rolls back the
 * open transaction (when autocommit can confirm non-commit) and fences.
 * Replacement after the last pre-COMMIT revalidation but before COMMIT returns,
 * or after COMMIT success, is observed only at the post-COMMIT identity check
 * and returns COMMIT_UNKNOWN with a fenced connection — never OK. Checks do
 * not atomically close the windows between them; support requires operators not
 * to rename/replace live paths (docs/08, port README). Schema v1 accepts only
 * its closed table object set and revalidates it inside the same transaction
 * after BEGIN IMMEDIATE and before DELETE/INSERT. Opaque values are
 * non-dereferenced addresses from a pre-reserved 64-bit virtual token arena;
 * addresses are not reused until provider destroy and do not consume heap per
 * operation. Capacity is commit-time net of the final view (docs/08, docs/14).
 *
 * Supported host diagnostics (same thread as the storage instance; no internal
 * locking): live handle/txn/iterator counters, connection/lease-token fence
 * flags, and simulate_crash. See function comments and docs/08 / port README
 * for lifetime and side effects.
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
 * Open/create the configured database file, apply WAL / synchronous=FULL /
 * foreign_keys, and verify or initialize schema version 1. Returns NULL on
 * invalid config, I/O failure, or unsupported schema (migration is rejected).
 */
ninlil_posix_sqlite_storage_t *ninlil_posix_sqlite_storage_create(
    const ninlil_posix_sqlite_storage_config_t *config);

void ninlil_posix_sqlite_storage_destroy(ninlil_posix_sqlite_storage_t *storage);

const ninlil_storage_ops_t *ninlil_posix_sqlite_storage_ops(
    ninlil_posix_sqlite_storage_t *storage);

/*
 * Supported diagnostic: drop all live namespace handles/leases as if the
 * process crashed mid-flight. Caller-held txn/iterator tokens become stale
 * (subsequent use fail-closed). Does not unlink DB/sidecar files or reverse
 * durable commits. Thread: same thread that owns the storage instance.
 */
void ninlil_posix_sqlite_storage_simulate_crash(
    ninlil_posix_sqlite_storage_t *storage);

/*
 * Supported diagnostics: counts of currently live opaque tokens on this
 * instance. Zero when storage is NULL. Thread: same thread as the instance;
 * values are snapshots, not synchronized across threads.
 */
uint64_t ninlil_posix_sqlite_storage_live_handles(
    const ninlil_posix_sqlite_storage_t *storage);

uint64_t ninlil_posix_sqlite_storage_live_transactions(
    const ninlil_posix_sqlite_storage_t *storage);

uint64_t ninlil_posix_sqlite_storage_live_iterators(
    const ninlil_posix_sqlite_storage_t *storage);

/*
 * Supported diagnostics: permanent fail-closed flags.
 * lease_tokens_fenced: lease-token sequence exhausted (no further open).
 * connection_fenced: durable outcome or identity could not be classified;
 * further durable use of this connection is fail-closed.
 * Thread: same thread as the instance.
 */
int ninlil_posix_sqlite_storage_lease_tokens_fenced(
    const ninlil_posix_sqlite_storage_t *storage);

int ninlil_posix_sqlite_storage_connection_fenced(
    const ninlil_posix_sqlite_storage_t *storage);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_SQLITE_STORAGE_H */
