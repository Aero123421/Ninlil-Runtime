#ifndef NINLIL_POSIX_LAB_PLATFORM_H
#define NINLIL_POSIX_LAB_PLATFORM_H

/*
 * V1-LAB POSIX platform provider set (factory / ownership / shutdown / restart).
 * Composes allocator, execution, clock, entropy, SQLite storage, simulated
 * bearer + tx_gate, and canonical origin authorization for host LAB use.
 *
 * This header is not part of the public Ninlil ABI under include/ninlil/.
 */

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"
#include "ninlil_posix_sqlite_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_INACTIVE ((uint32_t)0u)
#define NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_ACTIVE   ((uint32_t)1u)
#define NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_SHUTDOWN ((uint32_t)2u)

typedef struct ninlil_posix_lab_platform ninlil_posix_lab_platform_t;

typedef struct ninlil_posix_lab_platform_config {
    /*
     * SQLite database path. When NULL, create() uses a private temp file that
     * survives restart until destroy().
     */
    const char *database_path;
    ninlil_role_t role;
    ninlil_environment_t environment;
    uint64_t execution_context_id;
    uint64_t entropy_seed;
    uint32_t entropy_stream_id;
    uint32_t busy_timeout_ms;
    uint64_t max_entries_per_namespace;
    uint64_t max_bytes_per_namespace;
    uint32_t max_sqlite_handles;
    uint32_t max_sqlite_transactions;
    uint32_t max_sqlite_iterators;
    uint64_t bearer_max_entries_per_direction;
    uint64_t bearer_max_bytes_per_direction;
    uint32_t bearer_max_permits;
} ninlil_posix_lab_platform_config_t;

void ninlil_posix_lab_platform_config_defaults(
    ninlil_posix_lab_platform_config_t *config);

/*
 * Create and wire every platform.h provider slot. Returns NULL on invalid
 * config or allocation failure. Caller owns the returned object until destroy.
 */
ninlil_posix_lab_platform_t *ninlil_posix_lab_platform_create(
    const ninlil_posix_lab_platform_config_t *config);

/*
 * Tear down every provider in reverse dependency order. Idempotent after the
 * first successful destroy (second call is a no-op).
 */
void ninlil_posix_lab_platform_destroy(ninlil_posix_lab_platform_t *platform);

/*
 * Shutdown all providers and recreate them with the same configuration and
 * database path. Fails when lifecycle is not ACTIVE or recreate fails.
 */
int ninlil_posix_lab_platform_restart(ninlil_posix_lab_platform_t *platform);

const ninlil_platform_ops_t *ninlil_posix_lab_platform_ops(
    const ninlil_posix_lab_platform_t *platform);

uint32_t ninlil_posix_lab_platform_lifecycle(
    const ninlil_posix_lab_platform_t *platform);

const char *ninlil_posix_lab_platform_database_path(
    const ninlil_posix_lab_platform_t *platform);

ninlil_posix_sqlite_storage_t *ninlil_posix_lab_platform_storage_handle(
    ninlil_posix_lab_platform_t *platform);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_LAB_PLATFORM_H */
