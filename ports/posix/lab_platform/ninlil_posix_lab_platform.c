#include "ninlil_posix_lab_platform.h"

#include "canonical_origin_authorization.h"
#include "deterministic_entropy.h"
#include "ninlil_posix_loopback_bearer.h"
#include "ninlil_posix_loopback_bearer_inject.h"
#include "platform_basic_fixtures.h"
#include "typed_simulated_bearer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ninlil_posix_lab_platform {
    ninlil_posix_lab_platform_config_t config;
    char owned_database_path[512];
    int owns_database_path;
    uint32_t lifecycle;
    ninlil_test_allocator_t *allocator;
    ninlil_test_execution_t *execution;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_posix_sqlite_storage_t *storage;
    ninlil_test_bearer_t *bearer;
    ninlil_posix_loopback_bearer_t *loopback_bearer;
    ninlil_posix_loopback_bearer_inject_t *loopback_inject;
    ninlil_test_origin_auth_t *origin;
    ninlil_platform_ops_t platform;
};

static int make_temp_database_path(char *out, size_t out_size)
{
    const char *tmpdir = getenv("TMPDIR");
    int written;
    int fd;

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    written = snprintf(out, out_size, "%s/ninlil-posix-lab-XXXXXX", tmpdir);
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

static void remove_database_artifacts(const char *path)
{
    char wal[576];
    char shm[576];

    if (path == NULL || path[0] == '\0') {
        return;
    }
    (void)unlink(path);
    (void)snprintf(wal, sizeof(wal), "%s-wal", path);
    (void)snprintf(shm, sizeof(shm), "%s-shm", path);
    (void)unlink(wal);
    (void)unlink(shm);
}

static int sqlite_config_from_platform(
    const ninlil_posix_lab_platform_t *platform,
    ninlil_posix_sqlite_storage_config_t *out)
{
    const char *path;

    if (platform == NULL || out == NULL) {
        return 0;
    }
    path = platform->owned_database_path[0] != '\0'
        ? platform->owned_database_path
        : platform->config.database_path;
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    (void)memset(out, 0, sizeof(*out));
    out->database_path = path;
    out->busy_timeout_ms = platform->config.busy_timeout_ms;
    out->max_entries_per_namespace = platform->config.max_entries_per_namespace;
    out->max_bytes_per_namespace = platform->config.max_bytes_per_namespace;
    out->max_handles = platform->config.max_sqlite_handles;
    out->max_transactions = platform->config.max_sqlite_transactions;
    out->max_iterators = platform->config.max_sqlite_iterators;
    return 1;
}

static void platform_wire_ops(ninlil_posix_lab_platform_t *platform)
{
    (void)memset(&platform->platform, 0, sizeof(platform->platform));
    platform->platform.abi_version = NINLIL_ABI_VERSION;
    platform->platform.struct_size = (uint16_t)sizeof(platform->platform);
    platform->platform.allocator =
        ninlil_test_allocator_ops(platform->allocator);
    platform->platform.execution =
        ninlil_test_execution_ops(platform->execution);
    platform->platform.clock = ninlil_test_clock_ops(platform->clock);
    platform->platform.entropy = ninlil_test_entropy_ops(platform->entropy);
    platform->platform.storage =
        ninlil_posix_sqlite_storage_ops(platform->storage);
    if (platform->config.bearer_kind == NINLIL_POSIX_LAB_PLATFORM_BEARER_LOOPBACK
        && platform->loopback_inject != NULL) {
        platform->platform.bearer =
            ninlil_posix_loopback_bearer_inject_bearer_ops(platform->loopback_inject);
        platform->platform.tx_gate =
            ninlil_posix_loopback_bearer_inject_tx_gate_ops(platform->loopback_inject);
    } else if (platform->bearer != NULL) {
        platform->platform.bearer = ninlil_test_bearer_ops(platform->bearer);
        platform->platform.tx_gate =
            ninlil_test_bearer_tx_gate_ops(platform->bearer);
    }
    platform->platform.origin_authorization =
        ninlil_test_origin_auth_ops(platform->origin);
}

static void providers_shutdown(ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL) {
        return;
    }
    if (platform->loopback_inject != NULL) {
        ninlil_posix_loopback_bearer_inject_destroy(platform->loopback_inject);
        platform->loopback_inject = NULL;
    }
    if (platform->loopback_bearer != NULL) {
        ninlil_posix_loopback_bearer_destroy(platform->loopback_bearer);
        platform->loopback_bearer = NULL;
    }
    if (platform->bearer != NULL) {
        ninlil_test_bearer_destroy(platform->bearer);
        platform->bearer = NULL;
    }
    if (platform->storage != NULL) {
        ninlil_posix_sqlite_storage_destroy(platform->storage);
        platform->storage = NULL;
    }
    if (platform->origin != NULL) {
        ninlil_test_origin_auth_destroy(platform->origin);
        platform->origin = NULL;
    }
    if (platform->entropy != NULL) {
        ninlil_test_entropy_destroy(platform->entropy);
        platform->entropy = NULL;
    }
    if (platform->clock != NULL) {
        ninlil_test_clock_destroy(platform->clock);
        platform->clock = NULL;
    }
    if (platform->execution != NULL) {
        ninlil_test_execution_destroy(platform->execution);
        platform->execution = NULL;
    }
    if (platform->allocator != NULL) {
        (void)ninlil_test_allocator_destroy(platform->allocator);
        platform->allocator = NULL;
    }
    (void)memset(&platform->platform, 0, sizeof(platform->platform));
}

static int providers_create(ninlil_posix_lab_platform_t *platform)
{
    ninlil_posix_sqlite_storage_config_t storage_config;
    ninlil_test_bearer_config_t bearer_config;
    ninlil_posix_loopback_bearer_config_t loopback_config;
    ninlil_posix_loopback_bearer_inject_config_t inject_config;

    platform->allocator = ninlil_test_allocator_create();
    platform->execution = ninlil_test_execution_create(
        platform->config.execution_context_id);
    platform->clock = ninlil_test_clock_create();
    platform->entropy = ninlil_test_entropy_create(
        platform->config.entropy_seed, platform->config.entropy_stream_id);
    platform->origin = ninlil_test_origin_auth_create();
    if (!sqlite_config_from_platform(platform, &storage_config)) {
        return 0;
    }
    platform->storage = ninlil_posix_sqlite_storage_create(&storage_config);
    if (platform->config.bearer_kind == NINLIL_POSIX_LAB_PLATFORM_BEARER_LOOPBACK) {
        ninlil_posix_loopback_bearer_config_defaults(&loopback_config);
        loopback_config.socket_path = platform->config.loopback_socket_path;
        loopback_config.role = platform->config.loopback_role;
        loopback_config.max_entries_per_direction =
            platform->config.bearer_max_entries_per_direction;
        loopback_config.max_bytes_per_direction =
            platform->config.bearer_max_bytes_per_direction;
        loopback_config.max_permits = platform->config.bearer_max_permits;
        platform->loopback_bearer =
            ninlil_posix_loopback_bearer_create(&loopback_config);
        if (platform->loopback_bearer == NULL) {
            return 0;
        }
        (void)memset(&inject_config, 0, sizeof(inject_config));
        inject_config.inner_bearer =
            ninlil_posix_loopback_bearer_ops(platform->loopback_bearer);
        inject_config.inner_tx_gate =
            ninlil_posix_loopback_bearer_tx_gate_ops(platform->loopback_bearer);
        inject_config.inner_user = platform->loopback_bearer;
        inject_config.seed = platform->config.inject_seed;
        inject_config.mode = platform->config.inject_mode;
        inject_config.drop_budget = platform->config.inject_drop_budget;
        inject_config.duplicate_budget = platform->config.inject_duplicate_budget;
        platform->loopback_inject =
            ninlil_posix_loopback_bearer_inject_create(&inject_config);
        if (platform->loopback_inject == NULL) {
            return 0;
        }
    } else {
        (void)memset(&bearer_config, 0, sizeof(bearer_config));
        bearer_config.max_entries_per_direction =
            platform->config.bearer_max_entries_per_direction;
        bearer_config.max_bytes_per_direction =
            platform->config.bearer_max_bytes_per_direction;
        bearer_config.max_permits = platform->config.bearer_max_permits;
        bearer_config.permit_issuer_id.bytes[0] = 0x80u;
        bearer_config.permit_issuer_id.bytes[15] = 0x01u;
        bearer_config.initial_clock_epoch_id.bytes[0] = 0xa0u;
        bearer_config.initial_clock_epoch_id.bytes[15] = 0x01u;
        bearer_config.initial_time_ms = 1000u;
        platform->bearer = ninlil_test_bearer_create(&bearer_config);
    }
    if (platform->allocator == NULL || platform->execution == NULL
        || platform->clock == NULL || platform->entropy == NULL
        || platform->origin == NULL || platform->storage == NULL
        || (platform->config.bearer_kind == NINLIL_POSIX_LAB_PLATFORM_BEARER_LOOPBACK
            ? (platform->loopback_bearer == NULL
                || platform->loopback_inject == NULL)
            : platform->bearer == NULL)) {
        return 0;
    }
    platform_wire_ops(platform);
    return 1;
}

void ninlil_posix_lab_platform_config_defaults(
    ninlil_posix_lab_platform_config_t *config)
{
    if (config == NULL) {
        return;
    }
    (void)memset(config, 0, sizeof(*config));
    config->role = NINLIL_ROLE_CONTROLLER;
    config->environment = NINLIL_ENV_TEST;
    config->execution_context_id = 1u;
    config->entropy_seed = 0x4e494e4c494c4c41u;
    config->entropy_stream_id = 1u;
    config->busy_timeout_ms = NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS;
    config->max_entries_per_namespace = 512u;
    config->max_bytes_per_namespace = 1048576u;
    config->max_sqlite_handles = 8u;
    config->max_sqlite_transactions = 8u;
    config->max_sqlite_iterators = 8u;
    config->bearer_max_entries_per_direction = 64u;
    config->bearer_max_bytes_per_direction = 131072u;
    config->bearer_max_permits = 128u;
}

ninlil_posix_lab_platform_t *ninlil_posix_lab_platform_create(
    const ninlil_posix_lab_platform_config_t *config)
{
    ninlil_posix_lab_platform_t *platform;
    ninlil_posix_lab_platform_config_t local;

    if (config == NULL) {
        return NULL;
    }
    local = *config;
    if (local.execution_context_id == 0u) {
        return NULL;
    }
    platform = (ninlil_posix_lab_platform_t *)calloc(1u, sizeof(*platform));
    if (platform == NULL) {
        return NULL;
    }
    platform->config = local;
    platform->lifecycle = NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_INACTIVE;
    if (local.database_path == NULL || local.database_path[0] == '\0') {
        if (!make_temp_database_path(
                platform->owned_database_path,
                sizeof(platform->owned_database_path))) {
            free(platform);
            return NULL;
        }
        platform->owns_database_path = 1;
    } else {
        (void)snprintf(
            platform->owned_database_path,
            sizeof(platform->owned_database_path),
            "%s",
            local.database_path);
        platform->owns_database_path = 0;
    }
    if (!providers_create(platform)) {
        providers_shutdown(platform);
        if (platform->owns_database_path) {
            remove_database_artifacts(platform->owned_database_path);
        }
        free(platform);
        return NULL;
    }
    platform->lifecycle = NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_ACTIVE;
    return platform;
}

void ninlil_posix_lab_platform_destroy(ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL) {
        return;
    }
    if (platform->lifecycle == NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_SHUTDOWN) {
        return;
    }
    providers_shutdown(platform);
    if (platform->owns_database_path) {
        remove_database_artifacts(platform->owned_database_path);
        platform->owned_database_path[0] = '\0';
    }
    platform->lifecycle = NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_SHUTDOWN;
    free(platform);
}

int ninlil_posix_lab_platform_restart(ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL
        || platform->lifecycle != NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_ACTIVE) {
        return 0;
    }
    providers_shutdown(platform);
    if (!providers_create(platform)) {
        platform->lifecycle = NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_INACTIVE;
        return 0;
    }
    platform->lifecycle = NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_ACTIVE;
    return 1;
}

const ninlil_platform_ops_t *ninlil_posix_lab_platform_ops(
    const ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL
        || platform->lifecycle != NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_ACTIVE) {
        return NULL;
    }
    return &platform->platform;
}

uint32_t ninlil_posix_lab_platform_lifecycle(
    const ninlil_posix_lab_platform_t *platform)
{
    return platform == NULL ? NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_SHUTDOWN
                            : platform->lifecycle;
}

const char *ninlil_posix_lab_platform_database_path(
    const ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL || platform->owned_database_path[0] == '\0') {
        return NULL;
    }
    return platform->owned_database_path;
}

ninlil_posix_sqlite_storage_t *ninlil_posix_lab_platform_storage_handle(
    ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL
        || platform->lifecycle != NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_ACTIVE) {
        return NULL;
    }
    return platform->storage;
}

ninlil_test_allocator_t *ninlil_posix_lab_platform_test_allocator(
    ninlil_posix_lab_platform_t *platform)
{
    return platform == NULL ? NULL : platform->allocator;
}

ninlil_test_execution_t *ninlil_posix_lab_platform_test_execution(
    ninlil_posix_lab_platform_t *platform)
{
    return platform == NULL ? NULL : platform->execution;
}

ninlil_test_clock_t *ninlil_posix_lab_platform_test_clock(
    ninlil_posix_lab_platform_t *platform)
{
    return platform == NULL ? NULL : platform->clock;
}

ninlil_test_entropy_t *ninlil_posix_lab_platform_test_entropy(
    ninlil_posix_lab_platform_t *platform)
{
    return platform == NULL ? NULL : platform->entropy;
}

ninlil_test_bearer_t *ninlil_posix_lab_platform_test_bearer(
    ninlil_posix_lab_platform_t *platform)
{
    return platform == NULL ? NULL : platform->bearer;
}

ninlil_test_origin_auth_t *ninlil_posix_lab_platform_test_origin(
    ninlil_posix_lab_platform_t *platform)
{
    return platform == NULL ? NULL : platform->origin;
}

int ninlil_posix_lab_platform_test_loopback_connected(
    ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL || platform->loopback_bearer == NULL) {
        return 0;
    }
    return ninlil_posix_loopback_bearer_connected(platform->loopback_bearer);
}

uint64_t ninlil_posix_lab_platform_test_inject_send_count(
    ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL || platform->loopback_inject == NULL) {
        return 0u;
    }
    return ninlil_posix_loopback_bearer_inject_send_count(platform->loopback_inject);
}

uint64_t ninlil_posix_lab_platform_test_inject_recv_count(
    ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL || platform->loopback_inject == NULL) {
        return 0u;
    }
    return ninlil_posix_loopback_bearer_inject_recv_count(platform->loopback_inject);
}

uint64_t ninlil_posix_lab_platform_test_inject_drop_count(
    ninlil_posix_lab_platform_t *platform)
{
    if (platform == NULL || platform->loopback_inject == NULL) {
        return 0u;
    }
    return ninlil_posix_loopback_bearer_inject_drop_count(platform->loopback_inject);
}
