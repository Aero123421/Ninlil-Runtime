/*
 * V1-LAB unit 1b: POSIX SQLite restart E2E (single process).
 * (a) durable submit → restart → recovery resume, no duplicate resend
 * (b) COMMIT_UNKNOWN restart → false success 0
 * (c) corrupt DB page → recovery reject + bounded termination
 * (d) allowlist-external row injection → publication reject
 */

#include "ninlil_posix_sqlite_storage.h"
#include "runtime_lifecycle_model.h"
#include "runtime_store_stage5_seam.h"
#include "stage5_empty_metadata.h"
#include "v1_durable_restart.h"

#include <ninlil/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t TEST_NAMESPACE[] = "v1-posix-sqlite-restart-e2e";

typedef struct validation_platform {
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_storage_ops_t storage;
    ninlil_bearer_ops_t bearer;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t platform;
} validation_platform_t;

typedef struct sqlite_session {
    char path[512];
    ninlil_posix_sqlite_storage_t *provider;
    const ninlil_storage_ops_t *storage;
    ninlil_storage_handle_t handle;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_runtime_store_stage5_workspace_t stage5_ws;
    ninlil_stage5_empty_metadata_workspace_t empty_ws;
} sqlite_session_t;

static void *vp_allocate(void *user, uint64_t size, uint32_t alignment)
{
    (void)user;
    (void)size;
    (void)alignment;
    return NULL;
}

static void vp_deallocate(
    void *user, void *ptr, uint64_t size, uint32_t alignment)
{
    (void)user;
    (void)ptr;
    (void)size;
    (void)alignment;
}

static uint64_t vp_context(void *user)
{
    (void)user;
    return 1u;
}

static ninlil_port_status_t vp_clock(void *user, ninlil_time_sample_t *out)
{
    (void)user;
    (void)out;
    return NINLIL_PORT_PERMANENT_FAILURE;
}

static ninlil_port_status_t vp_entropy(
    void *user, uint8_t *out, uint32_t length)
{
    (void)user;
    (void)out;
    (void)length;
    return NINLIL_PORT_PERMANENT_FAILURE;
}

static ninlil_storage_status_t vp_storage_open(
    void *user,
    ninlil_bytes_view_t ns,
    uint32_t schema,
    ninlil_storage_handle_t *out_handle)
{
    (void)user;
    (void)ns;
    (void)schema;
    (void)out_handle;
    return NINLIL_STORAGE_IO_ERROR;
}

static void vp_storage_close(void *user, ninlil_storage_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_storage_status_t vp_storage_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    (void)user;
    (void)handle;
    (void)mode;
    (void)out_txn;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    (void)user;
    (void)txn;
    (void)key;
    (void)inout_value;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    (void)user;
    (void)txn;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    (void)user;
    (void)txn;
    (void)key;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    (void)user;
    (void)txn;
    (void)prefix;
    (void)out_iter;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *value)
{
    (void)user;
    (void)iter;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_IO_ERROR;
}

static void vp_storage_iter_close(void *user, ninlil_storage_iter_t iter)
{
    (void)user;
    (void)iter;
}

static ninlil_storage_status_t vp_storage_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    (void)user;
    (void)handle;
    (void)out_capacity;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    (void)user;
    (void)txn;
    (void)durability;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_storage_status_t vp_storage_rollback(
    void *user,
    ninlil_storage_txn_t txn)
{
    (void)user;
    (void)txn;
    return NINLIL_STORAGE_IO_ERROR;
}

static ninlil_bearer_status_t vp_bearer_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    (void)user;
    (void)runtime_id;
    (void)role;
    (void)out_handle;
    return NINLIL_BEARER_UNAVAILABLE;
}

static void vp_bearer_close(void *user, ninlil_bearer_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_bearer_status_t vp_bearer_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    (void)user;
    (void)handle;
    (void)permit;
    (void)message;
    (void)out_result;
    return NINLIL_BEARER_UNAVAILABLE;
}

static ninlil_bearer_status_t vp_bearer_receive(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    (void)user;
    (void)handle;
    (void)out_message;
    return NINLIL_BEARER_EMPTY;
}

static void vp_bearer_release(
    void *user, ninlil_bearer_handle_t handle, ninlil_bearer_message_t *message)
{
    (void)user;
    (void)handle;
    (void)message;
}

static ninlil_bearer_status_t vp_bearer_state(
    void *user, ninlil_bearer_handle_t handle, ninlil_bearer_state_t *out_state)
{
    (void)user;
    (void)handle;
    (void)out_state;
    return NINLIL_BEARER_UNAVAILABLE;
}

static ninlil_tx_gate_status_t vp_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    (void)user;
    (void)request;
    (void)now;
    (void)out_permit;
    return NINLIL_TX_GATE_TEMPORARY;
}

static void vp_tx_release(void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t vp_origin(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *decision)
{
    (void)user;
    (void)request;
    (void)decision;
    return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
}

static void validation_platform_init(validation_platform_t *vp)
{
    (void)memset(vp, 0, sizeof(*vp));
#define HDR(obj)                                                               \
    do {                                                                       \
        (obj).abi_version = NINLIL_ABI_VERSION;                                \
        (obj).struct_size = (uint16_t)sizeof(obj);                             \
    } while (0)
    HDR(vp->allocator);
    vp->allocator.allocate = vp_allocate;
    vp->allocator.deallocate = vp_deallocate;
    HDR(vp->execution);
    vp->execution.current_context_id = vp_context;
    HDR(vp->clock);
    vp->clock.now = vp_clock;
    HDR(vp->entropy);
    vp->entropy.fill = vp_entropy;
    HDR(vp->storage);
    vp->storage.open = vp_storage_open;
    vp->storage.close = vp_storage_close;
    vp->storage.begin = vp_storage_begin;
    vp->storage.get = vp_storage_get;
    vp->storage.put = vp_storage_put;
    vp->storage.erase = vp_storage_erase;
    vp->storage.iter_open = vp_storage_iter_open;
    vp->storage.iter_next = vp_storage_iter_next;
    vp->storage.iter_close = vp_storage_iter_close;
    vp->storage.capacity = vp_storage_capacity;
    vp->storage.commit = vp_storage_commit;
    vp->storage.rollback = vp_storage_rollback;
    HDR(vp->bearer);
    vp->bearer.open = vp_bearer_open;
    vp->bearer.close = vp_bearer_close;
    vp->bearer.send = vp_bearer_send;
    vp->bearer.receive_next = vp_bearer_receive;
    vp->bearer.release_received = vp_bearer_release;
    vp->bearer.state = vp_bearer_state;
    HDR(vp->tx_gate);
    vp->tx_gate.acquire = vp_tx_acquire;
    vp->tx_gate.release_unused = vp_tx_release;
    HDR(vp->origin);
    vp->origin.evaluate = vp_origin;
    HDR(vp->platform);
    vp->platform.allocator = &vp->allocator;
    vp->platform.execution = &vp->execution;
    vp->platform.clock = &vp->clock;
    vp->platform.entropy = &vp->entropy;
    vp->platform.storage = &vp->storage;
    vp->platform.bearer = &vp->bearer;
    vp->platform.tx_gate = &vp->tx_gate;
    vp->platform.origin_authorization = &vp->origin;
#undef HDR
}

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static ninlil_runtime_config_t config_fixture(void)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x10u);
    config.local_identity.abi_version = NINLIL_ABI_VERSION;
    config.local_identity.struct_size =
        (uint16_t)sizeof(config.local_identity);
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x20u);
    set_id(&config.local_identity.installation_id, 0x40u);
    set_id(&config.local_identity.site_domain_id, 0x60u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = TEST_NAMESPACE;
    config.storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    config.limits.abi_version = NINLIL_ABI_VERSION;
    config.limits.struct_size = (uint16_t)sizeof(config.limits);
    config.limits.max_services = 11u;
    config.limits.max_nonterminal_transactions = 27u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 5000u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 30u;
    config.limits.max_nonterminal_deliveries = 19u;
    config.limits.max_result_cache_entries = 13u;
    config.limits.max_retained_dispositions = 14u;
    config.limits.max_ingress_per_step = 15u;
    config.limits.max_callbacks_per_step = 16u;
    config.limits.max_state_transitions_per_step = 17u;
    config.limits.max_bearer_sends_per_step = 18u;
    config.limits.max_deferred_tokens = 12u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 900u;
    config.observation_retention_ms = 800u;
    return config;
}

static int validation_from_config(
    const ninlil_runtime_config_t *config,
    ninlil_model_runtime_validation_result_t *out)
{
    validation_platform_t vp;
    ninlil_status_t st;

    if (config == NULL || out == NULL) {
        return 0;
    }
    validation_platform_init(&vp);
    st = ninlil_model_runtime_validate_and_derive(config, &vp.platform, out);
    return st == NINLIL_OK && out->status == NINLIL_OK
        && out->failure_field == NINLIL_MODEL_RUNTIME_VALIDATION_NONE;
}

static int make_temp_path(char *out, size_t out_size)
{
    const char *tmpdir = getenv("TMPDIR");
    int written;
    int fd;

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    written = snprintf(
        out, out_size, "%s/ninlil-v1-restart-XXXXXX", tmpdir);
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

static void remove_db_artifacts(const char *path)
{
    char wal[576];
    char shm[576];
    (void)unlink(path);
    (void)snprintf(wal, sizeof(wal), "%s-wal", path);
    (void)snprintf(shm, sizeof(shm), "%s-shm", path);
    (void)unlink(wal);
    (void)unlink(shm);
}

static int sqlite_config(
    const char *path,
    ninlil_posix_sqlite_storage_config_t *out)
{
    (void)memset(out, 0, sizeof(*out));
    out->database_path = path;
    out->busy_timeout_ms = 200u;
    out->max_entries_per_namespace = 128u;
    out->max_bytes_per_namespace = 512000u;
    out->max_handles = 8u;
    out->max_transactions = 8u;
    out->max_iterators = 8u;
    return 1;
}

static int session_open(sqlite_session_t *session)
{
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_bytes_view_t ns;
    ninlil_runtime_config_t runtime_config;

    (void)memset(session, 0, sizeof(*session));
    if (!make_temp_path(session->path, sizeof(session->path))) {
        return 0;
    }
    if (!sqlite_config(session->path, &config)) {
        return 0;
    }
    session->provider = ninlil_posix_sqlite_storage_create(&config);
    if (session->provider == NULL) {
        return 0;
    }
    session->storage = ninlil_posix_sqlite_storage_ops(session->provider);
    runtime_config = config_fixture();
    if (!validation_from_config(&runtime_config, &session->validation)) {
        return 0;
    }
    ns.data = TEST_NAMESPACE;
    ns.length = sizeof(TEST_NAMESPACE) - 1u;
    return session->storage->open(
               session->storage->user,
               ns,
               NINLIL_STORAGE_SCHEMA_M1A,
               &session->handle)
        == NINLIL_STORAGE_OK;
}

static void session_shutdown_provider(sqlite_session_t *session)
{
    if (session->handle != NULL && session->storage != NULL) {
        session->storage->close(session->storage->user, session->handle);
        session->handle = NULL;
    }
    if (session->provider != NULL) {
        ninlil_posix_sqlite_storage_destroy(session->provider);
        session->provider = NULL;
        session->storage = NULL;
    }
}

static int session_restart_provider(sqlite_session_t *session)
{
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_bytes_view_t ns;

    session_shutdown_provider(session);
    if (!sqlite_config(session->path, &config)) {
        return 0;
    }
    session->provider = ninlil_posix_sqlite_storage_create(&config);
    if (session->provider == NULL) {
        return 0;
    }
    session->storage = ninlil_posix_sqlite_storage_ops(session->provider);
    ns.data = TEST_NAMESPACE;
    ns.length = sizeof(TEST_NAMESPACE) - 1u;
    return session->storage->open(
               session->storage->user,
               ns,
               NINLIL_STORAGE_SCHEMA_M1A,
               &session->handle)
        == NINLIL_STORAGE_OK;
}

static int session_destroy(sqlite_session_t *session)
{
    session_shutdown_provider(session);
    remove_db_artifacts(session->path);
    return 1;
}

static int durable_submit_bootstrap(sqlite_session_t *session)
{
    ninlil_runtime_store_stage5_result_t result;

    (void)memset(&session->stage5_ws, 0, sizeof(session->stage5_ws));
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_runtime_store_stage5_private_hookup(
                session->storage,
                &session->handle,
                &session->validation,
                NULL,
                &session->stage5_ws,
                &result)
        == NINLIL_OK);
    REQUIRE(result.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING);
    return 1;
}

static int durable_submit_metadata(sqlite_session_t *session)
{
    ninlil_stage5_empty_metadata_result_t result;

    (void)memset(&session->empty_ws, 0, sizeof(session->empty_ws));
    (void)memset(&result, 0, sizeof(result));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
                session->storage,
                &session->handle,
                &session->validation,
                &session->empty_ws,
                &result)
        == NINLIL_OK);
    REQUIRE(result.wrote_metadata == 1u);
    return 1;
}

static int test_normal_restart_resume_no_duplicate(void)
{
    sqlite_session_t session;
    ninlil_v1_durable_restart_result_t recovery;
    ninlil_stage5_empty_metadata_result_t retry;

    REQUIRE(session_open(&session));
    REQUIRE(durable_submit_bootstrap(&session));
    REQUIRE(durable_submit_metadata(&session));
    REQUIRE(session_restart_provider(&session));

    (void)memset(&session.stage5_ws, 0, sizeof(session.stage5_ws));
    (void)memset(&recovery, 0, sizeof(recovery));
    REQUIRE(ninlil_v1_durable_restart_recovery(
                session.storage,
                &session.handle,
                &session.validation,
                0u,
                &session.stage5_ws,
                &recovery)
        == NINLIL_OK);
    REQUIRE(recovery.stage5.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING);
    REQUIRE(recovery.stage5.scan_adopted == 1u);
    REQUIRE(recovery.storage_recovery_complete == 1u);
    REQUIRE(recovery.publication.success_evidence_count > 0u);
    REQUIRE(recovery.publication.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_NONE);

    (void)memset(&session.empty_ws, 0, sizeof(session.empty_ws));
    (void)memset(&retry, 0, sizeof(retry));
    REQUIRE(ninlil_stage5_empty_metadata_commit(
                session.storage,
                &session.handle,
                &session.validation,
                &session.empty_ws,
                &retry)
        == NINLIL_OK);
    REQUIRE(retry.wrote_metadata == 0u);

    REQUIRE(session_destroy(&session));
    return 0;
}

static int test_commit_unknown_restart_reject(void)
{
    sqlite_session_t session;
    ninlil_v1_durable_restart_result_t recovery;

    REQUIRE(session_open(&session));
    REQUIRE(durable_submit_bootstrap(&session));
    REQUIRE(durable_submit_metadata(&session));
    REQUIRE(session_restart_provider(&session));

    (void)memset(&session.stage5_ws, 0, sizeof(session.stage5_ws));
    (void)memset(&recovery, 0, sizeof(recovery));
    REQUIRE(ninlil_v1_durable_restart_recovery(
                session.storage,
                &session.handle,
                &session.validation,
                1u,
                &session.stage5_ws,
                &recovery)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(recovery.storage_recovery_complete == 0u);
    REQUIRE(recovery.publication.success_evidence_count == 0u);
    REQUIRE(recovery.publication.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN);

    REQUIRE(session_destroy(&session));
    return 0;
}

static int test_corrupt_page_recovery_reject(void)
{
    sqlite_session_t session;
    ninlil_v1_durable_restart_result_t recovery;
    FILE *fp;

    REQUIRE(session_open(&session));
    REQUIRE(durable_submit_bootstrap(&session));
    REQUIRE(durable_submit_metadata(&session));
    session_shutdown_provider(&session);

    fp = fopen(session.path, "r+b");
    REQUIRE(fp != NULL);
    REQUIRE(fseek(fp, 16, SEEK_SET) == 0);
    {
        static const uint8_t garbage[] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        REQUIRE(fwrite(garbage, 1, sizeof(garbage), fp) == sizeof(garbage));
    }
    (void)fclose(fp);

    if (!session_restart_provider(&session)) {
        REQUIRE(session.provider == NULL);
        REQUIRE(session.handle == NULL);
        REQUIRE(session_destroy(&session));
        return 0;
    }

    (void)memset(&session.stage5_ws, 0, sizeof(session.stage5_ws));
    (void)memset(&recovery, 0, sizeof(recovery));
    REQUIRE(ninlil_v1_durable_restart_recovery(
                session.storage,
                &session.handle,
                &session.validation,
                0u,
                &session.stage5_ws,
                &recovery)
        != NINLIL_OK);
    REQUIRE(recovery.storage_recovery_complete == 0u);
    REQUIRE(recovery.publication.success_evidence_count == 0u);

    REQUIRE(session_destroy(&session));
    return 0;
}

static int raw_put(
    sqlite_session_t *session,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;

    st = session->storage->begin(
        session->storage->user,
        session->handle,
        NINLIL_STORAGE_READ_WRITE,
        &txn);
    if (st != NINLIL_STORAGE_OK) {
        return 0;
    }
    st = session->storage->put(
        session->storage->user, txn, key, value);
    if (st != NINLIL_STORAGE_OK) {
        (void)session->storage->rollback(session->storage->user, txn);
        return 0;
    }
    st = session->storage->commit(
        session->storage->user, txn, NINLIL_DURABILITY_FULL);
    return st == NINLIL_STORAGE_OK;
}

static int test_allowlist_external_injection_reject(void)
{
    sqlite_session_t session;
    ninlil_v1_durable_restart_result_t recovery;
    ninlil_v1_durable_recovery_publication_result_t pub;
    static const uint8_t future_key[] = {
        0x4e, 0x49, 0x4e, 0x4c, 0x49, 0x4c, 0x00, 0x02,
        0x06, 0x10, 0x01, 0x02, 0x10
    };
    static const uint8_t future_val[] = {0x01u, 0x02u, 0x03u, 0x04u};
    ninlil_bytes_view_t fk;
    ninlil_bytes_view_t fv;
    ninlil_status_t gate_status;

    REQUIRE(session_open(&session));
    REQUIRE(durable_submit_bootstrap(&session));
    REQUIRE(durable_submit_metadata(&session));

    fk.data = future_key;
    fk.length = (uint32_t)sizeof(future_key);
    fv.data = future_val;
    fv.length = (uint32_t)sizeof(future_val);
    REQUIRE(raw_put(&session, fk, fv));

    (void)memset(&pub, 0, sizeof(pub));
    gate_status = ninlil_v1_durable_recovery_publication_gate_storage(
        session.storage, session.handle, 0u, &pub);
    REQUIRE(gate_status != NINLIL_OK);
    REQUIRE(pub.success_evidence_count == 0u);
    REQUIRE(pub.reject_reason == NINLIL_V1_DURABLE_RECOVERY_REJECT_MIXED
        || pub.reject_reason == NINLIL_V1_DURABLE_RECOVERY_REJECT_UNKNOWN);

    (void)memset(&recovery, 0, sizeof(recovery));
    REQUIRE(ninlil_v1_durable_restart_recovery(
                session.storage,
                &session.handle,
                &session.validation,
                0u,
                &session.stage5_ws,
                &recovery)
        != NINLIL_OK);
    REQUIRE(recovery.storage_recovery_complete == 0u);
    REQUIRE(recovery.publication.success_evidence_count == 0u);

    REQUIRE(session_destroy(&session));
    return 0;
}

int main(void)
{
    if (test_normal_restart_resume_no_duplicate() != 0) {
        return 1;
    }
    if (test_commit_unknown_restart_reject() != 0) {
        return 1;
    }
    if (test_corrupt_page_recovery_reject() != 0) {
        return 1;
    }
    if (test_allowlist_external_injection_reject() != 0) {
        return 1;
    }
    (void)printf("v1_posix_sqlite_restart_e2e_test ok\n");
    return 0;
}
