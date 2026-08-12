/* SPDX-License-Identifier: Apache-2.0 */
/*
 *
 * Real POSIX SQLite cold-close/reopen acceptance for the private MFDT Host
 * coordinator.  Every reopen creates a new SQLite provider, namespace handle,
 * typed MFDT store port, and Host owner over the same database path.
 *
 * Software evidence only.  This is not physical HIL, power-cut evidence,
 * SPEC_ACCEPTED, release support, or public ABI.
 */
#include "mfdt_v1_host_coordinator.h"
#include "mfdt_v1_ncl1.h"
#include "ninlil_posix_sqlite_storage.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                       \
                "CHECK_FAIL %s:%d: %s\n",                                    \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct sqlite_mfdt_session {
    ninlil_posix_sqlite_storage_t *provider;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle;
    ninlil_mfdt_v1_store_port_t port;
} sqlite_mfdt_session_t;

typedef struct durable_row_fingerprint {
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t value_len;
    uint8_t value_digest[32];
} durable_row_fingerprint_t;

typedef struct durable_fingerprint {
    uint32_t row_count;
    durable_row_fingerprint_t rows[32];
} durable_fingerprint_t;

static const uint8_t k_storage_namespace[] =
    "mfdt.v1.host.sqlite.acceptance";
static const uint8_t k_app_namespace[] = "acceptance.sqlite";
static const uint8_t k_service[] = "binary-transfer.v1";
static const uint8_t k_schema[] = "application-data.v1";

static void make_tid(uint8_t transfer_id[16], uint8_t tag)
{
    (void)memset(transfer_id, 0, 16u);
    transfer_id[15] = tag;
}

static void make_endpoint(uint8_t endpoint[16], uint8_t tag)
{
    size_t index;

    for (index = 0u; index < 16u; ++index) {
        endpoint[index] = (uint8_t)(tag + (uint8_t)(index * 3u));
    }
}

static void make_config(ninlil_mfdt_v1_config_t *config)
{
    (void)memset(config, 0, sizeof(*config));
    config->policy = NINLIL_MFDT_V1_POLICY_ON;
    config->mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    config->host_mode = 1u;
    config->session_generation = 1u;
    config->mfdt_capability = 1u;
    config->retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    config->now_ms = 1000ull;
    (void)memset(config->local_clock_epoch.bytes, 0xc0, 16u);
}

static void make_bind(
    ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t peer_tag,
    uint8_t role,
    uint64_t cookie)
{
    (void)memset(bind, 0, sizeof(*bind));
    make_endpoint(bind->peer_endpoint_id, peer_tag);
    bind->session_generation = 1u;
    bind->session_cookie = cookie;
    bind->role = role;
}

static ninlil_mfdt_v1_store_guarantees_t exact_guarantees(void)
{
    ninlil_mfdt_v1_store_guarantees_t guarantees;

    (void)memset(&guarantees, 0, sizeof(guarantees));
    guarantees.struct_size = sizeof(guarantees);
    guarantees.flags = NINLIL_MFDT_V1_STORE_REQUIRED_FLAGS;
    guarantees.committed_keys_max =
        NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX;
    guarantees.begin_final_row_images_max =
        NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX;
    guarantees.full_ops_max = NINLIL_MFDT_V1_HOST_FULL_OPS_MAX;
    guarantees.committed_logical_bytes_max =
        NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX;
    guarantees.full_staging_logical_bytes_max =
        NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX;
    guarantees.begin_final_union_logical_bytes_max =
        NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX;
    return guarantees;
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
        out,
        out_size,
        "%s/ninlil-mfdt-host-sqlite-XXXXXX",
        tmpdir);
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

static int make_authority_lock_path(
    const char *path,
    char *out,
    size_t out_size)
{
    struct stat status;
    char *canonical;
    char *slash;
    size_t parent_length;
    int written;

    if (path == NULL || stat(path, &status) != 0) {
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
    parent_length =
        slash == canonical ? 1u : (size_t)(slash - canonical);
    written = snprintf(
        out,
        out_size,
        "%.*s/.ninlil-sqlite-%llx-%llx.lock",
        (int)parent_length,
        canonical,
        (unsigned long long)status.st_dev,
        (unsigned long long)status.st_ino);
    free(canonical);
    return written > 0 && (size_t)written < out_size;
}

static void remove_db_artifacts(const char *path)
{
    char wal[640];
    char shm[640];
    char journal[640];
    char lock_path[768];
    int have_lock;

    if (path == NULL || path[0] == '\0') {
        return;
    }
    have_lock =
        make_authority_lock_path(path, lock_path, sizeof(lock_path));
    (void)snprintf(wal, sizeof(wal), "%s-wal", path);
    (void)snprintf(shm, sizeof(shm), "%s-shm", path);
    (void)snprintf(journal, sizeof(journal), "%s-journal", path);
    (void)remove(wal);
    (void)remove(shm);
    (void)remove(journal);
    (void)remove(path);
    if (have_lock != 0) {
        (void)remove(lock_path);
    }
}

static int sqlite_session_open(
    sqlite_mfdt_session_t *session,
    const char *path)
{
    ninlil_posix_sqlite_storage_config_t sqlite_config;
    ninlil_mfdt_v1_store_guarantees_t guarantees;
    ninlil_bytes_view_t namespace_view;
    ninlil_storage_status_t status;

    if (session == NULL || path == NULL) {
        return 0;
    }
    (void)memset(session, 0, sizeof(*session));
    (void)memset(&sqlite_config, 0, sizeof(sqlite_config));
    sqlite_config.database_path = path;
    sqlite_config.busy_timeout_ms = 200u;
    sqlite_config.max_entries_per_namespace = 64u;
    sqlite_config.max_bytes_per_namespace = 600000u;
    sqlite_config.max_handles = 4u;
    sqlite_config.max_transactions = 4u;
    sqlite_config.max_iterators = 4u;
    session->provider =
        ninlil_posix_sqlite_storage_create(&sqlite_config);
    if (session->provider == NULL) {
        return 0;
    }
    session->ops =
        ninlil_posix_sqlite_storage_ops(session->provider);
    if (session->ops == NULL) {
        return 0;
    }
    namespace_view.data = k_storage_namespace;
    namespace_view.length =
        (uint32_t)(sizeof(k_storage_namespace) - 1u);
    status = session->ops->open(
        session->ops->user,
        namespace_view,
        NINLIL_STORAGE_SCHEMA_M1A,
        &session->handle);
    if (status != NINLIL_STORAGE_OK || session->handle == NULL) {
        return 0;
    }
    guarantees = exact_guarantees();
    return ninlil_mfdt_v1_store_port_init(
               &session->port,
               session->ops,
               session->handle,
               &guarantees) == NINLIL_MFDT_V1_OK;
}

static void sqlite_session_close(sqlite_mfdt_session_t *session)
{
    if (session == NULL) {
        return;
    }
    if (session->ops != NULL && session->handle != NULL) {
        session->ops->close(
            session->ops->user,
            session->handle);
    }
    if (session->provider != NULL) {
        ninlil_posix_sqlite_storage_destroy(session->provider);
    }
    (void)memset(session, 0, sizeof(*session));
}

static int durable_fingerprint(
    sqlite_mfdt_session_t *session,
    durable_fingerprint_t *fingerprint)
{
    ninlil_mfdt_v1_store_snapshot_t snapshot;
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t *value;
    uint32_t value_len;
    int snapshot_open = 0;
    int done = 0;
    int ok = 0;
    int rc;

    if (session == NULL || fingerprint == NULL) {
        return 0;
    }
    (void)memset(fingerprint, 0, sizeof(*fingerprint));
    (void)memset(&snapshot, 0, sizeof(snapshot));
    value = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    if (value == NULL) {
        return 0;
    }
    rc = ninlil_mfdt_v1_store_snapshot_begin(
        &session->port,
        (const uint8_t *)"N",
        1u,
        &snapshot);
    if (rc != NINLIL_MFDT_V1_OK) {
        goto cleanup;
    }
    snapshot_open = 1;
    while (done == 0) {
        if (fingerprint->row_count >=
            (uint32_t)(sizeof(fingerprint->rows) /
                       sizeof(fingerprint->rows[0]))) {
            goto cleanup;
        }
        rc = ninlil_mfdt_v1_store_snapshot_next(
            &snapshot,
            key,
            value,
            NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
            &value_len,
            &done);
        if (rc != NINLIL_MFDT_V1_OK) {
            goto cleanup;
        }
        if (done == 0) {
            durable_row_fingerprint_t *row =
                &fingerprint->rows[fingerprint->row_count];

            (void)memcpy(row->key, key, sizeof(row->key));
            row->value_len = value_len;
            ninlil_mfdt_v1_sha256(
                value,
                value_len,
                row->value_digest);
            ++fingerprint->row_count;
        }
    }
    ok = 1;

cleanup:
    if (snapshot_open != 0 &&
        ninlil_mfdt_v1_store_snapshot_end(&snapshot) !=
            NINLIL_MFDT_V1_OK) {
        ok = 0;
    }
    free(value);
    if (ok == 0) {
        (void)memset(fingerprint, 0, sizeof(*fingerprint));
    }
    return ok;
}

static void make_metadata(
    ninlil_mfdt_v1_open_metadata_t *metadata,
    const ninlil_mfdt_v1_config_t *config,
    const uint8_t source_runtime_id[16],
    const uint8_t target_runtime_id[16],
    uint8_t tag)
{
    size_t index;

    (void)memset(metadata, 0, sizeof(*metadata));
    for (index = 0u; index < 16u; ++index) {
        metadata->origin_transaction_id[index] =
            (uint8_t)(tag + (uint8_t)index);
        metadata->original_attempt_id[index] =
            (uint8_t)(0x30u + tag + (uint8_t)index);
        metadata->source_application_instance_id[index] =
            (uint8_t)(0x50u + tag + (uint8_t)index);
        metadata->target_application_instance_id[index] =
            (uint8_t)(0x70u + tag + (uint8_t)index);
    }
    (void)memcpy(
        metadata->source_runtime_id,
        source_runtime_id,
        16u);
    (void)memcpy(
        metadata->target_runtime_id,
        target_runtime_id,
        16u);
    metadata->service_descriptor_revision = (uint64_t)tag + 1ull;
    ninlil_mfdt_v1_sha256(
        k_service,
        sizeof(k_service) - 1u,
        metadata->service_descriptor_digest);
    metadata->namespace_bytes = k_app_namespace;
    metadata->namespace_length =
        (uint16_t)(sizeof(k_app_namespace) - 1u);
    metadata->service_bytes = k_service;
    metadata->service_length =
        (uint16_t)(sizeof(k_service) - 1u);
    metadata->schema_bytes = k_schema;
    metadata->schema_length =
        (uint16_t)(sizeof(k_schema) - 1u);
    (void)memcpy(
        metadata->deadline_clock_epoch_id,
        config->local_clock_epoch.bytes,
        16u);
    metadata->absolute_effect_deadline_ms =
        config->now_ms + 600000ull;
    metadata->service_schema_major = 1u;
    metadata->service_family = 2u;
    metadata->application_generation = (uint64_t)tag + 1ull;
    metadata->required_evidence = 1u;
}

static int sender_open(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_config_t *config,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t tid_tag,
    uint64_t request_id,
    uint8_t *slot_out)
{
    ninlil_mfdt_v1_open_metadata_t metadata;
    uint8_t transfer_id[16];
    uint8_t local_runtime[16];
    uint8_t content[64];

    make_tid(transfer_id, tid_tag);
    make_endpoint(local_runtime, 0xe0u);
    (void)memset(content, tid_tag, sizeof(content));
    make_metadata(
        &metadata,
        config,
        local_runtime,
        bind->peer_endpoint_id,
        tid_tag);
    return ninlil_mfdt_v1_host_sender_open_with_metadata(
        owner,
        bind,
        transfer_id,
        content,
        sizeof(content),
        &metadata,
        request_id,
        slot_out);
}

static int build_open(
    const ninlil_mfdt_v1_config_t *config,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t tid_tag,
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint16_t *open_len)
{
    uint8_t transfer_id[16];
    uint8_t target[16];
    ninlil_mfdt_v1_open_metadata_t metadata;
    uint8_t entries[
        NINLIL_MFDT_V1_MAX_CHUNKS *
        NINLIL_MFDT_V1_ENTRY_BYTES];
    uint8_t manifest_digest[32];
    uint8_t whole_digest[32];
    uint8_t content = tid_tag;
    uint16_t entry_bytes = 0u;

    make_tid(transfer_id, tid_tag);
    make_endpoint(target, 0xf0u);
    (void)memset(&metadata, 0, sizeof(metadata));
    (void)memset(metadata.origin_transaction_id, tid_tag, 16u);
    (void)memcpy(metadata.source_runtime_id, bind->peer_endpoint_id, 16u);
    (void)memcpy(metadata.target_runtime_id, target, 16u);
    (void)memset(metadata.original_attempt_id,
                 (uint8_t)(tid_tag + 2u), 16u);
    (void)memset(metadata.source_application_instance_id,
                 (uint8_t)(tid_tag + 3u), 16u);
    (void)memset(metadata.target_application_instance_id,
                 (uint8_t)(tid_tag + 4u), 16u);
    ninlil_mfdt_v1_sha256(
        k_service,
        sizeof(k_service) - 1u,
        metadata.service_descriptor_digest);
    metadata.service_descriptor_revision = 1ull;
    (void)memcpy(metadata.deadline_clock_epoch_id,
                 config->local_clock_epoch.bytes, 16u);
    metadata.absolute_effect_deadline_ms = config->now_ms + 600000ull;
    metadata.service_schema_major = 1u;
    metadata.service_family = 2u;
    metadata.application_generation = 1ull;
    metadata.required_evidence = 1u;
    metadata.namespace_bytes = k_app_namespace;
    metadata.namespace_length =
        (uint16_t)(sizeof(k_app_namespace) - 1u);
    metadata.service_bytes = k_service;
    metadata.service_length = (uint16_t)(sizeof(k_service) - 1u);
    metadata.schema_bytes = k_schema;
    metadata.schema_length = (uint16_t)(sizeof(k_schema) - 1u);
    return ninlil_mfdt_v1_encode_open(
        transfer_id, 1u, &content, &metadata, open, open_len, entries,
        &entry_bytes, manifest_digest, whole_digest);
}

static int drain_outbound(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot)
{
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t frame_len = 0u;
    int rc = ninlil_mfdt_v1_host_take_outbound_ncl1(
        owner,
        slot,
        frame,
        sizeof(frame),
        &frame_len);

    return rc == NINLIL_MFDT_V1_OK && frame_len != 0u
               ? NINLIL_MFDT_V1_OK
               : (rc != NINLIL_MFDT_V1_OK
                      ? rc : NINLIL_MFDT_V1_ERR_STATE);
}

static int receiver_open(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_config_t *config,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t tid_tag,
    uint64_t request_id,
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint16_t *open_len,
    uint8_t *slot_out,
    ninlil_mfdt_v1_response_t *response)
{
    ninlil_mfdt_v1_wire_view_t wire;
    int rc = build_open(
        config,
        bind,
        tid_tag,
        open,
        open_len);

    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = request_id;
    wire.body = open;
    wire.body_len = *open_len;
    return ninlil_mfdt_v1_host_on_wire(
        owner,
        bind,
        &wire,
        response,
        slot_out);
}

static int receiver_abort(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t slot,
    const uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint64_t request_id)
{
    uint8_t abort_body[76];
    ninlil_mfdt_v1_wire_view_t wire;
    ninlil_mfdt_v1_response_t response;
    uint8_t routed_slot = 0xffu;
    int rc;

    (void)memset(abort_body, 0, sizeof(abort_body));
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        abort_body);
    ninlil_mfdt_v1_put_u16(
        abort_body + 52u,
        NINLIL_MFDT_V1_TERM_REASON_OPERATOR);
    abort_body[56] = 0xabu;
    ninlil_mfdt_v1_put_u32(abort_body + 72u, 1u);
    wire.message_type = NINLIL_MFDT_V1_MSG_ABORT;
    wire.request_id = request_id;
    wire.body = abort_body;
    wire.body_len = sizeof(abort_body);
    rc = ninlil_mfdt_v1_host_on_wire(
        owner,
        bind,
        &wire,
        &response,
        &routed_slot);
    if (rc != NINLIL_MFDT_V1_OK || routed_slot != slot ||
        response.message_type != NINLIL_MFDT_V1_MSG_ABORT_ACK) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_STATE;
    }
    return drain_outbound(owner, slot);
}

static int test_sqlite_cold_reopen(void)
{
    char path[512];
    sqlite_mfdt_session_t session;
    ninlil_mfdt_v1_config_t config;
    ninlil_mfdt_v1_host_owner_t *owner = NULL;
    ninlil_mfdt_v1_host_owner_t *owner_before = NULL;
    ninlil_mfdt_v1_host_owner_t *cold_owner = NULL;
    ninlil_mfdt_v1_host_bind_t terminal_bind;
    ninlil_mfdt_v1_host_bind_t active_receiver_bind;
    ninlil_mfdt_v1_host_bind_t sender_binds[4];
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_response_t terminal_open_accept;
    ninlil_mfdt_v1_response_t active_open_accept;
    ninlil_mfdt_v1_wire_view_t wire;
    durable_fingerprint_t durable_before;
    durable_fingerprint_t durable_after;
    uint8_t terminal_open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t active_open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t terminal_open_len = 0u;
    uint16_t active_open_len = 0u;
    uint8_t terminal_slot = 0xffu;
    uint8_t active_receiver_slot = 0xffu;
    uint8_t sender_slot = 0xffu;
    uint8_t transfer_id[16];
    uint8_t terminal_record[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t slot_index;
    uint8_t *record = NULL;
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t record_len = 0u;
    int present = 0;
    uint32_t committed_keys;
    uint64_t committed_bytes;

    CHECK(make_temp_path(path, sizeof(path)));
    make_config(&config);
    CHECK(sqlite_session_open(&session, path));
    owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*owner));
    CHECK(owner != NULL);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              owner,
              &session.port,
              &config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(owner) ==
          NINLIL_MFDT_V1_OK);

    make_bind(
        &terminal_bind,
        0x71u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x710001ull);
    CHECK(receiver_open(
              owner,
              &config,
              &terminal_bind,
              1u,
              101u,
              terminal_open,
              &terminal_open_len,
              &terminal_slot,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT);
    terminal_open_accept = response;
    CHECK(drain_outbound(owner, terminal_slot) ==
          NINLIL_MFDT_V1_OK);
    CHECK(receiver_abort(
              owner,
              &terminal_bind,
              terminal_slot,
              terminal_open,
              201u) == NINLIL_MFDT_V1_OK);

    make_bind(
        &active_receiver_bind,
        0x72u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x720002ull);
    CHECK(receiver_open(
              owner,
              &config,
              &active_receiver_bind,
              2u,
              102u,
              active_open,
              &active_open_len,
              &active_receiver_slot,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(active_receiver_slot == 0u);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT);
    active_open_accept = response;
    CHECK(drain_outbound(owner, active_receiver_slot) ==
          NINLIL_MFDT_V1_OK);

    for (slot_index = 0u; slot_index < 4u; ++slot_index) {
        make_bind(
            &sender_binds[slot_index],
            (uint8_t)(0x80u + slot_index),
            NINLIL_MFDT_V1_HOST_ROLE_SENDER,
            0x800000ull + slot_index);
    }
    for (slot_index = 0u; slot_index < 3u; ++slot_index) {
        sender_slot = 0xffu;
        CHECK(sender_open(
                  owner,
                  &config,
                  &sender_binds[slot_index],
                  (uint8_t)(3u + slot_index),
                  (uint64_t)(103u + slot_index),
                  &sender_slot) == NINLIL_MFDT_V1_OK);
        CHECK(sender_slot == (uint8_t)(slot_index + 1u));
    }
    CHECK(durable_fingerprint(&session, &durable_before));
    owner_before = (ninlil_mfdt_v1_host_owner_t *)malloc(
        sizeof(*owner_before));
    CHECK(owner_before != NULL);
    (void)memcpy(owner_before, owner, sizeof(*owner_before));
    sender_slot = 0xaau;
    CHECK(sender_open(
              owner,
              &config,
              &sender_binds[3],
              6u,
              106u,
              &sender_slot) == NINLIL_MFDT_V1_ERR_CAPACITY);
    CHECK(sender_slot == 0xaau);
    CHECK(memcmp(owner, owner_before, sizeof(*owner)) == 0);
    free(owner_before);
    owner_before = NULL;
    CHECK(durable_fingerprint(&session, &durable_after));
    CHECK(memcmp(
              &durable_before,
              &durable_after,
              sizeof(durable_before)) == 0);
    CHECK(ninlil_mfdt_v1_host_snapshot(
              owner,
              &header,
              slots) == NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 4u);
    CHECK(header.tracked_groups == 5u);
    CHECK(header.committed_keys == 10u);
    committed_keys = header.committed_keys;
    committed_bytes = header.committed_logical_bytes;
    (void)printf("WITNESS_PASS sqlite_four_slot_fifth_ceiling\n");

    free(owner);
    owner = NULL;
    sqlite_session_close(&session);
    CHECK(sqlite_session_open(&session, path));
    cold_owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*cold_owner));
    CHECK(cold_owner != NULL);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              cold_owner,
              &session.port,
              &config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_snapshot(
              cold_owner,
              &header,
              slots) == NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 4u);
    CHECK(header.tracked_groups == 5u);
    CHECK(header.committed_keys == 10u);
    for (slot_index = 0u; slot_index < 4u; ++slot_index) {
        CHECK(slots[slot_index].occupied == 1u);
        CHECK(slots[slot_index].bind_valid == 0u);
        CHECK(slots[slot_index].transfer_id[15] ==
              (uint8_t)(slot_index + 2u));
    }
    make_tid(transfer_id, 1u);
    (void)memcpy(key, "NM30", 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &session.port,
              key,
              terminal_record,
              sizeof(terminal_record),
              &record_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(record_len == NINLIL_MFDT_V1_NM30_BYTES);
    CHECK(ninlil_mfdt_v1_validate_nm30_record(
              terminal_record,
              record_len,
              transfer_id) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_rebind_recovered(
              cold_owner,
              transfer_id,
              &terminal_bind) == NINLIL_MFDT_V1_OK);
    CHECK(durable_fingerprint(&session, &durable_before));
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 101u;
    wire.body = terminal_open;
    wire.body_len = terminal_open_len;
    terminal_slot = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              cold_owner,
              &terminal_bind,
              &wire,
              &response,
              &terminal_slot) == NINLIL_MFDT_V1_OK);
    CHECK(terminal_slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE);
    CHECK(response.message_type == terminal_open_accept.message_type);
    CHECK(response.body_len == terminal_open_accept.body_len);
    CHECK(response.reject_code == terminal_open_accept.reject_code);
    CHECK(memcmp(
              response.body,
              terminal_open_accept.body,
              response.body_len) == 0);
    CHECK(response.from_nrc1_hit == 1u);
    CHECK(response.state_mutation == 0u);
    CHECK(response.full_count == 0u);
    CHECK(durable_fingerprint(&session, &durable_after));
    CHECK(memcmp(
              &durable_before,
              &durable_after,
              sizeof(durable_before)) == 0);
    CHECK(drain_outbound(
              cold_owner,
              NINLIL_MFDT_V1_HOST_CONTROL_ROUTE) ==
          NINLIL_MFDT_V1_OK);
    (void)printf("WITNESS_PASS sqlite_terminal_nrc1_cold_replay\n");
    CHECK(ninlil_mfdt_v1_host_rebind_recovered(
              cold_owner,
              slots[0].transfer_id,
              &active_receiver_bind) == NINLIL_MFDT_V1_OK);
    (void)printf("WITNESS_PASS sqlite_active_terminal_cold_reopen\n");

    CHECK(durable_fingerprint(&session, &durable_before));
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 102u;
    wire.body = active_open;
    wire.body_len = active_open_len;
    active_receiver_slot = 0xffu;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              cold_owner,
              &active_receiver_bind,
              &wire,
              &response,
              &active_receiver_slot) == NINLIL_MFDT_V1_OK);
    CHECK(active_receiver_slot == 0u);
    CHECK(response.message_type == active_open_accept.message_type);
    CHECK(response.body_len == active_open_accept.body_len);
    CHECK(memcmp(
              response.body,
              active_open_accept.body,
              response.body_len) == 0);
    CHECK(response.from_nrc1_hit == 1u);
    CHECK(response.state_mutation == 0u);
    CHECK(response.full_count == 0u);
    CHECK(durable_fingerprint(&session, &durable_after));
    CHECK(memcmp(
              &durable_before,
              &durable_after,
              sizeof(durable_before)) == 0);
    CHECK(drain_outbound(cold_owner, active_receiver_slot) ==
          NINLIL_MFDT_V1_OK);
    CHECK(receiver_abort(
              cold_owner,
              &active_receiver_bind,
              active_receiver_slot,
              active_open,
              202u) == NINLIL_MFDT_V1_OK);

    CHECK(ninlil_mfdt_v1_host_snapshot(
              cold_owner,
              &header,
              slots) == NINLIL_MFDT_V1_OK);
    CHECK(slots[0].occupied == 0u);
    (void)printf("WITNESS_PASS sqlite_active_nrc1_replay\n");

    committed_keys = header.committed_keys;
    committed_bytes = header.committed_logical_bytes;
    free(cold_owner);
    cold_owner = NULL;
    sqlite_session_close(&session);

    /*
     * Corrupt one active row through the same typed port, close the provider,
     * then prove a fourth independent process image publishes no partial
     * recovery state.
     */
    CHECK(sqlite_session_open(&session, path));
    record = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    CHECK(record != NULL);
    make_tid(transfer_id, 3u);
    (void)memcpy(key, "NM3S", 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &session.port,
              key,
              record,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &record_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1 && record_len >= 312u);
    record[record_len - 1u] ^= 0xffu;
    CHECK(ninlil_mfdt_v1_store_full_begin(
              &session.port,
              committed_keys,
              committed_bytes) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_store_full_put(
              &session.port,
              key,
              record,
              record_len) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_store_full_commit(&session.port) ==
          NINLIL_MFDT_V1_OK);
    free(record);
    record = NULL;
    sqlite_session_close(&session);

    CHECK(sqlite_session_open(&session, path));
    cold_owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*cold_owner));
    CHECK(cold_owner != NULL);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              cold_owner,
              &session.port,
              &config) == NINLIL_MFDT_V1_OK);
    CHECK(durable_fingerprint(&session, &durable_before));
    CHECK(ninlil_mfdt_v1_host_owner_recover(cold_owner) ==
          NINLIL_MFDT_V1_ERR_CORRUPT);
    CHECK(durable_fingerprint(&session, &durable_after));
    CHECK(memcmp(
              &durable_before,
              &durable_after,
              sizeof(durable_before)) == 0);
    CHECK(ninlil_mfdt_v1_host_snapshot(
              cold_owner,
              &header,
              slots) == NINLIL_MFDT_V1_OK);
    CHECK(header.recovered == 0u);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 0u);
    for (slot_index = 0u; slot_index < 4u; ++slot_index) {
        CHECK(slots[slot_index].occupied == 0u);
    }
    (void)printf("WITNESS_PASS sqlite_corrupt_cold_reopen_fail_closed\n");

    free(cold_owner);
    sqlite_session_close(&session);
    remove_db_artifacts(path);
    return 0;
}

static int test_sqlite_schema1_legacy_deny(void)
{
    char path[512];
    sqlite_mfdt_session_t session;
    ninlil_mfdt_v1_config_t config;
    ninlil_mfdt_v1_host_owner_t *owner;
    ninlil_mfdt_v1_host_owner_t *cold_owner;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_wire_view_t wire;
    durable_fingerprint_t durable_before;
    durable_fingerprint_t durable_after;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t transfer_id[16];
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t schema2[NINLIL_MFDT_V1_NM30_BYTES];
    uint8_t schema1[NINLIL_MFDT_V1_NM30_SCHEMA1_BYTES];
    uint8_t recovered_peer[16];
    uint16_t open_len = 0u;
    uint8_t slot = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    uint8_t replay_eligible = 0xffu;
    uint8_t recovered_role = 0xffu;
    uint32_t record_len = 0u;
    int present = 0;

    CHECK(make_temp_path(path, sizeof(path)));
    make_config(&config);
    CHECK(sqlite_session_open(&session, path));
    owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*owner));
    CHECK(owner != NULL);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              owner,
              &session.port,
              &config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(owner) ==
          NINLIL_MFDT_V1_OK);
    make_bind(
        &bind,
        0xc1u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xc10001ull);
    CHECK(receiver_open(
              owner,
              &config,
              &bind,
              21u,
              2101u,
              open,
              &open_len,
              &slot,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(drain_outbound(owner, slot) == NINLIL_MFDT_V1_OK);
    CHECK(receiver_abort(
              owner,
              &bind,
              slot,
              open,
              2102u) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_snapshot(
              owner,
              &header,
              slots) == NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 1u);
    CHECK(header.committed_keys == 2u);
    free(owner);
    sqlite_session_close(&session);

    CHECK(sqlite_session_open(&session, path));
    make_tid(transfer_id, 21u);
    (void)memcpy(key, "NM30", 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &session.port,
              key,
              schema2,
              sizeof(schema2),
              &record_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(record_len == NINLIL_MFDT_V1_NM30_BYTES);
    (void)memcpy(schema1, schema2, 156u);
    ninlil_mfdt_v1_put_u16(schema1 + 4u, 1u);
    ninlil_mfdt_v1_put_u16(
        schema1 + 6u,
        NINLIL_MFDT_V1_NM30_SCHEMA1_BYTES);
    ninlil_mfdt_v1_put_u32(schema1 + 156u, 0u);
    ninlil_mfdt_v1_put_u32(
        schema1 + 160u,
        ninlil_mfdt_v1_crc32c(schema1, 160u));
    (void)memset(recovered_peer, 0xa5, sizeof(recovered_peer));
    CHECK(ninlil_mfdt_v1_validate_nm30_recovery_record(
              schema1,
              sizeof(schema1),
              transfer_id,
              &replay_eligible,
              recovered_peer,
              &recovered_role) == NINLIL_MFDT_V1_OK);
    CHECK(replay_eligible == 0u);
    CHECK(recovered_role == 0u);
    CHECK(memcmp(
              recovered_peer,
              (const uint8_t[16]){0},
              sizeof(recovered_peer)) == 0);
    CHECK(ninlil_mfdt_v1_store_full_begin(
              &session.port,
              header.committed_keys,
              header.committed_logical_bytes) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_store_full_put(
              &session.port,
              key,
              schema1,
              sizeof(schema1)) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_store_full_commit(&session.port) ==
          NINLIL_MFDT_V1_OK);
    sqlite_session_close(&session);

    CHECK(sqlite_session_open(&session, path));
    cold_owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*cold_owner));
    CHECK(cold_owner != NULL);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              cold_owner,
              &session.port,
              &config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_snapshot(
              cold_owner,
              &header,
              slots) == NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 1u);
    CHECK(header.committed_keys == 2u);
    CHECK(header.terminal_count == 1u);
    CHECK(durable_fingerprint(&session, &durable_before));
    CHECK(ninlil_mfdt_v1_host_rebind_recovered(
              cold_owner,
              transfer_id,
              &bind) == NINLIL_MFDT_V1_ERR_VERSION);
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 2101u;
    wire.body = open;
    wire.body_len = open_len;
    (void)memset(&response, 0xa5, sizeof(response));
    slot = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              cold_owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_ERR_VERSION);
    CHECK(slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE);
    CHECK(response.message_type == 0u);
    CHECK(response.body_len == 0u);
    CHECK(durable_fingerprint(&session, &durable_after));
    CHECK(memcmp(
              &durable_before,
              &durable_after,
              sizeof(durable_before)) == 0);
    CHECK(ninlil_mfdt_v1_host_gc(
              cold_owner,
              config.now_ms + config.retention_ms + 1ull) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_snapshot(
              cold_owner,
              &header,
              slots) == NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 0u);
    CHECK(header.committed_keys == 0u);
    CHECK(header.terminal_count == 0u);
    (void)printf(
        "WITNESS_PASS "
        "sqlite_schema1_accounting_rebind_wire_deny_gc\n");

    free(cold_owner);
    sqlite_session_close(&session);
    remove_db_artifacts(path);
    return 0;
}

int main(void)
{
    if (test_sqlite_cold_reopen() != 0) {
        (void)fprintf(
            stderr,
            "mfdt_v1_host_sqlite_restart_test FAILED\n");
        return 1;
    }
    if (test_sqlite_schema1_legacy_deny() != 0) {
        (void)fprintf(
            stderr,
            "mfdt_v1_host_sqlite_restart_test FAILED\n");
        return 1;
    }
    (void)printf("mfdt_v1_host_sqlite_restart_test OK\n");
    return 0;
}
