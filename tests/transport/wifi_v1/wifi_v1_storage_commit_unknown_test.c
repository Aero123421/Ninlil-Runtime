/*
 * Wi-Fi durable-state COMMIT_UNKNOWN oracle.
 *
 * Every FULL write closes the uncertain handle, performs a fresh reopen, and
 * reports INTENDED / OLD / ABSENT / OTHER without promoting the original
 * COMMIT_UNKNOWN to success. Crash/restart checks use only committed storage.
 */
#include "wifi_attachment_m4.h"
#include "wifi_credentials.h"
#include "wifi_journal.h"
#include "wifi_session.h"
#include "wifi_storage_cu.h"

#include "in_memory_storage.h"

#include <ninlil/version.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__);          \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

typedef struct wrapped_storage {
    ninlil_test_storage_t *owner;
    const ninlil_storage_ops_t *base;
    ninlil_storage_ops_t ops;
    uint32_t commit_calls;
    uint32_t fault_commit_number;
    int fault_committed_truth;
    int inject_other;
    int inject_other_pending;
    const char *other_namespace;
    const char *other_key;
    uint8_t other_value[NINLIL_WIFI_STORAGE_CU_VALUE_MAX];
    uint32_t other_length;
} wrapped_storage_t;

static ninlil_bytes_view_t view(const void *data, uint32_t length)
{
    ninlil_bytes_view_t result;
    result.data = (const uint8_t *)data;
    result.length = length;
    return result;
}

static ninlil_storage_status_t raw_put_full(
    wrapped_storage_t *wrapped,
    const char *storage_namespace,
    const char *key,
    const uint8_t *value,
    uint32_t value_length)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t status;
    status = wrapped->base->open(
        wrapped->base->user,
        view(storage_namespace, (uint32_t)strlen(storage_namespace)),
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    status = wrapped->base->begin(
        wrapped->base->user,
        handle,
        NINLIL_STORAGE_READ_WRITE,
        &transaction);
    if (status != NINLIL_STORAGE_OK) {
        wrapped->base->close(wrapped->base->user, handle);
        return status;
    }
    status = wrapped->base->put(
        wrapped->base->user,
        transaction,
        view(key, (uint32_t)strlen(key)),
        view(value, value_length));
    if (status != NINLIL_STORAGE_OK) {
        if (wrapped->base->rollback != NULL) {
            (void)wrapped->base->rollback(
                wrapped->base->user, transaction);
        }
        wrapped->base->close(wrapped->base->user, handle);
        return status;
    }
    status = wrapped->base->commit(
        wrapped->base->user, transaction, NINLIL_DURABILITY_FULL);
    wrapped->base->close(wrapped->base->user, handle);
    return status;
}

static ninlil_storage_status_t wrap_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    wrapped_storage_t *wrapped = (wrapped_storage_t *)user;
    return wrapped->base->open(
        wrapped->base->user,
        storage_namespace,
        expected_schema,
        out_handle);
}

static void wrap_close(void *user, ninlil_storage_handle_t handle)
{
    wrapped_storage_t *wrapped = (wrapped_storage_t *)user;
    wrapped->base->close(wrapped->base->user, handle);
    if (wrapped->inject_other_pending != 0) {
        wrapped->inject_other_pending = 0;
        CHECK(raw_put_full(
                  wrapped,
                  wrapped->other_namespace,
                  wrapped->other_key,
                  wrapped->other_value,
                  wrapped->other_length)
            == NINLIL_STORAGE_OK);
    }
}

static ninlil_storage_status_t wrap_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_transaction)
{
    wrapped_storage_t *wrapped = (wrapped_storage_t *)user;
    return wrapped->base->begin(
        wrapped->base->user, handle, mode, out_transaction);
}

static ninlil_storage_status_t wrap_get(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    wrapped_storage_t *wrapped = (wrapped_storage_t *)user;
    return wrapped->base->get(
        wrapped->base->user, transaction, key, inout_value);
}

static ninlil_storage_status_t wrap_put(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    wrapped_storage_t *wrapped = (wrapped_storage_t *)user;
    return wrapped->base->put(
        wrapped->base->user, transaction, key, value);
}

static ninlil_storage_status_t wrap_commit(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_durability_t durability)
{
    wrapped_storage_t *wrapped = (wrapped_storage_t *)user;
    ninlil_storage_status_t status;
    wrapped->commit_calls += 1u;
    if (wrapped->fault_commit_number != 0u
        && wrapped->commit_calls == wrapped->fault_commit_number) {
        CHECK(ninlil_test_storage_fault_enqueue(
            wrapped->owner,
            NINLIL_TEST_STORAGE_OP_COMMIT,
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            1u,
            1,
            wrapped->fault_committed_truth));
    }
    status = wrapped->base->commit(
        wrapped->base->user, transaction, durability);
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN
        && wrapped->inject_other != 0) {
        wrapped->inject_other = 0;
        /*
         * The production helper must close the uncertain handle before
         * reconciliation. Inject the third durable image from wrap_close so
         * this oracle also proves that ordering.
         */
        wrapped->inject_other_pending = 1;
    }
    return status;
}

static ninlil_storage_status_t wrap_rollback(
    void *user, ninlil_storage_txn_t transaction)
{
    wrapped_storage_t *wrapped = (wrapped_storage_t *)user;
    return wrapped->base->rollback(
        wrapped->base->user, transaction);
}

static void wrapped_init(
    wrapped_storage_t *wrapped,
    ninlil_test_storage_t *owner)
{
    (void)memset(wrapped, 0, sizeof(*wrapped));
    wrapped->owner = owner;
    wrapped->base = ninlil_test_storage_ops(owner);
    wrapped->ops.abi_version = NINLIL_ABI_VERSION;
    wrapped->ops.struct_size = (uint16_t)sizeof(wrapped->ops);
    wrapped->ops.user = wrapped;
    wrapped->ops.open = wrap_open;
    wrapped->ops.close = wrap_close;
    wrapped->ops.begin = wrap_begin;
    wrapped->ops.get = wrap_get;
    wrapped->ops.put = wrap_put;
    wrapped->ops.commit = wrap_commit;
    wrapped->ops.rollback = wrap_rollback;
}

static ninlil_test_storage_t *new_storage(void)
{
    ninlil_test_storage_config_t config;
    (void)memset(&config, 0, sizeof(config));
    config.max_namespaces = 8u;
    config.max_entries_per_namespace = 32u;
    config.max_bytes_per_namespace = 65536u;
    return ninlil_test_storage_create(&config);
}

static void check_storage_clean(ninlil_test_storage_t *storage)
{
    CHECK(ninlil_test_storage_live_handles(storage) == 0u);
    CHECK(ninlil_test_storage_live_transactions(storage) == 0u);
    CHECK(ninlil_test_storage_live_iterators(storage) == 0u);
}

static void arm_commit_unknown(
    wrapped_storage_t *wrapped,
    int committed_truth,
    int inject_other,
    const char *storage_namespace,
    const char *key)
{
    wrapped->fault_commit_number = wrapped->commit_calls + 1u;
    wrapped->fault_committed_truth = committed_truth;
    wrapped->inject_other = inject_other;
    wrapped->other_namespace = storage_namespace;
    wrapped->other_key = key;
    wrapped->other_length = NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES;
    (void)memset(
        wrapped->other_value, 0xc7, sizeof(wrapped->other_value));
}

static void run_journal_case(
    ninlil_wifi_cu_class_t expected_class,
    int seed_old,
    int committed_truth,
    int inject_other)
{
    static const char storage_namespace[] = "wifi.cu.journal";
    ninlil_test_storage_t *storage = new_storage();
    wrapped_storage_t wrapped;
    ninlil_wifi_journal_t journal;
    ninlil_wifi_journal_t cold;
    ninlil_wifi_journal_attempt_t old_attempt;
    ninlil_wifi_journal_attempt_t intended;
    ninlil_wifi_journal_attempt_t recovered;
    ninlil_wifi_status_t status;

    CHECK(storage != NULL);
    wrapped_init(&wrapped, storage);
    ninlil_wifi_journal_init(&journal);
    CHECK(ninlil_wifi_journal_open(
              &journal, &wrapped.ops, wrapped.ops.user, storage_namespace)
        == NINLIL_WIFI_OK);
    (void)memset(&old_attempt, 0, sizeof(old_attempt));
    old_attempt.attempt_id = 11u;
    old_attempt.phase = (uint8_t)NINLIL_WIFI_PHASE_CONNECTING;
    old_attempt.write_point = 0u;
    if (seed_old != 0) {
        CHECK(ninlil_wifi_journal_put_attempt(&journal, &old_attempt)
            == NINLIL_WIFI_OK);
    }
    (void)memset(&intended, 0, sizeof(intended));
    intended.attempt_id = 22u;
    intended.generation = 3u;
    intended.phase = (uint8_t)NINLIL_WIFI_PHASE_ATTACHED;
    intended.write_point = 3u;
    intended.session_id[0] = 0xa5u;
    arm_commit_unknown(
        &wrapped,
        committed_truth,
        inject_other,
        storage_namespace,
        NINLIL_WIFI_JOURNAL_KEY_ATTEMPT);
    status = ninlil_wifi_journal_put_attempt(&journal, &intended);
    CHECK(status == NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN);
    CHECK(ninlil_wifi_journal_last_commit_unknown_class(&journal)
        == expected_class);
    check_storage_clean(storage);

    ninlil_test_storage_simulate_crash(storage);
    ninlil_wifi_journal_close(&journal);
    ninlil_wifi_journal_init(&cold);
    CHECK(ninlil_wifi_journal_open(
              &cold, &wrapped.ops, wrapped.ops.user, storage_namespace)
        == NINLIL_WIFI_OK);
    (void)memset(&recovered, 0, sizeof(recovered));
    status = ninlil_wifi_journal_recover(&cold, &recovered);
    if (expected_class == NINLIL_WIFI_CU_INTENDED) {
        CHECK(status == NINLIL_WIFI_OK);
        CHECK(recovered.attempt_id == 22u);
        CHECK(recovered.write_point == 3u);
    } else if (expected_class == NINLIL_WIFI_CU_OLD) {
        CHECK(status == NINLIL_WIFI_OK);
        CHECK(recovered.attempt_id == 11u);
        CHECK(recovered.write_point == 0u);
    } else if (expected_class == NINLIL_WIFI_CU_ABSENT) {
        CHECK(status == NINLIL_WIFI_UNAVAILABLE);
    } else {
        CHECK(status == NINLIL_WIFI_CORRUPT);
    }
    ninlil_wifi_journal_close(&cold);
    check_storage_clean(storage);
    ninlil_test_storage_destroy(storage);
}

static void credential_set(
    ninlil_wifi_credential_store_t *store,
    uint8_t tag,
    uint64_t revision)
{
    uint8_t digest[32];
    (void)memset(digest, tag, sizeof(digest));
    CHECK(ninlil_wifi_credential_stage(store, digest, revision)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_credential_activate(store) == NINLIL_WIFI_OK);
}

static void run_credential_case(
    ninlil_wifi_cu_class_t expected_class,
    int seed_old,
    int committed_truth,
    int inject_other)
{
    static const char storage_namespace[] = "wifi.cu.credential";
    ninlil_test_storage_t *storage = new_storage();
    wrapped_storage_t wrapped;
    ninlil_wifi_credential_store_t store;
    ninlil_wifi_credential_store_t cold;
    ninlil_wifi_status_t status;

    CHECK(storage != NULL);
    wrapped_init(&wrapped, storage);
    ninlil_wifi_credential_store_init(&store);
    CHECK(ninlil_wifi_credential_bind_storage(
              &store, &wrapped.ops, wrapped.ops.user, storage_namespace)
        == NINLIL_WIFI_OK);
    if (seed_old != 0) {
        credential_set(&store, 0x11u, 1u);
        CHECK(ninlil_wifi_credential_durable_put_full(&store)
            == NINLIL_WIFI_OK);
    }
    credential_set(&store, 0x22u, 2u);
    arm_commit_unknown(
        &wrapped,
        committed_truth,
        inject_other,
        storage_namespace,
        NINLIL_WIFI_NWD1_KEY_COMMITTED);
    status = ninlil_wifi_credential_durable_put_full(&store);
    CHECK(status == NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN);
    CHECK(ninlil_wifi_credential_last_commit_unknown_class(&store)
        == expected_class);
    check_storage_clean(storage);

    ninlil_test_storage_simulate_crash(storage);
    ninlil_wifi_credential_store_init(&cold);
    CHECK(ninlil_wifi_credential_bind_storage(
              &cold, &wrapped.ops, wrapped.ops.user, storage_namespace)
        == NINLIL_WIFI_OK);
    status = ninlil_wifi_credential_durable_reopen(&cold);
    if (expected_class == NINLIL_WIFI_CU_INTENDED) {
        CHECK(status == NINLIL_WIFI_OK);
        CHECK(cold.committed.revision == 2u);
        CHECK(cold.committed.secret_ref_digest[0] == 0x22u);
    } else if (expected_class == NINLIL_WIFI_CU_OLD) {
        CHECK(status == NINLIL_WIFI_OK);
        CHECK(cold.committed.revision == 1u);
        CHECK(cold.committed.secret_ref_digest[0] == 0x11u);
    } else if (expected_class == NINLIL_WIFI_CU_ABSENT) {
        CHECK(status == NINLIL_WIFI_UNAVAILABLE);
    } else {
        CHECK(status == NINLIL_WIFI_CORRUPT);
    }
    check_storage_clean(storage);
    ninlil_test_storage_destroy(storage);
}

enum m4_kind {
    M4_MEMBERSHIP = 0,
    M4_ATTACHMENT = 1,
    M4_CREDENTIAL = 2
};

static const char *m4_key(enum m4_kind kind)
{
    if (kind == M4_MEMBERSHIP) {
        return NINLIL_WIFI_M4_KEY_MEMBERSHIP;
    }
    if (kind == M4_ATTACHMENT) {
        return NINLIL_WIFI_M4_KEY_ATTACHMENT;
    }
    return NINLIL_WIFI_M4_KEY_CREDENTIAL;
}

static ninlil_wifi_status_t m4_store(
    enum m4_kind kind,
    const ninlil_storage_ops_t *ops,
    void *storage_user,
    const char *path,
    uint8_t variant,
    ninlil_wifi_cu_class_t *out_class)
{
    ninlil_wifi_m4_membership_lease_t lease;
    uint8_t peer[16];
    uint8_t authority[16];
    uint8_t binding[32];
    uint8_t credential[32];
    uint8_t descriptor[32];
    (void)memset(peer, variant, sizeof(peer));
    (void)memset(authority, 0x31u, sizeof(authority));
    (void)memset(binding, 0x41u, sizeof(binding));
    (void)memset(credential, variant, sizeof(credential));
    (void)memset(descriptor, 0x61u, sizeof(descriptor));
    if (kind == M4_MEMBERSHIP) {
        (void)memset(&lease, 0, sizeof(lease));
        (void)memset(lease.member_runtime_id, variant, 16u);
        lease.lease_not_before_ms = 1u;
        lease.lease_not_after_ms = 1000u;
        (void)memset(lease.authority_id, 0x31u, 16u);
        (void)memset(lease.binding_digest, 0x41u, 32u);
        return ninlil_wifi_m4_membership_store_full_reconciled(
            ops, storage_user, path, &lease, out_class);
    }
    if (kind == M4_ATTACHMENT) {
        return ninlil_wifi_m4_attachment_store_full_reconciled(
            ops,
            storage_user,
            path,
            peer,
            authority,
            binding,
            credential,
            descriptor,
            out_class);
    }
    return ninlil_wifi_m4_credential_store_full_reconciled(
        ops, storage_user, path, credential, (uint64_t)variant, out_class);
}

static void run_m4_case(
    enum m4_kind kind,
    ninlil_wifi_cu_class_t expected_class,
    int seed_old,
    int committed_truth,
    int inject_other)
{
    static const char target_namespace[] = "wifi.cu.m4.target";
    static const char reference_namespace[] = "wifi.cu.m4.reference";
    ninlil_test_storage_t *storage = new_storage();
    wrapped_storage_t wrapped;
    ninlil_wifi_cu_class_t observed = NINLIL_WIFI_CU_NONE;
    uint8_t old_wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint8_t intended_wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint8_t actual_wire[NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES];
    uint32_t old_length = 0u;
    uint32_t intended_length = 0u;
    uint32_t actual_length = 0u;
    int old_present = 0;
    int intended_present = 0;
    int actual_present = 0;
    ninlil_wifi_status_t status;

    CHECK(storage != NULL);
    wrapped_init(&wrapped, storage);
    CHECK(m4_store(
              kind,
              &wrapped.ops,
              wrapped.ops.user,
              reference_namespace,
              2u,
              &observed)
        == NINLIL_WIFI_OK);
    CHECK(ninlil_wifi_storage_read(
              &wrapped.ops,
              wrapped.ops.user,
              reference_namespace,
              m4_key(kind),
              intended_wire,
              sizeof(intended_wire),
              &intended_length,
              &intended_present)
        == NINLIL_WIFI_OK);
    CHECK(intended_present == 1);
    if (seed_old != 0) {
        CHECK(m4_store(
                  kind,
                  &wrapped.ops,
                  wrapped.ops.user,
                  target_namespace,
                  1u,
                  &observed)
            == NINLIL_WIFI_OK);
        CHECK(ninlil_wifi_storage_read(
                  &wrapped.ops,
                  wrapped.ops.user,
                  target_namespace,
                  m4_key(kind),
                  old_wire,
                  sizeof(old_wire),
                  &old_length,
                  &old_present)
            == NINLIL_WIFI_OK);
        CHECK(old_present == 1);
    }
    arm_commit_unknown(
        &wrapped,
        committed_truth,
        inject_other,
        target_namespace,
        m4_key(kind));
    observed = NINLIL_WIFI_CU_NONE;
    status = m4_store(
        kind,
        &wrapped.ops,
        wrapped.ops.user,
        target_namespace,
        2u,
        &observed);
    CHECK(status == NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN);
    CHECK(observed == expected_class);
    check_storage_clean(storage);

    ninlil_test_storage_simulate_crash(storage);
    CHECK(ninlil_wifi_storage_read(
              &wrapped.ops,
              wrapped.ops.user,
              target_namespace,
              m4_key(kind),
              actual_wire,
              sizeof(actual_wire),
              &actual_length,
              &actual_present)
        == NINLIL_WIFI_OK);
    if (expected_class == NINLIL_WIFI_CU_INTENDED) {
        CHECK(actual_present == 1);
        CHECK(actual_length == intended_length);
        CHECK(memcmp(actual_wire, intended_wire, actual_length) == 0);
    } else if (expected_class == NINLIL_WIFI_CU_OLD) {
        CHECK(actual_present == 1);
        CHECK(actual_length == old_length);
        CHECK(memcmp(actual_wire, old_wire, actual_length) == 0);
    } else if (expected_class == NINLIL_WIFI_CU_ABSENT) {
        CHECK(actual_present == 0);
        CHECK(actual_length == 0u);
    } else {
        CHECK(actual_present == 1);
        CHECK(actual_length == NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES);
        CHECK(actual_wire[0] == 0xc7u);
    }
    check_storage_clean(storage);
    ninlil_test_storage_destroy(storage);
}

static void run_journal_crash_points(void)
{
    ninlil_test_storage_t *storage = new_storage();
    const ninlil_storage_ops_t *ops = ninlil_test_storage_ops(storage);
    uint8_t point;
    CHECK(storage != NULL);
    for (point = 0u; point <= 4u; ++point) {
        ninlil_wifi_journal_t writer;
        ninlil_wifi_journal_t cold;
        ninlil_wifi_journal_attempt_t attempt;
        ninlil_wifi_journal_attempt_t recovered;
        ninlil_wifi_journal_init(&writer);
        CHECK(ninlil_wifi_journal_open(
                  &writer, ops, ops->user, "wifi.crash.points")
            == NINLIL_WIFI_OK);
        (void)memset(&attempt, 0, sizeof(attempt));
        attempt.attempt_id = (uint64_t)point + 1u;
        attempt.generation = (uint32_t)point + 10u;
        attempt.phase = point == 4u
            ? (uint8_t)NINLIL_WIFI_PHASE_FENCED
            : (uint8_t)NINLIL_WIFI_PHASE_CONNECTING;
        attempt.write_point = point;
        CHECK(ninlil_wifi_journal_put_attempt(&writer, &attempt)
            == NINLIL_WIFI_OK);
        ninlil_test_storage_simulate_crash(storage);
        ninlil_wifi_journal_close(&writer);
        ninlil_wifi_journal_init(&cold);
        CHECK(ninlil_wifi_journal_open(
                  &cold, ops, ops->user, "wifi.crash.points")
            == NINLIL_WIFI_OK);
        (void)memset(&recovered, 0, sizeof(recovered));
        CHECK(ninlil_wifi_journal_recover(&cold, &recovered)
            == NINLIL_WIFI_OK);
        CHECK(recovered.write_point == point);
        CHECK(recovered.attempt_id == (uint64_t)point + 1u);
        CHECK(recovered.generation == (uint32_t)point + 10u);
        ninlil_wifi_journal_close(&cold);
    }
    check_storage_clean(storage);
    ninlil_test_storage_destroy(storage);
}

static void run_session_writepoint_failure(uint32_t fault_commit_offset)
{
    ninlil_test_storage_t *storage = new_storage();
    wrapped_storage_t wrapped;
    ninlil_wifi_session_t session;
    int sockets[2] = { -1, -1 };
    ninlil_wifi_status_t status;
    CHECK(storage != NULL);
    wrapped_init(&wrapped, storage);
    ninlil_wifi_session_init(&session);
    CHECK(ninlil_wifi_session_bind_journal(
              &session,
              &wrapped.ops,
              wrapped.ops.user,
              fault_commit_offset == 1u ? "wifi.session.wp0" : "wifi.session.wp1")
        == NINLIL_WIFI_OK);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    wrapped.fault_commit_number =
        wrapped.commit_calls + fault_commit_offset;
    wrapped.fault_committed_truth = 1;
    status = ninlil_wifi_session_accept_fd(&session, sockets[0]);
    sockets[0] = -1; /* ownership was passed and must have been closed */
    CHECK(status == NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN);
    CHECK(session.phase == NINLIL_WIFI_PHASE_FENCED);
    CHECK(session.tcp.fd < 0);
    CHECK(ninlil_wifi_session_last_journal_status(&session)
        == NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN);
    CHECK(ninlil_wifi_journal_last_commit_unknown_class(&session.journal)
        == NINLIL_WIFI_CU_INTENDED);
    ninlil_wifi_session_close(&session);
    if (sockets[0] >= 0) {
        (void)close(sockets[0]);
    }
    if (sockets[1] >= 0) {
        (void)close(sockets[1]);
    }
    check_storage_clean(storage);
    ninlil_test_storage_destroy(storage);
}

int main(void)
{
    enum m4_kind kind;
    failures = 0;

    run_journal_case(NINLIL_WIFI_CU_INTENDED, 1, 1, 0);
    run_journal_case(NINLIL_WIFI_CU_OLD, 1, 0, 0);
    run_journal_case(NINLIL_WIFI_CU_ABSENT, 0, 0, 0);
    run_journal_case(NINLIL_WIFI_CU_OTHER, 1, 1, 1);

    run_credential_case(NINLIL_WIFI_CU_INTENDED, 1, 1, 0);
    run_credential_case(NINLIL_WIFI_CU_OLD, 1, 0, 0);
    run_credential_case(NINLIL_WIFI_CU_ABSENT, 0, 0, 0);
    run_credential_case(NINLIL_WIFI_CU_OTHER, 1, 1, 1);

    for (kind = M4_MEMBERSHIP; kind <= M4_CREDENTIAL; ++kind) {
        run_m4_case(kind, NINLIL_WIFI_CU_INTENDED, 1, 1, 0);
        run_m4_case(kind, NINLIL_WIFI_CU_OLD, 1, 0, 0);
        run_m4_case(kind, NINLIL_WIFI_CU_ABSENT, 0, 0, 0);
        run_m4_case(kind, NINLIL_WIFI_CU_OTHER, 1, 1, 1);
    }

    run_journal_crash_points();
    run_session_writepoint_failure(1u); /* point 0: before fd ownership */
    run_session_writepoint_failure(2u); /* point 1: before TLS attach */

    if (failures != 0) {
        return 1;
    }
    (void)printf(
        "wifi_v1_storage_commit_unknown_test PASS classes=4 crash-points=5\n");
    return 0;
}
