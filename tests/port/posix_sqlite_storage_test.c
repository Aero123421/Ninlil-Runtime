#include "ninlil_posix_sqlite_storage.h"
#include "ninlil_posix_sqlite_token_advance.h"
#include "posix_sqlite_persist_interpose.h"

#include <sqlite3.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static const char *test_program_path;

#if defined(_WIN32)
#error "posix_sqlite_storage host conformance test targets Linux/macOS only"
#endif

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct fixture {
    char path[512];
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle;
} fixture_t;

static ninlil_bytes_view_t bytes(const void *data, uint32_t length)
{
    ninlil_bytes_view_t view;
    view.data = (const uint8_t *)data;
    view.length = length;
    return view;
}

static ninlil_mut_bytes_t mut(void *data, uint32_t capacity)
{
    ninlil_mut_bytes_t value;
    value.data = (uint8_t *)data;
    value.capacity = capacity;
    value.length = 0u;
    return value;
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
        "%s/ninlil-sqlite-XXXXXX",
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

static fixture_t open_fixture(
    uint64_t max_entries,
    uint64_t max_bytes,
    const uint8_t *ns,
    uint32_t ns_len)
{
    fixture_t fixture;
    ninlil_posix_sqlite_storage_config_t config;

    (void)memset(&fixture, 0, sizeof(fixture));
    if (!make_temp_path(fixture.path, sizeof(fixture.path))) {
        return fixture;
    }
    (void)memset(&config, 0, sizeof(config));
    config.database_path = fixture.path;
    config.busy_timeout_ms = 50u;
    config.max_entries_per_namespace = max_entries;
    config.max_bytes_per_namespace = max_bytes;
    config.max_handles = 8u;
    config.max_transactions = 8u;
    config.max_iterators = 8u;
    fixture.storage = ninlil_posix_sqlite_storage_create(&config);
    if (fixture.storage == NULL) {
        return fixture;
    }
    fixture.ops = ninlil_posix_sqlite_storage_ops(fixture.storage);
    if (fixture.ops->open(
            fixture.ops->user, bytes(ns, ns_len), NINLIL_STORAGE_SCHEMA_M1A,
            &fixture.handle)
        != NINLIL_STORAGE_OK) {
        ninlil_posix_sqlite_storage_destroy(fixture.storage);
        (void)memset(&fixture, 0, sizeof(fixture));
    }
    return fixture;
}

static int make_authority_lock_path(
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

/* Test-only diagnosis: distinguish the expected flock conflict from an
 * unrelated factory failure in the spawned-child BUSY test. */
static int authority_lock_is_busy(const char *path)
{
    char lock_path[768];
    int fd;
    int saved;

    if (!make_authority_lock_path(path, lock_path, sizeof(lock_path))) {
        return -1;
    }
    fd = open(lock_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        (void)flock(fd, LOCK_UN);
        (void)close(fd);
        return 0;
    }
    saved = errno;
    (void)close(fd);
    return saved == EWOULDBLOCK || saved == EAGAIN ? 1 : -1;
}

static void remove_db_artifacts(const char *path)
{
    char wal[640];
    char shm[640];
    char journal[640];
    char lock_path[768];
    int have_lock_path;

    if (path == NULL || path[0] == '\0') {
        return;
    }
    have_lock_path = make_authority_lock_path(
        path, lock_path, sizeof(lock_path));
    (void)remove(path);
    (void)snprintf(wal, sizeof(wal), "%s-wal", path);
    (void)snprintf(shm, sizeof(shm), "%s-shm", path);
    (void)snprintf(journal, sizeof(journal), "%s-journal", path);
    (void)remove(wal);
    (void)remove(shm);
    (void)remove(journal);
    if (have_lock_path) {
        (void)remove(lock_path);
    }
}

static void close_fixture(fixture_t *fixture)
{
    if (fixture->ops != NULL && fixture->handle != NULL) {
        fixture->ops->close(fixture->ops->user, fixture->handle);
    }
    ninlil_posix_sqlite_storage_destroy(fixture->storage);
    remove_db_artifacts(fixture->path);
    (void)memset(fixture, 0, sizeof(*fixture));
}

static ninlil_posix_sqlite_storage_config_t default_config(const char *path)
{
    ninlil_posix_sqlite_storage_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.database_path = path;
    config.busy_timeout_ms = 50u;
    config.max_entries_per_namespace = 16u;
    config.max_bytes_per_namespace = 4096u;
    config.max_handles = 4u;
    config.max_transactions = 4u;
    config.max_iterators = 4u;
    return config;
}

static int test_namespace_isolation_and_lease(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t first = NULL;
    ninlil_storage_handle_t second = NULL;
    ninlil_storage_handle_t other = NULL;
    static const uint8_t ns_a[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x00u};
    static const uint8_t ns_b[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x01u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    (void)memset(&config, 0, sizeof(config));
    config.database_path = path;
    config.busy_timeout_ms = 50u;
    config.max_entries_per_namespace = 16u;
    config.max_bytes_per_namespace = 4096u;
    config.max_handles = 4u;
    config.max_transactions = 4u;
    config.max_iterators = 4u;
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns_a, sizeof(ns_a)), 0u, &first)
        == NINLIL_STORAGE_UNSUPPORTED_SCHEMA);
    REQUIRE(first == NULL);
    REQUIRE(ops->open(ops->user, bytes(ns_a, sizeof(ns_a)),
            NINLIL_STORAGE_SCHEMA_M1A, &first)
        == NINLIL_STORAGE_OK);
    REQUIRE(first != NULL);
    REQUIRE(ops->open(ops->user, bytes(ns_a, sizeof(ns_a)),
            NINLIL_STORAGE_SCHEMA_M1A, &second)
        == NINLIL_STORAGE_BUSY);
    REQUIRE(second == NULL);
    REQUIRE(ops->open(ops->user, bytes(ns_b, sizeof(ns_b)),
            NINLIL_STORAGE_SCHEMA_M1A, &other)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, first);
    first = NULL;
    REQUIRE(ops->open(ops->user, bytes(ns_a, sizeof(ns_a)),
            NINLIL_STORAGE_SCHEMA_M1A, &first)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, first);
    ops->close(ops->user, other);
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_db_artifacts(path);
    return 0;
}

static int test_snapshot_isolation_read_your_writes_and_order(void)
{
    static const uint8_t ns[] = {0x6eu, 0x73u, 0x01u};
    fixture_t fixture = open_fixture(32u, 65536u, ns, sizeof(ns));
    ninlil_storage_txn_t writer = NULL;
    ninlil_storage_txn_t reader = NULL;
    ninlil_storage_iter_t iter = NULL;
    uint8_t key_buf[8];
    uint8_t value_buf[8];
    ninlil_mut_bytes_t key_out;
    ninlil_mut_bytes_t value_out;
    static const uint8_t k1[] = {0x01u};
    static const uint8_t k2[] = {0x01u, 0x00u};
    static const uint8_t k3[] = {0xffu};
    static const uint8_t v1[] = {0x11u};
    static const uint8_t v2[] = {0x22u, 0x22u};
    static const uint8_t v3[] = {0x33u, 0x33u, 0x33u};
    static const uint8_t v1b[] = {0xaau};

    REQUIRE(fixture.storage != NULL);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &writer)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer, bytes(k2, sizeof(k2)),
            bytes(v2, sizeof(v2)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer, bytes(k3, sizeof(k3)),
            bytes(v3, sizeof(v3)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer, bytes(k1, sizeof(k1)),
            bytes(v1, sizeof(v1)))
        == NINLIL_STORAGE_OK);
    /* read-your-writes */
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, writer, bytes(k1, sizeof(k1)),
            &value_out)
        == NINLIL_STORAGE_OK);
    REQUIRE(value_out.length == 1u && value_buf[0] == 0x11u);
    REQUIRE(fixture.ops->commit(fixture.ops->user, writer,
            NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    writer = NULL;

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &writer)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_ONLY, &reader)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer, bytes(k1, sizeof(k1)),
            bytes(v1b, sizeof(v1b)))
        == NINLIL_STORAGE_OK);
    /* concurrent RO snapshot does not see staged writer mutation */
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, reader, bytes(k1, sizeof(k1)),
            &value_out)
        == NINLIL_STORAGE_OK);
    REQUIRE(value_out.length == 1u && value_buf[0] == 0x11u);
    /* writer sees its own write */
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, writer, bytes(k1, sizeof(k1)),
            &value_out)
        == NINLIL_STORAGE_OK);
    REQUIRE(value_out.length == 1u && value_buf[0] == 0xaau);

    REQUIRE(fixture.ops->iter_open(fixture.ops->user, reader,
            bytes(NULL, 0u), &iter)
        == NINLIL_STORAGE_OK);
    key_out = mut(key_buf, sizeof(key_buf));
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, iter, &key_out, &value_out)
        == NINLIL_STORAGE_OK);
    REQUIRE(key_out.length == 1u && key_buf[0] == 0x01u);
    key_out = mut(key_buf, sizeof(key_buf));
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, iter, &key_out, &value_out)
        == NINLIL_STORAGE_OK);
    REQUIRE(key_out.length == 2u && key_buf[0] == 0x01u && key_buf[1] == 0x00u);
    key_out = mut(key_buf, sizeof(key_buf));
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, iter, &key_out, &value_out)
        == NINLIL_STORAGE_OK);
    REQUIRE(key_out.length == 1u && key_buf[0] == 0xffu);
    key_out = mut(key_buf, sizeof(key_buf));
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, iter, &key_out, &value_out)
        == NINLIL_STORAGE_NOT_FOUND);

    fixture.ops->iter_close(fixture.ops->user, iter);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, reader)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->commit(fixture.ops->user, writer,
            NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    close_fixture(&fixture);
    return 0;
}

static int test_buffer_too_small_and_zero_length_value(void)
{
    static const uint8_t ns[] = {0x7au};
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    uint8_t sentinel[8];
    uint8_t key_buf[4];
    uint8_t value_buf[8];
    ninlil_mut_bytes_t out;
    ninlil_mut_bytes_t key_out;
    ninlil_mut_bytes_t value_out;
    static const uint8_t key[] = {0x10u, 0x20u, 0x30u, 0x40u};
    static const uint8_t value[] = {0x01u, 0x02u, 0x03u, 0x04u, 0x05u};
    static const uint8_t empty_key[] = {0x99u};

    REQUIRE(fixture.storage != NULL);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn,
            bytes(empty_key, sizeof(empty_key)), bytes(NULL, 0u))
        == NINLIL_STORAGE_OK);
    (void)memset(sentinel, 0xaau, sizeof(sentinel));
    out = mut(sentinel, 4u);
    REQUIRE(fixture.ops->get(fixture.ops->user, txn, bytes(key, sizeof(key)),
            &out)
        == NINLIL_STORAGE_BUFFER_TOO_SMALL);
    REQUIRE(out.length == 5u);
    REQUIRE(sentinel[0] == 0xaau && sentinel[3] == 0xaau);
    out = mut(NULL, 0u);
    REQUIRE(fixture.ops->get(fixture.ops->user, txn,
            bytes(empty_key, sizeof(empty_key)), &out)
        == NINLIL_STORAGE_OK);
    REQUIRE(out.length == 0u);

    REQUIRE(fixture.ops->iter_open(fixture.ops->user, txn, bytes(NULL, 0u),
            &iter)
        == NINLIL_STORAGE_OK);
    (void)memset(key_buf, 0xbbu, sizeof(key_buf));
    (void)memset(value_buf, 0xccu, sizeof(value_buf));
    key_out = mut(key_buf, 3u);
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, iter, &key_out, &value_out)
        == NINLIL_STORAGE_BUFFER_TOO_SMALL);
    REQUIRE(key_out.length == 4u);
    REQUIRE(value_out.length == 5u);
    REQUIRE(key_buf[0] == 0xbbu && value_buf[0] == 0xccu);
    /* row not consumed: retry with larger buffers yields same row */
    key_out = mut(key_buf, sizeof(key_buf));
    value_out = mut(value_buf, sizeof(value_buf));
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, iter, &key_out, &value_out)
        == NINLIL_STORAGE_OK);
    REQUIRE(key_out.length == 4u && value_out.length == 5u);
    fixture.ops->iter_close(fixture.ops->user, iter);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    close_fixture(&fixture);
    return 0;
}

static int test_capacity_and_value_bound(void)
{
    static const uint8_t ns[] = {0x63u};
    fixture_t fixture = open_fixture(2u, 48u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_capacity_t cap;
    static const uint8_t k1[] = {0x01u};
    static const uint8_t k2[] = {0x02u};
    static const uint8_t k3[] = {0x03u};
    static const uint8_t v[] = {0xdeu, 0xadu};
    uint8_t big[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES + 1u];

    REQUIRE(fixture.storage != NULL);
    (void)memset(&cap, 0, sizeof(cap));
    cap.abi_version = NINLIL_ABI_VERSION;
    cap.struct_size = (uint16_t)sizeof(cap);
    REQUIRE(fixture.ops->capacity(fixture.ops->user, fixture.handle, &cap)
        == NINLIL_STORAGE_OK);
    REQUIRE(cap.max_entries == 2u);
    REQUIRE(cap.used_entries == 0u);
    REQUIRE(cap.used_bytes == 0u);

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(k1, sizeof(k1)),
            bytes(v, sizeof(v)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(k2, sizeof(k2)),
            bytes(v, sizeof(v)))
        == NINLIL_STORAGE_OK);
    /* Over-capacity put is accepted into the working view (docs/14 net). */
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(k3, sizeof(k3)),
            bytes(v, sizeof(v)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_NO_SPACE);
    txn = NULL;

    /* After failed commit, committed view is still empty. */
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(k1, sizeof(k1)),
            bytes(v, sizeof(v)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(k2, sizeof(k2)),
            bytes(v, sizeof(v)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    (void)memset(&cap, 0, sizeof(cap));
    cap.abi_version = NINLIL_ABI_VERSION;
    cap.struct_size = (uint16_t)sizeof(cap);
    REQUIRE(fixture.ops->capacity(fixture.ops->user, fixture.handle, &cap)
        == NINLIL_STORAGE_OK);
    REQUIRE(cap.used_entries == 2u);
    /* 2 * (16 + 1 + 2) = 38 */
    REQUIRE(cap.used_bytes == 38u);

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    (void)memset(big, 0x5au, sizeof(big));
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(k1, sizeof(k1)),
            bytes(big, (uint32_t)sizeof(big)))
        == NINLIL_STORAGE_NO_SPACE);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, txn)
        == NINLIL_STORAGE_OK);
    close_fixture(&fixture);
    return 0;
}

static int test_commit_net_capacity_erase_put_order(void)
{
    static const uint8_t ns[] = {0x6eu, 0x65u, 0x74u};
    fixture_t fixture = open_fixture(2u, 64u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t ka[] = {0x41u};
    static const uint8_t kb[] = {0x42u};
    static const uint8_t va[] = {0x01u, 0x02u};
    static const uint8_t vb[] = {0x03u, 0x04u};
    uint8_t out_buf[8];
    ninlil_mut_bytes_t out;

    REQUIRE(fixture.storage != NULL);
    /* Seed with A only so namespace is at 1/2 entries. */
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(ka, sizeof(ka)),
            bytes(va, sizeof(va)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(kb, sizeof(kb)),
            bytes(vb, sizeof(vb)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* put(B already present as replace) is fine; put new while full then erase. */
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    {
        static const uint8_t kc[] = {0x43u};
        static const uint8_t vc[] = {0x05u, 0x06u};
        /* At max entries: put(C) must still be accepted into the working view. */
        REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(kc, sizeof(kc)),
                bytes(vc, sizeof(vc)))
            == NINLIL_STORAGE_OK);
        REQUIRE(fixture.ops->erase(fixture.ops->user, txn,
                bytes(ka, sizeof(ka)))
            == NINLIL_STORAGE_OK);
        REQUIRE(fixture.ops->commit(fixture.ops->user, txn,
                NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
        txn = NULL;
    }

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, txn, bytes(ka, sizeof(ka)),
            &out)
        == NINLIL_STORAGE_NOT_FOUND);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, txn, bytes(kb, sizeof(kb)),
            &out)
        == NINLIL_STORAGE_OK);
    {
        static const uint8_t kc[] = {0x43u};
        out = mut(out_buf, sizeof(out_buf));
        REQUIRE(fixture.ops->get(fixture.ops->user, txn, bytes(kc, sizeof(kc)),
                &out)
            == NINLIL_STORAGE_OK);
    }
    REQUIRE(fixture.ops->rollback(fixture.ops->user, txn)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Reverse order: erase(A) then put(C) — same net, commit OK. */
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    {
        static const uint8_t kc[] = {0x43u};
        static const uint8_t kd[] = {0x44u};
        static const uint8_t vd[] = {0x07u, 0x08u};
        REQUIRE(fixture.ops->erase(fixture.ops->user, txn,
                bytes(kb, sizeof(kb)))
            == NINLIL_STORAGE_OK);
        REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(kd, sizeof(kd)),
                bytes(vd, sizeof(vd)))
            == NINLIL_STORAGE_OK);
        REQUIRE(fixture.ops->erase(fixture.ops->user, txn,
                bytes(kc, sizeof(kc)))
            == NINLIL_STORAGE_OK);
        REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(ka, sizeof(ka)),
                bytes(va, sizeof(va)))
            == NINLIL_STORAGE_OK);
        REQUIRE(fixture.ops->commit(fixture.ops->user, txn,
                NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
    }
    close_fixture(&fixture);
    return 0;
}

static int test_restart_and_crash_recovery(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    uint8_t value_buf[8];
    ninlil_mut_bytes_t out;
    static const uint8_t ns[] = {0x00u, 0x01u, 0xffu};
    static const uint8_t key[] = {0x42u};
    static const uint8_t value[] = {0xfeu, 0xedu};
    static const uint8_t lost[] = {0x99u};
    static const uint8_t lost_v[] = {0x00u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    (void)memset(&config, 0, sizeof(config));
    config.database_path = path;
    config.busy_timeout_ms = 50u;
    config.max_entries_per_namespace = 16u;
    config.max_bytes_per_namespace = 4096u;
    config.max_handles = 4u;
    config.max_transactions = 4u;
    config.max_iterators = 4u;
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->begin(ops->user,
            (ninlil_storage_handle_t)(uintptr_t)1u,
            NINLIL_STORAGE_READ_ONLY,
            &txn) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(txn == NULL);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(lost, sizeof(lost)),
            bytes(lost_v, sizeof(lost_v)))
        == NINLIL_STORAGE_OK);
    /* crash before commit: staged mutation must not persist */
    ninlil_posix_sqlite_storage_simulate_crash(storage);
    REQUIRE(ninlil_posix_sqlite_storage_live_handles(storage) == 0u);
    ninlil_posix_sqlite_storage_destroy(storage);

    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    handle = NULL;
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(value_buf, sizeof(value_buf));
    REQUIRE(ops->get(ops->user, txn, bytes(key, sizeof(key)), &out)
        == NINLIL_STORAGE_OK);
    REQUIRE(out.length == 2u && value_buf[0] == 0xfeu && value_buf[1] == 0xedu);
    out = mut(value_buf, sizeof(value_buf));
    REQUIRE(ops->get(ops->user, txn, bytes(lost, sizeof(lost)), &out)
        == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_db_artifacts(path);
    return 0;
}

static int test_binary_bytes_and_namespace_not_path(void)
{
    static const uint8_t ns[] = {
        0x2fu, 0x74u, 0x6du, 0x70u, 0x2fu, 0x00u, 0xffu, 0x2eu, 0x2eu
    };
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    uint8_t out_buf[16];
    ninlil_mut_bytes_t out;
    static const uint8_t key[] = {0x00u, 0xffu, 0x2fu, 0x00u};
    static const uint8_t value[] = {0x00u, 0x01u, 0x7fu, 0x80u, 0xffu};

    REQUIRE(fixture.storage != NULL);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, txn, bytes(key, sizeof(key)),
            &out)
        == NINLIL_STORAGE_OK);
    REQUIRE(out.length == sizeof(value));
    REQUIRE(memcmp(out_buf, value, sizeof(value)) == 0);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, txn)
        == NINLIL_STORAGE_OK);
    close_fixture(&fixture);
    return 0;
}

/*
 * COMMIT_UNKNOWN outcomes via test-only SQLite interposition (production has
 * no fault fields). Durable truth: committed bytes present after reopen when
 * COMMIT actually ran; absent when COMMIT was skipped.
 */
static int test_commit_unknown_truth_via_interpose(void)
{
    static const uint8_t ns[] = {0xf0u};
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *reopen = NULL;
    const ninlil_storage_ops_t *rops;
    ninlil_storage_handle_t handle = NULL;
    uint8_t out_buf[4];
    ninlil_mut_bytes_t out;
    static const uint8_t key_c[] = {0xc0u};
    static const uint8_t key_n[] = {0xc1u};
    static const uint8_t value[] = {0x01u};

    REQUIRE(fixture.storage != NULL);

    /* Real COMMIT, then lie autocommit==0 → COMMIT_UNKNOWN + fence, data kept. */
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn,
            bytes(key_c, sizeof(key_c)), bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    ninlil_test_sqlite_force_autocommit_zero_once();
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    txn = NULL;
    REQUIRE(ninlil_posix_sqlite_storage_live_transactions(fixture.storage)
        == 0u);
    REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(fixture.storage)
        == 1);
    fixture.ops->close(fixture.ops->user, fixture.handle);
    fixture.handle = NULL;
    ninlil_posix_sqlite_storage_destroy(fixture.storage);
    fixture.storage = NULL;
    fixture.ops = NULL;

    config = default_config(fixture.path);
    reopen = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(reopen != NULL);
    rops = ninlil_posix_sqlite_storage_ops(reopen);
    REQUIRE(rops->open(rops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
    REQUIRE(rops->begin(rops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(rops->get(rops->user, txn, bytes(key_c, sizeof(key_c)), &out)
        == NINLIL_STORAGE_OK);
    REQUIRE(rops->rollback(rops->user, txn) == NINLIL_STORAGE_OK);
    txn = NULL;

    /* Skip real COMMIT (IOERR), real ROLLBACK → UNKNOWN, not durable. */
    REQUIRE(rops->begin(rops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(rops->put(rops->user, txn, bytes(key_n, sizeof(key_n)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    ninlil_test_sqlite_inject_commit(0, SQLITE_IOERR);
    ninlil_test_sqlite_inject_rollback(1, SQLITE_OK);
    REQUIRE(rops->commit(rops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    txn = NULL;
    REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(reopen) == 0);
    REQUIRE(rops->begin(rops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(rops->get(rops->user, txn, bytes(key_n, sizeof(key_n)), &out)
        == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(rops->rollback(rops->user, txn) == NINLIL_STORAGE_OK);
    ninlil_test_sqlite_inject_clear();
    rops->close(rops->user, handle);
    ninlil_posix_sqlite_storage_destroy(reopen);
    remove_db_artifacts(fixture.path);
    return 0;
}

static int test_bad_schema_rejected(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    sqlite3 *db = NULL;
    int rc;

    REQUIRE(make_temp_path(path, sizeof(path)));
    rc = sqlite3_open(path, &db);
    REQUIRE(rc == SQLITE_OK);
    rc = sqlite3_exec(
        db,
        "CREATE TABLE ninlil_meta(key TEXT PRIMARY KEY, value INTEGER);"
        "INSERT INTO ninlil_meta(key, value) VALUES('schema_version', 99);",
        NULL,
        NULL,
        NULL);
    REQUIRE(rc == SQLITE_OK);
    (void)sqlite3_close(db);

    (void)memset(&config, 0, sizeof(config));
    config.database_path = path;
    config.busy_timeout_ms = 50u;
    config.max_entries_per_namespace = 8u;
    config.max_bytes_per_namespace = 1024u;
    config.max_handles = 2u;
    config.max_transactions = 2u;
    config.max_iterators = 2u;
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage == NULL);
    remove_db_artifacts(path);
    return 0;
}

static int test_handle_txn_iterator_consume(void)
{
    static const uint8_t ns[] = {0x51u};
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    static const uint8_t key[] = {0x01u};
    static const uint8_t value[] = {0x02u};

    REQUIRE(fixture.storage != NULL);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, txn, bytes(NULL, 0u),
            &iter)
        == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_posix_sqlite_storage_live_iterators(fixture.storage) == 1u);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_posix_sqlite_storage_live_transactions(fixture.storage)
        == 0u);
    REQUIRE(ninlil_posix_sqlite_storage_live_iterators(fixture.storage) == 0u);
    /* implicit consume: further use is CORRUPT / no-op close */
    fixture.ops->iter_close(fixture.ops->user, iter);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, txn)
        == NINLIL_STORAGE_CORRUPT);
    close_fixture(&fixture);
    REQUIRE(ninlil_posix_sqlite_storage_live_handles(NULL) == 0u);
    return 0;
}

static int test_second_writer_busy(void)
{
    static const uint8_t ns[] = {0x62u};
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t w1 = NULL;
    ninlil_storage_txn_t w2 = NULL;

    REQUIRE(fixture.storage != NULL);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &w1)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &w2)
        == NINLIL_STORAGE_BUSY);
    REQUIRE(w2 == NULL);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, w1)
        == NINLIL_STORAGE_OK);
    close_fixture(&fixture);
    return 0;
}

static int test_db_wide_instance_lease_and_namespace_independence(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *a;
    ninlil_posix_sqlite_storage_t *b;
    const ninlil_storage_ops_t *ops_a;
    ninlil_storage_handle_t ha = NULL;
    ninlil_storage_handle_t ha_other = NULL;
    static const uint8_t ns[] = {0x01u, 0x02u, 0xffu};
    static const uint8_t ns_other[] = {0x01u, 0x02u, 0xfeu};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    a = ninlil_posix_sqlite_storage_create(&config);
    b = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(a != NULL && b == NULL);
    ops_a = ninlil_posix_sqlite_storage_ops(a);
    REQUIRE(ops_a->open(ops_a->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &ha)
        == NINLIL_STORAGE_OK);
    /* Distinct exact namespaces remain independent inside the authority. */
    REQUIRE(ops_a->open(ops_a->user, bytes(ns_other, sizeof(ns_other)),
            NINLIL_STORAGE_SCHEMA_M1A, &ha_other)
        == NINLIL_STORAGE_OK);
    ops_a->close(ops_a->user, ha);
    ops_a->close(ops_a->user, ha_other);
    ninlil_posix_sqlite_storage_destroy(a);

    b = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(b != NULL);
    ninlil_posix_sqlite_storage_destroy(b);
    remove_db_artifacts(path);
    return 0;
}

static int test_opaque_aba_fail_closed(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t first = NULL;
    ninlil_storage_handle_t second = NULL;
    ninlil_storage_handle_t stale;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_txn_t stale_txn;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_iter_t stale_iter;
    static const uint8_t ns[] = {0xabu, 0xcdu};
    static const uint8_t key[] = {0x01u};
    static const uint8_t value[] = {0x02u};
    uint8_t out_buf[4];
    ninlil_mut_bytes_t out;
    ninlil_mut_bytes_t key_out;
    ninlil_mut_bytes_t value_out;

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &first)
        == NINLIL_STORAGE_OK);
    stale = first;
    ops->close(ops->user, first);
    first = NULL;
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &second)
        == NINLIL_STORAGE_OK);
    /* Slot may be reused, but generation must reject the stale token. */
    REQUIRE(ops->begin(ops->user, stale, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(txn == NULL);
    REQUIRE(ops->begin(ops->user, second, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->iter_open(ops->user, txn, bytes(NULL, 0u), &iter)
        == NINLIL_STORAGE_OK);
    stale_iter = iter;
    stale_txn = txn;
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(ops->get(ops->user, stale_txn, bytes(key, sizeof(key)), &out)
        == NINLIL_STORAGE_CORRUPT);
    key_out = mut(out_buf, sizeof(out_buf));
    value_out = mut(out_buf, sizeof(out_buf));
    REQUIRE(ops->iter_next(ops->user, stale_iter, &key_out, &value_out)
        == NINLIL_STORAGE_CORRUPT);
    ops->close(ops->user, second);
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_db_artifacts(path);
    return 0;
}

static int child_try_open_status(
    const ninlil_posix_sqlite_storage_config_t *config,
    const uint8_t *ns,
    uint32_t ns_len)
{
    ninlil_posix_sqlite_storage_t *child_storage;
    const ninlil_storage_ops_t *child_ops;
    ninlil_storage_handle_t child_handle = NULL;
    ninlil_storage_status_t open_status;

    child_storage = ninlil_posix_sqlite_storage_create(config);
    if (child_storage == NULL) {
        return -1;
    }
    child_ops = ninlil_posix_sqlite_storage_ops(child_storage);
    open_status = child_ops->open(
        child_ops->user, bytes(ns, ns_len), NINLIL_STORAGE_SCHEMA_M1A,
        &child_handle);
    if (child_handle != NULL) {
        child_ops->close(child_ops->user, child_handle);
    }
    ninlil_posix_sqlite_storage_destroy(child_storage);
    return (int)open_status;
}

static int parse_fd(const char *text, int *out_fd)
{
    char *end = NULL;
    long parsed;

    if (text == NULL || out_fd == NULL || text[0] == '\0') {
        return 0;
    }
    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0'
        || parsed < 0 || parsed > INT_MAX) {
        return 0;
    }
    *out_fd = (int)parsed;
    return 1;
}

/*
 * macOS forbids calling SQLite (and other non-async-signal-safe libraries) in
 * the child side of fork before exec.  Cross-process tests therefore spawn a
 * fresh image of this executable and enter one of these narrowly-scoped modes.
 */
static int run_child_mode(int argc, char **argv)
{
    static const uint8_t process_ns[] = {0x10u, 0x00u, 0xffu};
    static const uint8_t dead_ns[] = {0xdeu, 0xadu, 0x01u};
    ninlil_posix_sqlite_storage_config_t config;

    if (argc < 3 || argv == NULL) {
        return 126;
    }
    config = default_config(argv[2]);
    if (strcmp(argv[1], "--child-open") == 0) {
        int open_status = child_try_open_status(
            &config, process_ns, (uint32_t)sizeof(process_ns));
        return open_status == (int)NINLIL_STORAGE_OK ? 0 : 1;
    }
    if (strcmp(argv[1], "--child-busy") == 0) {
        int go_fd;
        int result_fd;
        int open_status;
        int lock_busy;
        char gate = 0;
        char result;

        if (argc != 5 || !parse_fd(argv[3], &go_fd)
            || !parse_fd(argv[4], &result_fd)
            || read(go_fd, &gate, 1) != 1 || gate != 'G') {
            return 4;
        }
        lock_busy = authority_lock_is_busy(argv[2]);
        open_status = child_try_open_status(
            &config, process_ns, (uint32_t)sizeof(process_ns));
        result = lock_busy == 1 && open_status == -1 ? 'L' : 'X';
        if (write(result_fd, &result, 1) != 1) {
            return 5;
        }
        return lock_busy == 1 && open_status == -1 ? 0 : 1;
    }
    if (strcmp(argv[1], "--child-hold") == 0) {
        ninlil_posix_sqlite_storage_t *storage;
        const ninlil_storage_ops_t *ops;
        ninlil_storage_handle_t handle = NULL;
        int ready_fd;
        char ready = 'R';

        if (argc != 4 || !parse_fd(argv[3], &ready_fd)) {
            return 4;
        }
        storage = ninlil_posix_sqlite_storage_create(&config);
        if (storage == NULL) {
            return 2;
        }
        ops = ninlil_posix_sqlite_storage_ops(storage);
        if (ops->open(ops->user, bytes(dead_ns, (uint32_t)sizeof(dead_ns)),
                NINLIL_STORAGE_SCHEMA_M1A, &handle)
            != NINLIL_STORAGE_OK) {
            ninlil_posix_sqlite_storage_destroy(storage);
            return 3;
        }
        if (write(ready_fd, &ready, 1) != 1) {
            return 5;
        }
        for (;;) {
            pause();
        }
    }
    return 126;
}

static int test_spawned_child_busy_and_clean_close(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    int go_pipe[2];
    int res_pipe[2];
    pid_t child;
    int status = 0;
    int child_status = -1;
    char ack = 0;
    char go = 'G';
    char go_fd_text[32];
    char result_fd_text[32];
    char *busy_argv[6];
    char *open_argv[4];
    static const uint8_t ns[] = {0x10u, 0x00u, 0xffu};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    /* Materialize schema before the exclusion race. */
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ninlil_posix_sqlite_storage_destroy(storage);
    storage = NULL;

    /* Start the fresh child image before the parent acquires the lease. */
    REQUIRE(pipe(go_pipe) == 0);
    REQUIRE(pipe(res_pipe) == 0);
    REQUIRE(snprintf(go_fd_text, sizeof(go_fd_text), "%d", go_pipe[0]) > 0);
    REQUIRE(snprintf(result_fd_text, sizeof(result_fd_text), "%d", res_pipe[1])
        > 0);
    busy_argv[0] = (char *)test_program_path;
    busy_argv[1] = (char *)"--child-busy";
    busy_argv[2] = path;
    busy_argv[3] = go_fd_text;
    busy_argv[4] = result_fd_text;
    busy_argv[5] = NULL;
    REQUIRE(posix_spawnp(&child, test_program_path, NULL, NULL,
            busy_argv, environ) == 0);
    (void)close(go_pipe[0]);
    (void)close(res_pipe[1]);

    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle)
        == NINLIL_STORAGE_OK);
    REQUIRE(write(go_pipe[1], &go, 1) == 1);
    REQUIRE(read(res_pipe[0], &ack, 1) == 1);
    /* 'L' means the child independently observed LOCK_NB contention and the
     * provider factory rejected that exact authority; generic NULL is not
     * accepted as proof of BUSY. */
    REQUIRE(ack == 'L');
    (void)close(go_pipe[1]);
    (void)close(res_pipe[0]);
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    ops->close(ops->user, handle);
    handle = NULL;
    ninlil_posix_sqlite_storage_destroy(storage);
    storage = NULL;
    ops = NULL;

    /*
     * After clean close, a sibling process must be able to acquire the lease.
     * Use a fresh process that never inherited parent fds.
     */
    open_argv[0] = (char *)test_program_path;
    open_argv[1] = (char *)"--child-open";
    open_argv[2] = path;
    open_argv[3] = NULL;
    REQUIRE(posix_spawnp(&child, test_program_path, NULL, NULL,
            open_argv, environ) == 0);
    REQUIRE(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status)) {
        (void)fprintf(stderr,
            "clean-close child terminated by signal %d\n",
            WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    }
    REQUIRE(WIFEXITED(status));
    child_status = WEXITSTATUS(status);
    REQUIRE(child_status == 0);
    remove_db_artifacts(path);
    return 0;
}

static int test_sigkill_dead_owner_reopen(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    int pipes[2];
    pid_t child;
    int status = 0;
    char ack = 0;
    char ready_fd_text[32];
    char *hold_argv[5];
    static const uint8_t ns[] = {0xdeu, 0xadu, 0x01u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    /* Create schema in parent first. */
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ninlil_posix_sqlite_storage_destroy(storage);
    storage = NULL;

    REQUIRE(pipe(pipes) == 0);
    REQUIRE(snprintf(ready_fd_text, sizeof(ready_fd_text), "%d", pipes[1])
        > 0);
    hold_argv[0] = (char *)test_program_path;
    hold_argv[1] = (char *)"--child-hold";
    hold_argv[2] = path;
    hold_argv[3] = ready_fd_text;
    hold_argv[4] = NULL;
    REQUIRE(posix_spawnp(&child, test_program_path, NULL, NULL,
            hold_argv, environ) == 0);
    (void)close(pipes[1]);
    REQUIRE(read(pipes[0], &ack, 1) == 1);
    REQUIRE(ack == 'R');
    (void)close(pipes[0]);
    REQUIRE(kill(child, SIGKILL) == 0);
    REQUIRE(waitpid(child, &status, 0) == child);
    REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_db_artifacts(path);
    return 0;
}

static int test_stale_writer_fence_after_crash_sim(void)
{
    static const uint8_t ns[] = {0x51u, 0x47u};
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t key[] = {0x01u};
    static const uint8_t value[] = {0x02u};

    REQUIRE(fixture.storage != NULL);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    /* Drop leases/handles without consuming the caller-held txn token. */
    ninlil_posix_sqlite_storage_simulate_crash(fixture.storage);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_CORRUPT);
    fixture.handle = NULL;
    close_fixture(&fixture);
    return 0;
}

/*
 * Private pure advance helpers (max argument): no wrap, permanent exhaustion.
 * Production storage uses UINT64_MAX fixed; low-ceiling integration seams are
 * intentionally absent from the production library.
 */
static int test_pure_generation_and_lease_token_no_wrap(void)
{
    uint64_t gen = 0u;
    uint64_t tok = 0u;
    unsigned step;

    /* gen_max=3: issuable values 1,2,3 then permanent exhaustion. */
    REQUIRE(ninlil_posix_sqlite_generation_advance(0u, 3u) == 1u);
    REQUIRE(ninlil_posix_sqlite_generation_advance(1u, 3u) == 2u);
    REQUIRE(ninlil_posix_sqlite_generation_advance(2u, 3u) == 3u);
    REQUIRE(ninlil_posix_sqlite_generation_advance(3u, 3u) == 0u);
    REQUIRE(ninlil_posix_sqlite_generation_advance(4u, 3u) == 0u);
    REQUIRE(ninlil_posix_sqlite_generation_advance(0u, 0u) == 0u);
    /* Never restarts at 1 after max. */
    REQUIRE(ninlil_posix_sqlite_generation_advance(3u, 3u) != 1u);
    REQUIRE(ninlil_posix_sqlite_generation_advance(
            UINT64_MAX - 1u, UINT64_MAX) == UINT64_MAX);
    REQUIRE(ninlil_posix_sqlite_generation_advance(
            UINT64_MAX, UINT64_MAX) == 0u);

    REQUIRE(ninlil_posix_sqlite_lease_token_advance(0u, 2u) == 1u);
    REQUIRE(ninlil_posix_sqlite_lease_token_advance(1u, 2u) == 2u);
    REQUIRE(ninlil_posix_sqlite_lease_token_advance(2u, 2u) == 0u);
    REQUIRE(ninlil_posix_sqlite_lease_token_advance(UINT64_MAX, UINT64_MAX)
        == 0u);
    REQUIRE(ninlil_posix_sqlite_lease_token_advance(UINT64_MAX - 1u, UINT64_MAX)
        == UINT64_MAX);
    REQUIRE(ninlil_posix_sqlite_lease_token_advance(UINT64_MAX, UINT64_MAX)
        == 0u);

    /* Simulated slot retirement sequence with max=2 (pure state machine). */
    for (step = 0u; step < 2u; ++step) {
        uint64_t next = ninlil_posix_sqlite_generation_advance(gen, 2u);
        REQUIRE(next != 0u);
        gen = next;
    }
    REQUIRE(ninlil_posix_sqlite_generation_advance(gen, 2u) == 0u);
    REQUIRE(ninlil_posix_sqlite_generation_advance(gen, 2u) != 1u);

    for (step = 0u; step < 2u; ++step) {
        uint64_t next = ninlil_posix_sqlite_lease_token_advance(tok, 2u);
        REQUIRE(next != 0u);
        tok = next;
    }
    REQUIRE(ninlil_posix_sqlite_lease_token_advance(tok, 2u) == 0u);
    /* Last issuable token equals max → production would fence further opens. */
    REQUIRE(tok == 2u);
    return 0;
}

static int test_path_alias_hardlink_lease_convergence(void)
{
    char path_a[512];
    char path_abs[640];
    char path_link[640];
    char path_hard[640];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage_a;
    ninlil_posix_sqlite_storage_t *storage_b;
    const ninlil_storage_ops_t *ops_a;
    ninlil_storage_handle_t ha = NULL;
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t ns[] = {0xa1u, 0xa2u};
    static const uint8_t key[] = {0x01u};
    static const uint8_t value[] = {0x02u};
    const char *cwd;

    REQUIRE(make_temp_path(path_a, sizeof(path_a)));
    config = default_config(path_a);
    storage_a = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage_a != NULL);
    ninlil_posix_sqlite_storage_destroy(storage_a);

    cwd = getenv("PWD");
    if (cwd == NULL || cwd[0] == '\0') {
        cwd = ".";
    }
    /* Absolute alias of the same path string family. */
    if (path_a[0] == '/') {
        REQUIRE((size_t)snprintf(path_abs, sizeof(path_abs), "%s", path_a)
            < sizeof(path_abs));
    } else {
        REQUIRE((size_t)snprintf(path_abs, sizeof(path_abs), "%s/%s", cwd,
            path_a)
            < sizeof(path_abs));
    }
    REQUIRE((size_t)snprintf(path_link, sizeof(path_link), "%s.sym", path_a)
        < sizeof(path_link));
    REQUIRE((size_t)snprintf(path_hard, sizeof(path_hard), "%s.hard", path_a)
        < sizeof(path_hard));
    (void)unlink(path_link);
    (void)unlink(path_hard);
    REQUIRE(symlink(path_a, path_link) == 0);
    REQUIRE(link(path_a, path_hard) == 0);

    /* Existing hardlinks make WAL/SHM pathname authority ambiguous. */
    config = default_config(path_abs);
    REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);

    config = default_config(path_link);
    REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);

    config = default_config(path_hard);
    REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);

    REQUIRE(unlink(path_hard) == 0);
    config = default_config(path_a);
    storage_a = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage_a != NULL);
    ops_a = ninlil_posix_sqlite_storage_ops(storage_a);
    REQUIRE(ops_a->open(ops_a->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &ha)
        == NINLIL_STORAGE_OK);

    /* Same pathname authority is rejected while the provider owns it. */
    config = default_config(path_abs);
    storage_b = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage_b == NULL);

    /* A hardlink introduced after create fences the next durable mutation. */
    REQUIRE(link(path_a, path_hard) == 0);
    REQUIRE(ops_a->begin(ops_a->user, ha, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops_a->put(ops_a->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);
    REQUIRE(ops_a->commit(ops_a->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_CORRUPT);
    txn = NULL;

    ops_a->close(ops_a->user, ha);
    ninlil_posix_sqlite_storage_destroy(storage_a);
    (void)unlink(path_link);
    (void)unlink(path_hard);
    remove_db_artifacts(path_a);
    return 0;
}

static int test_sidecar_and_db_path_replacement_fail_closed(void)
{
    char path[512];
    char lock_path[768];
    char lock_hardlink[896];
    char moved_path[768];
    char moved_lock[896];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_handle_t other = NULL;
    ninlil_storage_txn_t txn = NULL;
    int fd;
    static const uint8_t ns[] = {0x70u, 0x61u, 0x74u, 0x68u};
    static const uint8_t key[] = {0x01u};
    static const uint8_t value[] = {0x02u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ninlil_posix_sqlite_storage_destroy(storage);
    REQUIRE(make_authority_lock_path(path, lock_path, sizeof(lock_path)));

    /* A final symlink at the authority path is never followed. */
    REQUIRE(unlink(lock_path) == 0);
    REQUIRE(symlink(path, lock_path) == 0);
    REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
    REQUIRE(unlink(lock_path) == 0);

    /* A multiply-linked sidecar cannot be accepted as unique authority. */
    fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    REQUIRE(fd >= 0);
    REQUIRE(close(fd) == 0);
    REQUIRE((size_t)snprintf(lock_hardlink, sizeof(lock_hardlink), "%s.hard",
            lock_path) < sizeof(lock_hardlink));
    (void)unlink(lock_hardlink);
    REQUIRE(link(lock_path, lock_hardlink) == 0);
    REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
    REQUIRE(unlink(lock_hardlink) == 0);

    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);

    /* Replacing the sidecar pathname cannot transfer the held authority. */
    REQUIRE((size_t)snprintf(moved_lock, sizeof(moved_lock), "%s.moved",
            lock_path) < sizeof(moved_lock));
    (void)unlink(moved_lock);
    REQUIRE(rename(lock_path, moved_lock) == 0);
    fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    REQUIRE(fd >= 0);
    REQUIRE(close(fd) == 0);
    REQUIRE(ops->open(ops->user, bytes(value, sizeof(value)),
            NINLIL_STORAGE_SCHEMA_M1A, &other) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(other == NULL);
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);
    REQUIRE(unlink(lock_path) == 0);
    REQUIRE(rename(moved_lock, lock_path) == 0);

    /* Replacing the configured DB pathname fences a staged writer. */
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    handle = NULL;
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);
    REQUIRE((size_t)snprintf(moved_path, sizeof(moved_path), "%s.moved", path)
        < sizeof(moved_path));
    (void)unlink(moved_path);
    REQUIRE(rename(path, moved_path) == 0);
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    REQUIRE(fd >= 0);
    REQUIRE(close(fd) == 0);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_CORRUPT);
    txn = NULL;
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);
    REQUIRE(unlink(path) == 0);
    REQUIRE(rename(moved_path, path) == 0);
    remove_db_artifacts(path);
    return 0;
}

static int test_sidecar_owner_and_mode_policy(void)
{
    static const mode_t rejected_modes[] = {
        (mode_t)0666,
        (mode_t)0620,
        (mode_t)0604
    };
    char path[512];
    char lock_path[768];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_handle_t other = NULL;
    struct stat st;
    size_t index;
    static const uint8_t ns[] = {0x6fu, 0x77u, 0x6eu};
    static const uint8_t ns_other[] = {0x6fu, 0x74u, 0x68u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ninlil_posix_sqlite_storage_destroy(storage);
    REQUIRE(make_authority_lock_path(path, lock_path, sizeof(lock_path)));
    REQUIRE(lstat(lock_path, &st) == 0);
    REQUIRE(st.st_uid == geteuid());
    REQUIRE((st.st_mode & (mode_t)0777) == (mode_t)0600);

    for (index = 0u;
         index < sizeof(rejected_modes) / sizeof(rejected_modes[0]); ++index) {
        REQUIRE(chmod(lock_path, rejected_modes[index]) == 0);
        REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
        REQUIRE(lstat(lock_path, &st) == 0);
        REQUIRE((st.st_mode & (mode_t)0777) == rejected_modes[index]);
    }
    REQUIRE(chmod(lock_path, (mode_t)0600) == 0);

    /* Foreign-owner coverage is executable under privileged CI/local runs;
     * unprivileged hosts cannot legally construct this fixture. */
    if (geteuid() == (uid_t)0) {
        REQUIRE(lstat(lock_path, &st) == 0);
        REQUIRE(chown(lock_path, (uid_t)1, st.st_gid) == 0);
        REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
        REQUIRE(lstat(lock_path, &st) == 0);
        REQUIRE(st.st_uid == (uid_t)1);
        REQUIRE(chown(lock_path, geteuid(), st.st_gid) == 0);
    }

    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);

    /* Permission drift after flock acquisition is caught at the next public
     * authority boundary, not merely on the initial open. */
    REQUIRE(chmod(lock_path, (mode_t)0666) == 0);
    REQUIRE(ops->open(ops->user, bytes(ns_other, sizeof(ns_other)),
            NINLIL_STORAGE_SCHEMA_M1A, &other) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(other == NULL);
    REQUIRE(chmod(lock_path, (mode_t)0600) == 0);
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_db_artifacts(path);
    return 0;
}

static int test_bad_schema_text_version_and_partial_meta(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    sqlite3 *db = NULL;
    int rc;

    REQUIRE(make_temp_path(path, sizeof(path)));
    /* TEXT-typed value column storing '1garbage' must not open as schema 1. */
    rc = sqlite3_open(path, &db);
    REQUIRE(rc == SQLITE_OK);
    rc = sqlite3_exec(
        db,
        "CREATE TABLE ninlil_meta(key TEXT PRIMARY KEY NOT NULL,"
        " value TEXT NOT NULL);"
        "CREATE TABLE ninlil_kv("
        "  namespace BLOB NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL,"
        "  PRIMARY KEY(namespace, key)"
        ") WITHOUT ROWID;"
        "INSERT INTO ninlil_meta(key, value)"
        " VALUES('schema_version', '1garbage');"
        "INSERT INTO ninlil_meta(key, value)"
        " VALUES('migration_state', '0');",
        NULL,
        NULL,
        NULL);
    REQUIRE(rc == SQLITE_OK);
    (void)sqlite3_close(db);

    config = default_config(path);
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage == NULL);

    /* meta(version integer 1) only — missing kv/migration_state. */
    rc = sqlite3_open(path, &db);
    REQUIRE(rc == SQLITE_OK);
    (void)sqlite3_exec(db, "DROP TABLE IF EXISTS ninlil_meta;"
        "DROP TABLE IF EXISTS ninlil_kv;", NULL, NULL, NULL);
    rc = sqlite3_exec(
        db,
        "CREATE TABLE ninlil_meta(key TEXT PRIMARY KEY NOT NULL,"
        " value INTEGER NOT NULL);"
        "INSERT INTO ninlil_meta(key, value) VALUES('schema_version', 1);",
        NULL,
        NULL,
        NULL);
    REQUIRE(rc == SQLITE_OK);
    (void)sqlite3_close(db);
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage == NULL);
    remove_db_artifacts(path);
    return 0;
}

static int test_strict_schema_and_legacy_rejection_matrix(void)
{
    static const char *const invalid_schema[] = {
        /* Exact columns but rowid tables. */
        "CREATE TABLE ninlil_meta(key TEXT PRIMARY KEY NOT NULL,"
        " value INTEGER NOT NULL) STRICT;"
        "CREATE TABLE ninlil_kv(namespace BLOB NOT NULL,key BLOB NOT NULL,"
        " value BLOB NOT NULL,PRIMARY KEY(namespace,key)) STRICT;"
        "INSERT INTO ninlil_meta VALUES('schema_version',1),"
        " ('migration_state',0);",
        /* WITHOUT ROWID but not STRICT, with invalid TEXT KV content. */
        "CREATE TABLE ninlil_meta(key TEXT PRIMARY KEY NOT NULL,"
        " value INTEGER NOT NULL) WITHOUT ROWID;"
        "CREATE TABLE ninlil_kv(namespace BLOB NOT NULL,key BLOB NOT NULL,"
        " value BLOB NOT NULL,PRIMARY KEY(namespace,key)) WITHOUT ROWID;"
        "INSERT INTO ninlil_meta VALUES('schema_version',1),"
        " ('migration_state',0);"
        "INSERT INTO ninlil_kv VALUES('text-ns','text-key','text-value');",
        /* Extra columns are not a compatible v1 extension. */
        "CREATE TABLE ninlil_meta(key TEXT PRIMARY KEY NOT NULL,"
        " value INTEGER NOT NULL) STRICT, WITHOUT ROWID;"
        "CREATE TABLE ninlil_kv(namespace BLOB NOT NULL,key BLOB NOT NULL,"
        " value BLOB NOT NULL,extra BLOB,PRIMARY KEY(namespace,key))"
        " STRICT, WITHOUT ROWID;"
        "INSERT INTO ninlil_meta VALUES('schema_version',1),"
        " ('migration_state',0);",
        /* Meta content must be exactly the two normative rows. */
        "CREATE TABLE ninlil_meta(key TEXT PRIMARY KEY NOT NULL,"
        " value INTEGER NOT NULL) STRICT, WITHOUT ROWID;"
        "CREATE TABLE ninlil_kv(namespace BLOB NOT NULL,key BLOB NOT NULL,"
        " value BLOB NOT NULL,PRIMARY KEY(namespace,key))"
        " STRICT, WITHOUT ROWID;"
        "INSERT INTO ninlil_meta VALUES('schema_version',1),"
        " ('migration_state',0),('extra',7);"
    };
    size_t index;

    for (index = 0u; index < sizeof(invalid_schema) / sizeof(invalid_schema[0]);
         ++index) {
        char path[512];
        sqlite3 *db = NULL;
        ninlil_posix_sqlite_storage_config_t config;

        REQUIRE(make_temp_path(path, sizeof(path)));
        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db, invalid_schema[index], NULL, NULL, NULL)
            == SQLITE_OK);
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        config = default_config(path);
        REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
        remove_db_artifacts(path);
    }

    /* Legacy lease presence is rejected without DROP/migration. */
    {
        char path[512];
        sqlite3 *db = NULL;
        sqlite3_stmt *stmt = NULL;
        ninlil_posix_sqlite_storage_config_t config;
        ninlil_posix_sqlite_storage_t *storage;

        REQUIRE(make_temp_path(path, sizeof(path)));
        config = default_config(path);
        storage = ninlil_posix_sqlite_storage_create(&config);
        REQUIRE(storage != NULL);
        ninlil_posix_sqlite_storage_destroy(storage);
        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db,
            "CREATE TABLE ninlil_lease(namespace BLOB PRIMARY KEY, owner BLOB);"
            "INSERT INTO ninlil_lease VALUES(x'01',x'02');",
            NULL, NULL, NULL) == SQLITE_OK);
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM ninlil_lease;", -1, &stmt, NULL)
            == SQLITE_OK);
        REQUIRE(sqlite3_step(stmt) == SQLITE_ROW);
        REQUIRE(sqlite3_column_int(stmt, 0) == 1);
        REQUIRE(sqlite3_finalize(stmt) == SQLITE_OK);
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        remove_db_artifacts(path);
    }
    return 0;
}

static int sqlite_count_one(
    sqlite3 *db,
    const char *sql,
    int expected)
{
    sqlite3_stmt *stmt = NULL;
    int ok = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    if (sqlite3_step(stmt) == SQLITE_ROW
        && sqlite3_column_int(stmt, 0) == expected
        && sqlite3_step(stmt) == SQLITE_DONE) {
        ok = 1;
    }
    (void)sqlite3_finalize(stmt);
    return ok;
}

static int test_closed_schema_objects_and_trigger_fence(void)
{
    static const struct {
        const char *ddl;
        const char *verify_sql;
    } extra_objects[] = {
        {
            "CREATE VIEW ninlil_debug_view AS"
            " SELECT namespace, key, value FROM ninlil_kv;",
            "SELECT COUNT(*) FROM sqlite_master"
            " WHERE type='view' AND name='ninlil_debug_view';"
        },
        {
            "CREATE INDEX ninlil_kv_value_idx ON ninlil_kv(value);",
            "SELECT COUNT(*) FROM sqlite_master"
            " WHERE type='index' AND name='ninlil_kv_value_idx';"
        }
    };
    size_t index;

    for (index = 0u;
         index < sizeof(extra_objects) / sizeof(extra_objects[0]); ++index) {
        char path[512];
        sqlite3 *db = NULL;
        ninlil_posix_sqlite_storage_config_t config;
        ninlil_posix_sqlite_storage_t *storage;

        REQUIRE(make_temp_path(path, sizeof(path)));
        config = default_config(path);
        storage = ninlil_posix_sqlite_storage_create(&config);
        REQUIRE(storage != NULL);
        ninlil_posix_sqlite_storage_destroy(storage);
        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db, extra_objects[index].ddl, NULL, NULL, NULL)
            == SQLITE_OK);
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        db = NULL;

        /* Unsupported objects are rejected, never dropped or migrated. */
        REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite_count_one(db, extra_objects[index].verify_sql, 1));
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        remove_db_artifacts(path);
    }

    {
        char path[512];
        sqlite3 *db = NULL;
        ninlil_posix_sqlite_storage_config_t config;
        ninlil_posix_sqlite_storage_t *storage;
        const ninlil_storage_ops_t *ops;
        ninlil_storage_handle_t handle = NULL;
        ninlil_storage_txn_t txn = NULL;
        static const uint8_t ns[] = {0x74u, 0x72u, 0x67u};
        static const uint8_t key_a[] = {0x01u};
        static const uint8_t key_b[] = {0x02u};
        static const uint8_t value[] = {0xa5u};

        REQUIRE(make_temp_path(path, sizeof(path)));
        config = default_config(path);
        storage = ninlil_posix_sqlite_storage_create(&config);
        REQUIRE(storage != NULL);
        ops = ninlil_posix_sqlite_storage_ops(storage);
        REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
                NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
        REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->put(ops->user, txn, bytes(key_a, sizeof(key_a)),
                bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);
        REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
        txn = NULL;

        REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->put(ops->user, txn, bytes(key_b, sizeof(key_b)),
                bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);
        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db,
            "CREATE TRIGGER ninlil_delete_after_insert"
            " AFTER INSERT ON ninlil_kv BEGIN"
            " DELETE FROM ninlil_kv WHERE namespace=NEW.namespace; END;",
            NULL, NULL, NULL) == SQLITE_OK);
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        db = NULL;

        /* Closed schema is revalidated inside the BEGIN IMMEDIATE txn before
         * mutation; the trigger cannot run and the durable row is unchanged. */
        REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_CORRUPT);
        REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(storage) == 1);
        txn = NULL;
        ops->close(ops->user, handle);
        ninlil_posix_sqlite_storage_destroy(storage);

        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite_count_one(db,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'"
            " AND name='ninlil_delete_after_insert';", 1));
        REQUIRE(sqlite_count_one(db, "SELECT COUNT(*) FROM ninlil_kv;", 1));
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        db = NULL;

        /* Reopen rejects the same trigger and leaves it and data untouched. */
        REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);
        REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
        REQUIRE(sqlite_count_one(db,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'"
            " AND name='ninlil_delete_after_insert';", 1));
        REQUIRE(sqlite_count_one(db, "SELECT COUNT(*) FROM ninlil_kv;", 1));
        REQUIRE(sqlite3_close(db) == SQLITE_OK);
        remove_db_artifacts(path);
    }
    return 0;
}

typedef struct interpose_path_ctx {
    const char *path;
    char moved_path[768];
    int fired;
    int replace_rc;
} interpose_path_ctx_t;

typedef struct interpose_trigger_ctx {
    const char *path;
    int fired;
    int create_rc;
    int concurrent_busy;
} interpose_trigger_ctx_t;

static int replace_db_pathname(const char *path, char *moved, size_t moved_size)
{
    int fd;
    int written;

    written = snprintf(moved, moved_size, "%s.moved", path);
    if (written <= 0 || (size_t)written >= moved_size) {
        return -1;
    }
    (void)unlink(moved);
    if (rename(path, moved) != 0) {
        return -1;
    }
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        (void)rename(moved, path);
        return -1;
    }
    if (close(fd) != 0) {
        (void)unlink(path);
        (void)rename(moved, path);
        return -1;
    }
    return 0;
}

static void interpose_replace_path(
    ninlil_test_persist_point_t point,
    void *user)
{
    interpose_path_ctx_t *ctx = (interpose_path_ctx_t *)user;

    (void)point;
    if (ctx == NULL || ctx->fired != 0) {
        return;
    }
    ctx->fired = 1;
    ctx->replace_rc = replace_db_pathname(
        ctx->path, ctx->moved_path, sizeof(ctx->moved_path));
}

static void interpose_inject_trigger(
    ninlil_test_persist_point_t point,
    void *user)
{
    interpose_trigger_ctx_t *ctx = (interpose_trigger_ctx_t *)user;
    sqlite3 *db = NULL;
    int rc;

    (void)point;
    if (ctx == NULL || ctx->fired != 0) {
        return;
    }
    ctx->fired = 1;
    rc = sqlite3_open(ctx->path, &db);
    if (rc != SQLITE_OK) {
        ctx->create_rc = rc;
        if (db != NULL) {
            (void)sqlite3_close(db);
        }
        return;
    }
    (void)sqlite3_busy_timeout(db, 0);
    rc = sqlite3_exec(db,
        "CREATE TRIGGER ninlil_delete_after_insert"
        " AFTER INSERT ON ninlil_kv BEGIN"
        " DELETE FROM ninlil_kv WHERE namespace=NEW.namespace; END;",
        NULL, NULL, NULL);
    ctx->create_rc = rc;
    if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
        ctx->concurrent_busy = 1;
    }
    (void)sqlite3_close(db);
}

static int sqlite_blob_count_equals(
    sqlite3 *db,
    const char *sql,
    int expected)
{
    return sqlite_count_one(db, sql, expected);
}

/*
 * Deterministic schema TOCTOU closure via test-only sqlite3_exec interposition:
 * inject an AFTER INSERT delete trigger immediately before BEGIN IMMEDIATE.
 * Provider must BEGIN, revalidate closed schema, reject before mutation, fence,
 * leave the durable row and trigger object intact, never OK.
 */
static int test_schema_trigger_before_begin_interleave(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    interpose_trigger_ctx_t ctx;
    sqlite3 *db = NULL;
    static const uint8_t ns[] = {0x74u, 0x62u, 0x31u};
    static const uint8_t key_a[] = {0x01u};
    static const uint8_t key_b[] = {0x02u};
    static const uint8_t value[] = {0xa5u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key_a, sizeof(key_a)),
            bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key_b, sizeof(key_b)),
            bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.path = path;
    ninlil_test_persist_interpose_set(
        NINLIL_TEST_PERSIST_POINT_BEFORE_BEGIN,
        interpose_inject_trigger,
        &ctx);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_CORRUPT);
    txn = NULL;
    REQUIRE(ctx.fired == 1);
    REQUIRE(ctx.create_rc == SQLITE_OK);
    REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(storage) == 1);
    ninlil_test_persist_interpose_clear();
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);

    REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
    REQUIRE(sqlite_blob_count_equals(db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'"
        " AND name='ninlil_delete_after_insert';", 1));
    REQUIRE(sqlite_blob_count_equals(db, "SELECT COUNT(*) FROM ninlil_kv;", 1));
    REQUIRE(sqlite3_close(db) == SQLITE_OK);
    remove_db_artifacts(path);
    return 0;
}

/*
 * While the provider holds BEGIN IMMEDIATE, concurrent CREATE TRIGGER must
 * observe BUSY/LOCKED (busy_timeout=0) rather than mutate schema under the
 * write lock. Existing durable data remains after a successful commit.
 */
static int test_schema_trigger_after_begin_busy(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    interpose_trigger_ctx_t ctx;
    sqlite3 *db = NULL;
    static const uint8_t ns[] = {0x74u, 0x62u, 0x32u};
    static const uint8_t key_a[] = {0x01u};
    static const uint8_t key_b[] = {0x02u};
    static const uint8_t value[] = {0xb6u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key_a, sizeof(key_a)),
            bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key_b, sizeof(key_b)),
            bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.path = path;
    ninlil_test_persist_interpose_set(
        NINLIL_TEST_PERSIST_POINT_AFTER_BEGIN,
        interpose_inject_trigger,
        &ctx);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(ctx.fired == 1);
    REQUIRE(ctx.concurrent_busy == 1);
    REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(storage) == 0);
    ninlil_test_persist_interpose_clear();
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);

    REQUIRE(sqlite3_open(path, &db) == SQLITE_OK);
    REQUIRE(sqlite_blob_count_equals(db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger';", 0));
    REQUIRE(sqlite_blob_count_equals(db, "SELECT COUNT(*) FROM ninlil_kv;", 2));
    REQUIRE(sqlite3_close(db) == SQLITE_OK);
    remove_db_artifacts(path);
    return 0;
}

static int durable_kv_count_at_path(const char *path, int expected)
{
    sqlite3 *db = NULL;
    int ok;

    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db != NULL) {
            (void)sqlite3_close(db);
        }
        return 0;
    }
    ok = sqlite_count_one(db, "SELECT COUNT(*) FROM ninlil_kv;", expected);
    (void)sqlite3_close(db);
    return ok;
}

/*
 * Rename+replace the DB pathname at each persist revalidation point via
 * test-only SQLite interposition. Pre-COMMIT points must rollback+fence+CORRUPT
 * with zero OK and no loss of prior durable rows. Post-COMMIT must return
 * COMMIT_UNKNOWN+fence, never OK, with the committed bytes on the original
 * inode.
 */
static int test_path_replacement_at_persist_points(void)
{
    static const struct {
        ninlil_test_persist_point_t point;
        ninlil_storage_status_t expected;
        int expect_post_commit;
    } cases[] = {
        {
            /* After BEGIN IMMEDIATE, before post-BEGIN identity revalidation. */
            NINLIL_TEST_PERSIST_POINT_AFTER_BEGIN,
            NINLIL_STORAGE_CORRUPT,
            0
        },
        {
            /* At DELETE prepare, after pre-mutation identity revalidation. */
            NINLIL_TEST_PERSIST_POINT_BEFORE_MUTATION,
            NINLIL_STORAGE_CORRUPT,
            0
        },
        {
            /*
             * sqlite3_exec("COMMIT") entry is after the last pre-COMMIT
             * identity revalidation; replacement here is only observed
             * post-COMMIT as COMMIT_UNKNOWN (docs/08 narrow window claim).
             */
            NINLIL_TEST_PERSIST_POINT_BEFORE_COMMIT,
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            1
        },
        {
            NINLIL_TEST_PERSIST_POINT_AFTER_COMMIT,
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            1
        }
    };
    size_t index;
    static const uint8_t ns[] = {0x72u, 0x6eu, 0x6du};
    static const uint8_t key_a[] = {0x01u};
    static const uint8_t key_b[] = {0x02u};
    static const uint8_t value_a[] = {0x11u};
    static const uint8_t value_b[] = {0x22u};

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char path[512];
        ninlil_posix_sqlite_storage_config_t config;
        ninlil_posix_sqlite_storage_t *storage;
        const ninlil_storage_ops_t *ops;
        ninlil_storage_handle_t handle = NULL;
        ninlil_storage_txn_t txn = NULL;
        interpose_path_ctx_t ctx;
        ninlil_storage_status_t status;

        REQUIRE(make_temp_path(path, sizeof(path)));
        config = default_config(path);
        storage = ninlil_posix_sqlite_storage_create(&config);
        REQUIRE(storage != NULL);
        ops = ninlil_posix_sqlite_storage_ops(storage);
        REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
                NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
        REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->put(ops->user, txn, bytes(key_a, sizeof(key_a)),
                bytes(value_a, sizeof(value_a))) == NINLIL_STORAGE_OK);
        REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
        txn = NULL;

        REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->put(ops->user, txn, bytes(key_b, sizeof(key_b)),
                bytes(value_b, sizeof(value_b))) == NINLIL_STORAGE_OK);

        (void)memset(&ctx, 0, sizeof(ctx));
        ctx.path = path;
        ninlil_test_persist_interpose_set(
            cases[index].point, interpose_replace_path, &ctx);
        status = ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL);
        txn = NULL;
        REQUIRE(ctx.fired == 1);
        REQUIRE(ctx.replace_rc == 0);
        REQUIRE(status == cases[index].expected);
        REQUIRE(status != NINLIL_STORAGE_OK);
        REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(storage) == 1);
        ninlil_test_persist_interpose_clear();
        ops->close(ops->user, handle);
        ninlil_posix_sqlite_storage_destroy(storage);

        /*
         * Restore the original inode to the live path (WAL siblings stay with
         * the open pathname) and prove durable truth. The empty replacement
         * file at path is never treated as a successful provider write.
         */
        REQUIRE(unlink(path) == 0);
        REQUIRE(rename(ctx.moved_path, path) == 0);
        if (cases[index].expect_post_commit) {
            /* COMMIT linearized on the original inode before detection. */
            REQUIRE(durable_kv_count_at_path(path, 2));
        } else {
            /* Pre-commit rollback: prior durable row only. */
            REQUIRE(durable_kv_count_at_path(path, 1));
        }
        remove_db_artifacts(path);
    }
    return 0;
}

static double elapsed_ms(struct timespec start, struct timespec end)
{
    double seconds = (double)(end.tv_sec - start.tv_sec) * 1000.0;
    double nanos = (double)(end.tv_nsec - start.tv_nsec) / 1000000.0;
    return seconds + nanos;
}

static int test_busy_timeout_narrowing_and_external_lock_timing(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    sqlite3 *external = NULL;
    struct timespec start;
    struct timespec end;
    ninlil_storage_status_t status;
    static const uint8_t ns[] = {0x62u, 0x75u, 0x73u, 0x79u};
    static const uint8_t key[] = {0x01u};
    static const uint8_t value[] = {0x02u};

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    config.busy_timeout_ms = UINT32_MAX;
    REQUIRE(ninlil_posix_sqlite_storage_create(&config) == NULL);

    config.busy_timeout_ms = 120u;
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value))) == NINLIL_STORAGE_OK);

    REQUIRE(sqlite3_open(path, &external) == SQLITE_OK);
    REQUIRE(sqlite3_exec(external, "BEGIN IMMEDIATE;", NULL, NULL, NULL)
        == SQLITE_OK);
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    status = ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL);
    REQUIRE(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    txn = NULL;
    REQUIRE(status == NINLIL_STORAGE_BUSY);
    REQUIRE(elapsed_ms(start, end) >= 70.0);
    REQUIRE(elapsed_ms(start, end) < 1500.0);
    REQUIRE(sqlite3_exec(external, "ROLLBACK;", NULL, NULL, NULL)
        == SQLITE_OK);
    REQUIRE(sqlite3_close(external) == SQLITE_OK);
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);
    remove_db_artifacts(path);
    return 0;
}

static int test_reopen_rejects_over_max_bytes(void)
{
    char path[512];
    ninlil_posix_sqlite_storage_config_t config;
    ninlil_posix_sqlite_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t ns[] = {0xb1u};
    static const uint8_t key[] = {0x01u};
    uint8_t value[32];

    REQUIRE(make_temp_path(path, sizeof(path)));
    config = default_config(path);
    config.max_entries_per_namespace = 8u;
    config.max_bytes_per_namespace = 4096u;
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_posix_sqlite_storage_ops(storage);
    REQUIRE(ops->open(ops->user, bytes(ns, sizeof(ns)),
            NINLIL_STORAGE_SCHEMA_M1A, &handle)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    (void)memset(value, 0x11u, sizeof(value));
    REQUIRE(ops->put(ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, handle);
    ninlil_posix_sqlite_storage_destroy(storage);

    /* 16 + 1 + 32 = 49 logical bytes; reopen with max_bytes=40 must fail. */
    config.max_bytes_per_namespace = 40u;
    storage = ninlil_posix_sqlite_storage_create(&config);
    REQUIRE(storage == NULL);
    remove_db_artifacts(path);
    return 0;
}

/*
 * BUSY clean rollback vs rollback-failure fence via interpose of COMMIT/ROLLBACK
 * results against the production classification path.
 */
static int test_commit_rollback_classification_via_interpose(void)
{
    static const uint8_t ns[] = {0xf1u};
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t key[] = {0x01u};
    static const uint8_t value[] = {0x02u};
    uint8_t out_buf[4];
    ninlil_mut_bytes_t out;

    REQUIRE(fixture.storage != NULL);
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    /* COMMIT fails BUSY, real ROLLBACK succeeds → definite BUSY, no fence. */
    ninlil_test_sqlite_inject_commit(0, SQLITE_BUSY);
    ninlil_test_sqlite_inject_rollback(1, SQLITE_OK);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_BUSY);
    REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(fixture.storage)
        == 0);
    txn = NULL;
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, txn, bytes(key, sizeof(key)),
            &out)
        == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, txn)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(key, sizeof(key)),
            bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    /* COMMIT fails BUSY, ROLLBACK does not clear txn → COMMIT_UNKNOWN + fence. */
    ninlil_test_sqlite_inject_commit(0, SQLITE_BUSY);
    ninlil_test_sqlite_inject_rollback(0, SQLITE_BUSY);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(ninlil_posix_sqlite_storage_connection_fenced(fixture.storage)
        == 1);
    ninlil_test_sqlite_inject_clear();
    close_fixture(&fixture);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        return run_child_mode(argc, argv);
    }
    if (argv == NULL || argv[0] == NULL || argv[0][0] == '\0') {
        return 1;
    }
    test_program_path = argv[0];
    if (test_namespace_isolation_and_lease() != 0) {
        return 1;
    }
    if (test_snapshot_isolation_read_your_writes_and_order() != 0) {
        return 1;
    }
    if (test_buffer_too_small_and_zero_length_value() != 0) {
        return 1;
    }
    if (test_capacity_and_value_bound() != 0) {
        return 1;
    }
    if (test_commit_net_capacity_erase_put_order() != 0) {
        return 1;
    }
    if (test_restart_and_crash_recovery() != 0) {
        return 1;
    }
    if (test_binary_bytes_and_namespace_not_path() != 0) {
        return 1;
    }
    if (test_commit_unknown_truth_via_interpose() != 0) {
        return 1;
    }
    if (test_bad_schema_rejected() != 0) {
        return 1;
    }
    if (test_handle_txn_iterator_consume() != 0) {
        return 1;
    }
    if (test_second_writer_busy() != 0) {
        return 1;
    }
    if (test_db_wide_instance_lease_and_namespace_independence() != 0) {
        return 1;
    }
    if (test_opaque_aba_fail_closed() != 0) {
        return 1;
    }
    if (test_spawned_child_busy_and_clean_close() != 0) {
        return 1;
    }
    if (test_sigkill_dead_owner_reopen() != 0) {
        return 1;
    }
    if (test_stale_writer_fence_after_crash_sim() != 0) {
        return 1;
    }
    if (test_pure_generation_and_lease_token_no_wrap() != 0) {
        return 1;
    }

    if (test_path_alias_hardlink_lease_convergence() != 0) {
        return 1;
    }
    if (test_sidecar_and_db_path_replacement_fail_closed() != 0) {
        return 1;
    }
    if (test_sidecar_owner_and_mode_policy() != 0) {
        return 1;
    }
    if (test_bad_schema_text_version_and_partial_meta() != 0) {
        return 1;
    }
    if (test_strict_schema_and_legacy_rejection_matrix() != 0) {
        return 1;
    }
    if (test_closed_schema_objects_and_trigger_fence() != 0) {
        return 1;
    }
    if (test_schema_trigger_before_begin_interleave() != 0) {
        return 1;
    }
    if (test_schema_trigger_after_begin_busy() != 0) {
        return 1;
    }
    if (test_path_replacement_at_persist_points() != 0) {
        return 1;
    }
    if (test_busy_timeout_narrowing_and_external_lock_timing() != 0) {
        return 1;
    }
    if (test_reopen_rejects_over_max_bytes() != 0) {
        return 1;
    }
    if (test_commit_rollback_classification_via_interpose() != 0) {
        return 1;
    }
    return 0;
}
