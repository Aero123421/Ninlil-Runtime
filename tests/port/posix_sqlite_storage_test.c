#include "ninlil_posix_sqlite_storage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    static unsigned counter = 0u;
    const char *tmpdir = getenv("TMPDIR");
    int written;

    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    counter += 1u;
    written = snprintf(
        out,
        out_size,
        "%s/ninlil-sqlite-%lu-%u.db",
        tmpdir,
        (unsigned long)time(NULL),
        counter);
    return written > 0 && (size_t)written < out_size;
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

static void close_fixture(fixture_t *fixture)
{
    if (fixture->ops != NULL && fixture->handle != NULL) {
        fixture->ops->close(fixture->ops->user, fixture->handle);
    }
    ninlil_posix_sqlite_storage_destroy(fixture->storage);
    if (fixture->path[0] != '\0') {
        (void)remove(fixture->path);
        {
            char wal[640];
            char shm[640];
            (void)snprintf(wal, sizeof(wal), "%s-wal", fixture->path);
            (void)snprintf(shm, sizeof(shm), "%s-shm", fixture->path);
            (void)remove(wal);
            (void)remove(shm);
        }
    }
    (void)memset(fixture, 0, sizeof(*fixture));
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
    (void)remove(path);
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
    REQUIRE(fixture.ops->put(fixture.ops->user, txn, bytes(k3, sizeof(k3)),
            bytes(v, sizeof(v)))
        == NINLIL_STORAGE_NO_SPACE);
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
    (void)remove(path);
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

static int test_commit_fault_unknown_matrix(void)
{
    static const uint8_t ns[] = {0xf0u};
    fixture_t fixture = open_fixture(8u, 4096u, ns, sizeof(ns));
    ninlil_storage_txn_t txn = NULL;
    uint8_t out_buf[4];
    ninlil_mut_bytes_t out;
    static const uint8_t key_c[] = {0xc0u};
    static const uint8_t key_n[] = {0xc1u};
    static const uint8_t value[] = {0x01u};

    REQUIRE(fixture.storage != NULL);

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn,
            bytes(key_c, sizeof(key_c)), bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    ninlil_posix_sqlite_storage_set_commit_fault(
        fixture.storage,
        NINLIL_POSIX_SQLITE_COMMIT_FAULT_UNKNOWN_COMMITTED);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    txn = NULL;
    REQUIRE(ninlil_posix_sqlite_storage_live_transactions(fixture.storage)
        == 0u);

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, txn,
            bytes(key_c, sizeof(key_c)), &out)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, txn)
        == NINLIL_STORAGE_OK);
    txn = NULL;

    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, txn,
            bytes(key_n, sizeof(key_n)), bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    ninlil_posix_sqlite_storage_set_commit_fault(
        fixture.storage,
        NINLIL_POSIX_SQLITE_COMMIT_FAULT_UNKNOWN_NOT_COMMITTED);
    REQUIRE(fixture.ops->commit(fixture.ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    txn = NULL;
    REQUIRE(fixture.ops->begin(fixture.ops->user, fixture.handle,
            NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(out_buf, sizeof(out_buf));
    REQUIRE(fixture.ops->get(fixture.ops->user, txn,
            bytes(key_n, sizeof(key_n)), &out)
        == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, txn)
        == NINLIL_STORAGE_OK);
    close_fixture(&fixture);
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
    (void)remove(path);
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

int main(void)
{
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
    if (test_restart_and_crash_recovery() != 0) {
        return 1;
    }
    if (test_binary_bytes_and_namespace_not_path() != 0) {
        return 1;
    }
    if (test_commit_fault_unknown_matrix() != 0) {
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
    return 0;
}
