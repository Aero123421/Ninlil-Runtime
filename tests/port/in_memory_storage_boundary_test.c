#include "in_memory_storage.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",       \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct boundary_fixture {
    ninlil_test_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle;
} boundary_fixture_t;

static ninlil_bytes_view_t view(const void *data, uint32_t length)
{
    ninlil_bytes_view_t result;
    result.data = (const uint8_t *)data;
    result.length = length;
    return result;
}

static ninlil_mut_bytes_t output(void *data, uint32_t capacity)
{
    ninlil_mut_bytes_t result;
    result.data = (uint8_t *)data;
    result.capacity = capacity;
    result.length = 0u;
    return result;
}

static ninlil_test_storage_t *create_storage(
    uint64_t max_entries,
    uint64_t max_bytes)
{
    ninlil_test_storage_config_t config;
    config.max_namespaces = 16u;
    config.max_entries_per_namespace = max_entries;
    config.max_bytes_per_namespace = max_bytes;
    return ninlil_test_storage_create(&config);
}

static boundary_fixture_t create_fixture(
    uint64_t max_entries,
    uint64_t max_bytes)
{
    boundary_fixture_t fixture;
    static const uint8_t name[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x00u};

    (void)memset(&fixture, 0, sizeof(fixture));
    fixture.storage = create_storage(max_entries, max_bytes);
    if (fixture.storage == NULL) {
        return fixture;
    }
    fixture.ops = ninlil_test_storage_ops(fixture.storage);
    if (fixture.ops->open(fixture.ops->user, view(name, sizeof(name)),
            NINLIL_STORAGE_SCHEMA_M1A, &fixture.handle)
        != NINLIL_STORAGE_OK) {
        ninlil_test_storage_destroy(fixture.storage);
        (void)memset(&fixture, 0, sizeof(fixture));
    }
    return fixture;
}

static void destroy_fixture(boundary_fixture_t *fixture)
{
    if (fixture->handle != NULL) {
        fixture->ops->close(fixture->ops->user, fixture->handle);
    }
    ninlil_test_storage_destroy(fixture->storage);
    (void)memset(fixture, 0, sizeof(*fixture));
}

static ninlil_storage_txn_t begin(
    boundary_fixture_t *fixture,
    ninlil_storage_mode_t mode)
{
    ninlil_storage_txn_t transaction = NULL;
    if (fixture->ops->begin(fixture->ops->user, fixture->handle,
            mode, &transaction) != NINLIL_STORAGE_OK) {
        return NULL;
    }
    return transaction;
}

static int successful_trace_ids_are_monotonic(
    const ninlil_test_storage_t *storage)
{
    uint64_t last_handle = 0u;
    uint64_t last_transaction = 0u;
    uint64_t last_iterator = 0u;
    size_t index;

    for (index = 0u; index < ninlil_test_storage_trace_count(storage); ++index) {
        const ninlil_test_storage_trace_record_t *record =
            ninlil_test_storage_trace_at(storage, index);
        if (record == NULL || record->status != NINLIL_STORAGE_OK) {
            continue;
        }
        if (record->operation == NINLIL_TEST_STORAGE_OP_OPEN) {
            if (record->handle_id <= last_handle) {
                return 0;
            }
            last_handle = record->handle_id;
        } else if (record->operation == NINLIL_TEST_STORAGE_OP_BEGIN) {
            if (record->transaction_id <= last_transaction) {
                return 0;
            }
            last_transaction = record->transaction_id;
        } else if (record->operation == NINLIL_TEST_STORAGE_OP_ITER_OPEN) {
            if (record->iterator_id <= last_iterator) {
                return 0;
            }
            last_iterator = record->iterator_id;
        }
    }
    return last_handle != 0u && last_transaction != 0u && last_iterator != 0u;
}

static int test_namespace_boundaries_and_copy(void)
{
    ninlil_test_storage_t *storage = create_storage(8u, 1000000u);
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_handle_t second = NULL;
    ninlil_storage_handle_t upper = NULL;
    ninlil_storage_handle_t lower = NULL;
    ninlil_storage_handle_t short_name = NULL;
    ninlil_storage_handle_t nul_name = NULL;
    uint8_t caller_name[255];
    uint8_t exact_name[255];
    uint8_t too_long[256];
    uint8_t non_null_zero = 0u;
    static const uint8_t upper_name[] = {'A'};
    static const uint8_t lower_name[] = {'a'};
    static const uint8_t short_bytes[] = {'x'};
    static const uint8_t nul_bytes[] = {'x', 0u};
    size_t index;

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    for (index = 0u; index < sizeof(caller_name); ++index) {
        caller_name[index] = (uint8_t)index;
    }
    (void)memcpy(exact_name, caller_name, sizeof(exact_name));
    (void)memset(too_long, 0x5a, sizeof(too_long));
    REQUIRE(ops->open(ops->user, view(NULL, 0u),
        NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(handle == NULL);
    REQUIRE(ops->open(ops->user, view(&non_null_zero, 0u),
        NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(ops->open(ops->user, view(NULL, 1u),
        NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(ops->open(ops->user, view(too_long, sizeof(too_long)),
        NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(ops->open(ops->user, view(caller_name, sizeof(caller_name)),
        NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
    (void)memset(caller_name, 0xee, sizeof(caller_name));
    REQUIRE(ops->open(ops->user, view(exact_name, sizeof(exact_name)),
        NINLIL_STORAGE_SCHEMA_M1A, &second) == NINLIL_STORAGE_BUSY);
    REQUIRE(second == NULL);
    ops->close(ops->user, handle);
    handle = NULL;
    REQUIRE(ops->open(ops->user, view(exact_name, sizeof(exact_name)),
        NINLIL_STORAGE_SCHEMA_M1A, &handle) == NINLIL_STORAGE_OK);
    ops->close(ops->user, handle);
    handle = NULL;
    REQUIRE(ops->open(ops->user, view(upper_name, sizeof(upper_name)),
        NINLIL_STORAGE_SCHEMA_M1A, &upper) == NINLIL_STORAGE_OK);
    REQUIRE(ops->open(ops->user, view(lower_name, sizeof(lower_name)),
        NINLIL_STORAGE_SCHEMA_M1A, &lower) == NINLIL_STORAGE_OK);
    REQUIRE(ops->open(ops->user, view(short_bytes, sizeof(short_bytes)),
        NINLIL_STORAGE_SCHEMA_M1A, &short_name) == NINLIL_STORAGE_OK);
    REQUIRE(ops->open(ops->user, view(nul_bytes, sizeof(nul_bytes)),
        NINLIL_STORAGE_SCHEMA_M1A, &nul_name) == NINLIL_STORAGE_OK);
    REQUIRE(upper != lower && short_name != nul_name);
    ops->close(ops->user, upper);
    ops->close(ops->user, lower);
    ops->close(ops->user, short_name);
    ops->close(ops->user, nul_name);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_key_value_prefix_boundaries_and_copy(void)
{
    boundary_fixture_t fixture = create_fixture(16u, 2000000u);
    ninlil_storage_txn_t writer;
    ninlil_storage_txn_t reader;
    ninlil_storage_iter_t iterator = NULL;
    uint8_t key255[255];
    uint8_t key255_exact[255];
    uint8_t key256[256];
    uint8_t prefix255[255];
    uint8_t value_data[3] = {1u, 2u, 3u};
    uint8_t read_data[8] = {0u};
    uint8_t key_data[255];
    uint8_t non_null_zero = 0u;
    static const uint8_t key_one_exact[] = {'k'};
    uint8_t key_one_caller[] = {'k'};
    ninlil_mut_bytes_t read_output;
    ninlil_mut_bytes_t key_output;
    ninlil_mut_bytes_t value_output;
    size_t index;

    REQUIRE(fixture.storage != NULL);
    for (index = 0u; index < sizeof(key255); ++index) {
        key255[index] = (uint8_t)(index + 1u);
    }
    (void)memcpy(key255_exact, key255, sizeof(key255_exact));
    (void)memset(key256, 0x5a, sizeof(key256));
    writer = begin(&fixture, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(writer != NULL);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(NULL, 0u), view(NULL, 0u)) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(&non_null_zero, 0u), view(NULL, 0u)) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(NULL, 1u), view(NULL, 0u)) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(key256, sizeof(key256)), view(NULL, 0u))
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(key_one_caller, sizeof(key_one_caller)),
        view(&non_null_zero, 0u)) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(key_one_caller, sizeof(key_one_caller)),
        view(NULL, 1u)) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(key_one_caller, sizeof(key_one_caller)),
        view(value_data, sizeof(value_data))) == NINLIL_STORAGE_OK);
    key_one_caller[0] = 'z';
    (void)memset(value_data, 9, sizeof(value_data));
    read_output = output(read_data, sizeof(read_data));
    REQUIRE(fixture.ops->get(fixture.ops->user, writer,
        view(key_one_exact, sizeof(key_one_exact)), &read_output)
        == NINLIL_STORAGE_OK);
    REQUIRE(read_output.length == 3u
        && read_data[0] == 1u && read_data[1] == 2u && read_data[2] == 3u);
    REQUIRE(fixture.ops->put(fixture.ops->user, writer,
        view(key255, sizeof(key255)), view(NULL, 0u)) == NINLIL_STORAGE_OK);
    (void)memset(key255, 0xee, sizeof(key255));
    REQUIRE(fixture.ops->commit(fixture.ops->user, writer,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_OK);
    reader = begin(&fixture, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(reader != NULL);
    read_output = output(read_data, sizeof(read_data));
    REQUIRE(fixture.ops->get(fixture.ops->user, reader,
        view(key_one_exact, sizeof(key_one_exact)), &read_output)
        == NINLIL_STORAGE_OK);
    REQUIRE(read_output.length == 3u
        && read_data[0] == 1u && read_data[1] == 2u && read_data[2] == 3u);
    read_output = output(NULL, 0u);
    REQUIRE(fixture.ops->get(fixture.ops->user, reader,
        view(key255_exact, sizeof(key255_exact)), &read_output)
        == NINLIL_STORAGE_OK);
    (void)memcpy(prefix255, key255_exact, sizeof(prefix255));
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, reader,
        view(key256, sizeof(key256)), &iterator) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(iterator == NULL);
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, reader,
        view(&non_null_zero, 0u), &iterator) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, reader,
        view(NULL, 1u), &iterator) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, reader,
        view(prefix255, sizeof(prefix255)), &iterator) == NINLIL_STORAGE_OK);
    (void)memset(prefix255, 0, sizeof(prefix255));
    key_output = output(key_data, sizeof(key_data));
    value_output = output(NULL, 0u);
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, iterator,
        &key_output, &value_output) == NINLIL_STORAGE_OK);
    REQUIRE(key_output.length == 255u
        && memcmp(key_data, key255_exact, sizeof(key255_exact)) == 0);
    fixture.ops->iter_close(fixture.ops->user, iterator);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, reader)
        == NINLIL_STORAGE_OK);
    destroy_fixture(&fixture);
    return 0;
}

static int test_capacity_fault_shapes_and_strict_fault_registration(void)
{
    boundary_fixture_t fixture = create_fixture(8u, 4096u);
    ninlil_storage_capacity_t capacity;
    ninlil_storage_status_t statuses[] = {
        NINLIL_STORAGE_BUSY,
        NINLIL_STORAGE_IO_ERROR,
        NINLIL_STORAGE_CORRUPT,
        (ninlil_storage_status_t)999u
    };
    size_t index;

    REQUIRE(fixture.storage != NULL);
    REQUIRE(!ninlil_test_storage_fault_next(fixture.storage,
        NINLIL_TEST_STORAGE_OP_GET, NINLIL_STORAGE_OK));
    REQUIRE(!ninlil_test_storage_fault_next(fixture.storage,
        NINLIL_TEST_STORAGE_OP_GET, NINLIL_STORAGE_NOT_FOUND));
    REQUIRE(!ninlil_test_storage_fault_next(fixture.storage,
        NINLIL_TEST_STORAGE_OP_GET, NINLIL_STORAGE_BUFFER_TOO_SMALL));
    REQUIRE(!ninlil_test_storage_fault_enqueue(fixture.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 2, 0));
    REQUIRE(!ninlil_test_storage_fault_enqueue(fixture.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 2));
    REQUIRE(!ninlil_test_storage_fault_enqueue(fixture.storage,
        NINLIL_TEST_STORAGE_OP_GET, NINLIL_STORAGE_BUSY, 1u, 1, 1));
    REQUIRE(!ninlil_test_storage_fault_enqueue(fixture.storage,
        NINLIL_TEST_STORAGE_OP_GET, NINLIL_STORAGE_BUSY, 1u, 0, 1));
    REQUIRE(ninlil_test_storage_fault_next(fixture.storage,
        NINLIL_TEST_STORAGE_OP_CAPACITY, NINLIL_STORAGE_BUSY));
    (void)memset(&capacity, 0x5a, sizeof(capacity));
    capacity.abi_version = 0u;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    REQUIRE(fixture.ops->capacity(fixture.ops->user, fixture.handle,
        &capacity) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(capacity.max_entries == UINT64_C(0x5a5a5a5a5a5a5a5a));
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    REQUIRE(fixture.ops->capacity(fixture.ops->user, fixture.handle,
        &capacity) == NINLIL_STORAGE_BUSY);
    REQUIRE(capacity.abi_version == NINLIL_ABI_VERSION
        && capacity.struct_size == sizeof(capacity)
        && capacity.max_entries == 0u && capacity.used_entries == 0u
        && capacity.max_bytes == 0u && capacity.used_bytes == 0u);
    for (index = 1u; index < sizeof(statuses) / sizeof(statuses[0]); ++index) {
        REQUIRE(ninlil_test_storage_fault_next(fixture.storage,
            NINLIL_TEST_STORAGE_OP_CAPACITY, statuses[index]));
        (void)memset(&capacity, 0, sizeof(capacity));
        capacity.abi_version = NINLIL_ABI_VERSION;
        capacity.struct_size = (uint16_t)sizeof(capacity);
        REQUIRE(fixture.ops->capacity(fixture.ops->user, fixture.handle,
            &capacity) == statuses[index]);
        REQUIRE(capacity.abi_version == NINLIL_ABI_VERSION
            && capacity.struct_size == sizeof(capacity)
            && capacity.max_entries == 0u && capacity.used_entries == 0u
            && capacity.max_bytes == 0u && capacity.used_bytes == 0u);
    }
    destroy_fixture(&fixture);
    return 0;
}

static int test_commit_capacity_precedes_unknown_fault(void)
{
    boundary_fixture_t fixture = create_fixture(1u, 4096u);
    ninlil_storage_txn_t transaction;
    ninlil_storage_txn_t reader;
    static const uint8_t key_a[] = {'a'};
    static const uint8_t key_b[] = {'b'};
    static const uint8_t value[] = {1u};
    uint8_t read_data[2];
    ninlil_mut_bytes_t read_output;

    REQUIRE(fixture.storage != NULL);
    transaction = begin(&fixture, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(transaction != NULL);
    REQUIRE(fixture.ops->put(fixture.ops->user, transaction,
        view(key_a, sizeof(key_a)), view(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->put(fixture.ops->user, transaction,
        view(key_b, sizeof(key_b)), view(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_test_storage_fault_enqueue(fixture.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 1));
    REQUIRE(fixture.ops->commit(fixture.ops->user, transaction,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_NO_SPACE);
    transaction = begin(&fixture, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(transaction != NULL);
    REQUIRE(fixture.ops->put(fixture.ops->user, transaction,
        view(key_a, sizeof(key_a)), view(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->commit(fixture.ops->user, transaction,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_COMMIT_UNKNOWN);
    ninlil_test_storage_simulate_crash(fixture.storage);
    fixture.handle = NULL;
    {
        static const uint8_t name[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x00u};
        REQUIRE(fixture.ops->open(fixture.ops->user, view(name, sizeof(name)),
            NINLIL_STORAGE_SCHEMA_M1A, &fixture.handle) == NINLIL_STORAGE_OK);
    }
    reader = begin(&fixture, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(reader != NULL);
    read_output = output(read_data, sizeof(read_data));
    REQUIRE(fixture.ops->get(fixture.ops->user, reader,
        view(key_a, sizeof(key_a)), &read_output) == NINLIL_STORAGE_OK);
    read_output = output(read_data, sizeof(read_data));
    REQUIRE(fixture.ops->get(fixture.ops->user, reader,
        view(key_b, sizeof(key_b)), &read_output) == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, reader)
        == NINLIL_STORAGE_OK);
    destroy_fixture(&fixture);
    return 0;
}

static int test_stale_tokens_and_overlap(void)
{
    boundary_fixture_t fixture = create_fixture(8u, 4096u);
    ninlil_storage_handle_t stale_handle;
    ninlil_storage_handle_t current_handle = NULL;
    ninlil_storage_txn_t stale_transaction;
    ninlil_storage_txn_t current_transaction;
    ninlil_storage_txn_t after_crash_transaction = NULL;
    ninlil_storage_iter_t stale_iterator = NULL;
    ninlil_storage_iter_t current_iterator = NULL;
    ninlil_storage_iter_t second_iterator = NULL;
    static const uint8_t name[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x00u};
    static const uint8_t key[] = {'k'};
    static const uint8_t value[] = {1u};
    uint8_t shared[8];
    ninlil_mut_bytes_t key_output;
    ninlil_mut_bytes_t value_output;

    REQUIRE(fixture.storage != NULL);
    stale_handle = fixture.handle;
    fixture.ops->close(fixture.ops->user, stale_handle);
    fixture.handle = NULL;
    REQUIRE(fixture.ops->open(fixture.ops->user, view(name, sizeof(name)),
        NINLIL_STORAGE_SCHEMA_M1A, &current_handle) == NINLIL_STORAGE_OK);
    REQUIRE(current_handle != stale_handle);
    REQUIRE(fixture.ops->begin(fixture.ops->user, stale_handle,
        NINLIL_STORAGE_READ_ONLY, &after_crash_transaction)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(after_crash_transaction == NULL);
    fixture.handle = current_handle;
    stale_transaction = begin(&fixture, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(stale_transaction != NULL);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, stale_transaction)
        == NINLIL_STORAGE_OK);
    current_transaction = begin(&fixture, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(current_transaction != NULL && current_transaction != stale_transaction);
    key_output = output(shared, sizeof(shared));
    REQUIRE(fixture.ops->get(fixture.ops->user, stale_transaction,
        view(key, sizeof(key)), &key_output) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(fixture.ops->put(fixture.ops->user, current_transaction,
        view(key, sizeof(key)), view(value, sizeof(value))) == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, current_transaction,
        view(NULL, 0u), &stale_iterator) == NINLIL_STORAGE_OK);
    fixture.ops->iter_close(fixture.ops->user, stale_iterator);
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, current_transaction,
        view(NULL, 0u), &current_iterator) == NINLIL_STORAGE_OK);
    REQUIRE(fixture.ops->iter_open(fixture.ops->user, current_transaction,
        view(NULL, 0u), &second_iterator) == NINLIL_STORAGE_OK);
    REQUIRE(current_iterator != stale_iterator && second_iterator != stale_iterator);
    key_output = output(shared, 4u);
    value_output = output(shared + 2u, 4u);
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, current_iterator,
        &key_output, &value_output) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(key_output.length == 0u && value_output.length == 0u);
    key_output = output(shared, 4u);
    value_output = output(shared, 4u);
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, current_iterator,
        &key_output, &value_output) == NINLIL_STORAGE_CORRUPT);
    key_output = output(shared, 4u);
    value_output = output(shared + 4u, 4u);
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, stale_iterator,
        &key_output, &value_output) == NINLIL_STORAGE_CORRUPT);
    key_output = output(shared, 4u);
    value_output = output(shared + 4u, 4u);
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, current_iterator,
        &key_output, &value_output) == NINLIL_STORAGE_OK);
    ninlil_test_storage_simulate_crash(fixture.storage);
    fixture.handle = NULL;
    REQUIRE(fixture.ops->open(fixture.ops->user, view(name, sizeof(name)),
        NINLIL_STORAGE_SCHEMA_M1A, &fixture.handle) == NINLIL_STORAGE_OK);
    REQUIRE(fixture.handle != current_handle && fixture.handle != stale_handle);
    REQUIRE(fixture.ops->begin(fixture.ops->user, current_handle,
        NINLIL_STORAGE_READ_ONLY, &after_crash_transaction)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(after_crash_transaction == NULL);
    key_output = output(shared, sizeof(shared));
    REQUIRE(fixture.ops->get(fixture.ops->user, current_transaction,
        view(key, sizeof(key)), &key_output) == NINLIL_STORAGE_CORRUPT);
    key_output = output(shared, sizeof(shared));
    value_output = output(NULL, 0u);
    REQUIRE(fixture.ops->iter_next(fixture.ops->user, second_iterator,
        &key_output, &value_output) == NINLIL_STORAGE_CORRUPT);
    after_crash_transaction = begin(&fixture, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(after_crash_transaction != NULL
        && after_crash_transaction != current_transaction
        && after_crash_transaction != stale_transaction);
    REQUIRE(fixture.ops->rollback(fixture.ops->user, after_crash_transaction)
        == NINLIL_STORAGE_OK);
    REQUIRE(successful_trace_ids_are_monotonic(fixture.storage));
    destroy_fixture(&fixture);
    return 0;
}

int main(void)
{
    if (test_namespace_boundaries_and_copy() != 0
        || test_key_value_prefix_boundaries_and_copy() != 0
        || test_capacity_fault_shapes_and_strict_fault_registration() != 0
        || test_commit_capacity_precedes_unknown_fault() != 0
        || test_stale_tokens_and_overlap() != 0) {
        return 1;
    }
    return 0;
}
