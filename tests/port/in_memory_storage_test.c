#include "in_memory_storage.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",       \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct fixture_context {
    ninlil_test_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle;
} fixture_context_t;

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

static fixture_context_t make_fixture(uint64_t entries, uint64_t bytes_limit)
{
    fixture_context_t context;
    ninlil_test_storage_config_t config;
    static const uint8_t name[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x00u};

    (void)memset(&context, 0, sizeof(context));
    config.max_namespaces = 8u;
    config.max_entries_per_namespace = entries;
    config.max_bytes_per_namespace = bytes_limit;
    context.storage = ninlil_test_storage_create(&config);
    if (context.storage == NULL) {
        return context;
    }
    context.ops = ninlil_test_storage_ops(context.storage);
    if (context.ops->open(context.ops->user, bytes(name, sizeof(name)),
            NINLIL_STORAGE_SCHEMA_M1A, &context.handle)
        != NINLIL_STORAGE_OK) {
        ninlil_test_storage_destroy(context.storage);
        (void)memset(&context, 0, sizeof(context));
    }
    return context;
}

static void destroy_fixture(fixture_context_t *context)
{
    if (context->handle != NULL) {
        context->ops->close(context->ops->user, context->handle);
    }
    ninlil_test_storage_destroy(context->storage);
    (void)memset(context, 0, sizeof(*context));
}

static ninlil_storage_txn_t begin_txn(
    fixture_context_t *context,
    ninlil_storage_mode_t mode)
{
    ninlil_storage_txn_t transaction = NULL;
    if (context->ops->begin(context->ops->user, context->handle,
            mode, &transaction) != NINLIL_STORAGE_OK) {
        return NULL;
    }
    return transaction;
}

static int put_value(
    fixture_context_t *context,
    ninlil_storage_txn_t transaction,
    const void *key,
    uint32_t key_length,
    const void *value,
    uint32_t value_length)
{
    return context->ops->put(context->ops->user, transaction,
        bytes(key, key_length), bytes(value, value_length))
        == NINLIL_STORAGE_OK;
}

static int get_status(
    fixture_context_t *context,
    ninlil_storage_txn_t transaction,
    const void *key,
    uint32_t key_length,
    ninlil_mut_bytes_t *output,
    ninlil_storage_status_t expected)
{
    return context->ops->get(context->ops->user, transaction,
        bytes(key, key_length), output) == expected;
}

static int commit_txn(
    fixture_context_t *context,
    ninlil_storage_txn_t transaction)
{
    return context->ops->commit(context->ops->user, transaction,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_OK;
}

static int test_configuration_namespace_lease_and_crash(void)
{
    ninlil_test_storage_config_t config = {2u, 8u, 4096u};
    ninlil_test_storage_t *storage;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t first = NULL;
    ninlil_storage_handle_t second = NULL;
    ninlil_storage_handle_t distinct = NULL;
    static const uint8_t ns1[] = {0x00u};
    static const uint8_t ns2[] = {0x00u, 0x00u};

    config.max_namespaces = 0u;
    REQUIRE(ninlil_test_storage_create(&config) == NULL);
    config.max_namespaces = 2u;
    config.max_entries_per_namespace = UINT64_MAX;
    REQUIRE(ninlil_test_storage_create(&config) == NULL);
    config.max_entries_per_namespace = 8u;
    storage = ninlil_test_storage_create(&config);
    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    REQUIRE(ops != NULL);
    REQUIRE(ops->open(ops->user, bytes(ns1, sizeof(ns1)),
        0u, &first) == NINLIL_STORAGE_UNSUPPORTED_SCHEMA);
    REQUIRE(first == NULL);
    REQUIRE(ops->open(ops->user, bytes(ns1, sizeof(ns1)),
        NINLIL_STORAGE_SCHEMA_M1A, &first) == NINLIL_STORAGE_OK);
    REQUIRE(first != NULL);
    REQUIRE(ops->open(ops->user, bytes(ns1, sizeof(ns1)),
        NINLIL_STORAGE_SCHEMA_M1A, &second) == NINLIL_STORAGE_BUSY);
    REQUIRE(second == NULL);
    REQUIRE(ops->open(ops->user, bytes(ns2, sizeof(ns2)),
        NINLIL_STORAGE_SCHEMA_M1A, &distinct) == NINLIL_STORAGE_OK);
    REQUIRE(distinct != NULL);
    ops->close(ops->user, distinct);
    REQUIRE(ninlil_test_storage_fault_next(storage,
        NINLIL_TEST_STORAGE_OP_OPEN, NINLIL_STORAGE_COMMIT_UNKNOWN));
    REQUIRE(ops->open(ops->user, bytes(ns1, sizeof(ns1)),
        NINLIL_STORAGE_SCHEMA_M1A, &second)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(second == NULL);
    ninlil_test_storage_simulate_crash(storage);
    REQUIRE(ninlil_test_storage_live_handles(storage) == 0u);
    first = NULL;
    REQUIRE(ops->open(ops->user, bytes(ns1, sizeof(ns1)),
        NINLIL_STORAGE_SCHEMA_M1A, &first) == NINLIL_STORAGE_OK);
    ops->close(ops->user, first);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_transaction_snapshots_and_lifecycle(void)
{
    fixture_context_t context = make_fixture(16u, 1000000u);
    ninlil_storage_txn_t ro1;
    ninlil_storage_txn_t ro2;
    ninlil_storage_txn_t writer;
    ninlil_storage_txn_t duplicate_writer = NULL;
    ninlil_storage_txn_t fresh;
    ninlil_storage_iter_t iterator = NULL;
    static const uint8_t key_a[] = {'a'};
    static const uint8_t key_b[] = {'b'};
    static const uint8_t one[] = {1u};
    uint8_t output_data[4] = {0xaau, 0xaau, 0xaau, 0xaau};
    ninlil_mut_bytes_t output;

    REQUIRE(context.storage != NULL);
    ro1 = begin_txn(&context, NINLIL_STORAGE_READ_ONLY);
    writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    ro2 = begin_txn(&context, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(ro1 != NULL && writer != NULL && ro2 != NULL);
    REQUIRE(context.ops->begin(context.ops->user, context.handle,
        NINLIL_STORAGE_READ_WRITE, &duplicate_writer) == NINLIL_STORAGE_BUSY);
    REQUIRE(duplicate_writer == NULL);
    REQUIRE(put_value(&context, writer, key_a, sizeof(key_a), one, sizeof(one)));
    output = mut(output_data, sizeof(output_data));
    REQUIRE(get_status(&context, writer, key_a, sizeof(key_a),
        &output, NINLIL_STORAGE_OK));
    REQUIRE(output.length == 1u && output_data[0] == 1u);
    output = mut(output_data, sizeof(output_data));
    REQUIRE(get_status(&context, ro1, key_a, sizeof(key_a),
        &output, NINLIL_STORAGE_NOT_FOUND));
    REQUIRE(context.ops->iter_open(context.ops->user, writer,
        bytes(NULL, 0u), &iterator) == NINLIL_STORAGE_OK);
    REQUIRE(put_value(&context, writer, key_b, sizeof(key_b), one, sizeof(one)));
    REQUIRE(commit_txn(&context, writer));
    REQUIRE(ninlil_test_storage_live_iterators(context.storage) == 0u);
    output = mut(output_data, sizeof(output_data));
    REQUIRE(get_status(&context, ro2, key_b, sizeof(key_b),
        &output, NINLIL_STORAGE_NOT_FOUND));
    REQUIRE(commit_txn(&context, ro1));
    REQUIRE(context.ops->rollback(context.ops->user, ro2) == NINLIL_STORAGE_OK);
    fresh = begin_txn(&context, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(fresh != NULL);
    output = mut(output_data, sizeof(output_data));
    REQUIRE(get_status(&context, fresh, key_b, sizeof(key_b),
        &output, NINLIL_STORAGE_OK));
    REQUIRE(ninlil_test_storage_fault_next(context.storage,
        NINLIL_TEST_STORAGE_OP_PUT, NINLIL_STORAGE_IO_ERROR));
    REQUIRE(context.ops->put(context.ops->user, fresh,
        bytes(key_a, sizeof(key_a)), bytes(one, sizeof(one)))
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(context.ops->commit(context.ops->user, fresh,
        NINLIL_DURABILITY_VOLATILE) == NINLIL_STORAGE_CORRUPT);
    duplicate_writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(duplicate_writer != NULL);
    REQUIRE(context.ops->put(context.ops->user, duplicate_writer,
        bytes(key_a, sizeof(key_a)), bytes(one, sizeof(one)))
        == NINLIL_STORAGE_IO_ERROR);
    REQUIRE(context.ops->rollback(context.ops->user, duplicate_writer)
        == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_test_storage_live_transactions(context.storage) == 0u);
    destroy_fixture(&context);
    return 0;
}

static int test_mutable_buffers_mb1_to_mb6(void)
{
    fixture_context_t context = make_fixture(16u, 1000000u);
    ninlil_storage_txn_t writer;
    ninlil_storage_txn_t reader;
    static const uint8_t zero_key[] = {'z'};
    static const uint8_t small_key[] = {'s'};
    static const uint8_t value[] = {1u, 2u, 3u, 4u, 5u};
    static const uint8_t missing[] = {'m'};
    uint8_t data[8];
    ninlil_mut_bytes_t output;
    size_t index;
    ninlil_storage_status_t errors[] = {
        NINLIL_STORAGE_BUSY,
        NINLIL_STORAGE_IO_ERROR,
        NINLIL_STORAGE_CORRUPT
    };

    REQUIRE(context.storage != NULL);
    writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(writer != NULL);
    REQUIRE(put_value(&context, writer, zero_key, sizeof(zero_key), NULL, 0u));
    REQUIRE(put_value(&context, writer, small_key, sizeof(small_key),
        value, sizeof(value)));
    REQUIRE(commit_txn(&context, writer));
    reader = begin_txn(&context, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(reader != NULL);
    output = mut(NULL, 0u);
    REQUIRE(get_status(&context, reader, zero_key, sizeof(zero_key),
        &output, NINLIL_STORAGE_OK));
    REQUIRE(output.length == 0u);
    (void)memset(data, 0xaa, sizeof(data));
    output = mut(data, sizeof(data));
    REQUIRE(get_status(&context, reader, small_key, sizeof(small_key),
        &output, NINLIL_STORAGE_OK));
    REQUIRE(output.length == sizeof(value));
    REQUIRE(memcmp(data, value, sizeof(value)) == 0);
    REQUIRE(data[5] == 0xaau && data[7] == 0xaau);
    (void)memset(data, 0xaa, sizeof(data));
    output = mut(data, 4u);
    REQUIRE(get_status(&context, reader, small_key, sizeof(small_key),
        &output, NINLIL_STORAGE_BUFFER_TOO_SMALL));
    REQUIRE(output.length == sizeof(value));
    REQUIRE(data[0] == 0xaau && data[3] == 0xaau);
    output = mut(data, sizeof(data));
    REQUIRE(get_status(&context, reader, missing, sizeof(missing),
        &output, NINLIL_STORAGE_NOT_FOUND));
    REQUIRE(output.length == 0u && data[0] == 0xaau);
    for (index = 0u; index < sizeof(errors) / sizeof(errors[0]); ++index) {
        REQUIRE(ninlil_test_storage_fault_next(context.storage,
            NINLIL_TEST_STORAGE_OP_GET, errors[index]));
        output = mut(data, sizeof(data));
        REQUIRE(get_status(&context, reader, small_key, sizeof(small_key),
            &output, errors[index]));
        REQUIRE(output.length == 0u && data[0] == 0xaau);
    }
    output = mut(NULL, 0u);
    output.length = 1u;
    REQUIRE(context.ops->get(context.ops->user, reader,
        bytes(small_key, sizeof(small_key)), &output)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(output.length == 1u);
    output = mut(data, 0u);
    REQUIRE(context.ops->get(context.ops->user, reader,
        bytes(small_key, sizeof(small_key)), &output)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(output.data == data && output.length == 0u);
    output = mut(NULL, 1u);
    REQUIRE(context.ops->get(context.ops->user, reader,
        bytes(small_key, sizeof(small_key)), &output)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(output.data == NULL && output.length == 0u);
    REQUIRE(context.ops->rollback(context.ops->user, reader) == NINLIL_STORAGE_OK);
    destroy_fixture(&context);
    return 0;
}

static int test_iteration_order_snapshot_and_mb7_mb8(void)
{
    fixture_context_t context = make_fixture(16u, 1000000u);
    ninlil_storage_txn_t writer;
    ninlil_storage_iter_t before = NULL;
    ninlil_storage_iter_t after = NULL;
    ninlil_storage_iter_t pair = NULL;
    static const uint8_t key_a[] = {'a'};
    static const uint8_t key_a0[] = {'a', 0u};
    static const uint8_t key_80[] = {0x80u};
    static const uint8_t key_ff[] = {0xffu};
    static const uint8_t key_new[] = {'b'};
    static const uint8_t key_pair[] = {'p', 'a', 'i', 'r'};
    static const uint8_t prefix_pair[] = {'p'};
    static const uint8_t value6[] = {1u, 2u, 3u, 4u, 5u, 6u};
    uint8_t key_data[8];
    uint8_t value_data[8];
    ninlil_mut_bytes_t key_output;
    ninlil_mut_bytes_t value_output;

    REQUIRE(context.storage != NULL);
    writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(writer != NULL);
    REQUIRE(put_value(&context, writer, key_ff, sizeof(key_ff), value6, sizeof(value6)));
    REQUIRE(put_value(&context, writer, key_80, sizeof(key_80), value6, sizeof(value6)));
    REQUIRE(put_value(&context, writer, key_a0, sizeof(key_a0), value6, sizeof(value6)));
    REQUIRE(put_value(&context, writer, key_a, sizeof(key_a), value6, sizeof(value6)));
    REQUIRE(context.ops->iter_open(context.ops->user, writer,
        bytes(NULL, 0u), &before) == NINLIL_STORAGE_OK);
    REQUIRE(put_value(&context, writer, key_new, sizeof(key_new), value6, sizeof(value6)));
    REQUIRE(context.ops->iter_open(context.ops->user, writer,
        bytes(NULL, 0u), &after) == NINLIL_STORAGE_OK);
    REQUIRE(put_value(&context, writer, key_pair, sizeof(key_pair),
        value6, sizeof(value6)));
    REQUIRE(context.ops->iter_open(context.ops->user, writer,
        bytes(prefix_pair, sizeof(prefix_pair)), &pair) == NINLIL_STORAGE_OK);
    (void)memset(key_data, 0xaa, sizeof(key_data));
    (void)memset(value_data, 0xaa, sizeof(value_data));
    key_output = mut(key_data, 3u);
    value_output = mut(value_data, sizeof(value_data));
    REQUIRE(context.ops->iter_next(context.ops->user, pair,
        &key_output, &value_output) == NINLIL_STORAGE_BUFFER_TOO_SMALL);
    REQUIRE(key_output.length == 4u && value_output.length == 6u);
    REQUIRE(key_data[0] == 0xaau && value_data[0] == 0xaau);
    key_output = mut(key_data, sizeof(key_data));
    value_output = mut(value_data, sizeof(value_data));
    REQUIRE(context.ops->iter_next(context.ops->user, pair,
        &key_output, &value_output) == NINLIL_STORAGE_OK);
    REQUIRE(key_output.length == 4u
        && memcmp(key_data, key_pair, sizeof(key_pair)) == 0);
    context.ops->iter_close(context.ops->user, pair);
    key_output = mut(key_data, sizeof(key_data));
    value_output = mut(value_data, sizeof(value_data));
    REQUIRE(context.ops->iter_next(context.ops->user, before,
        &key_output, &value_output) == NINLIL_STORAGE_OK);
    REQUIRE(key_output.length == 1u && key_data[0] == 'a');
    REQUIRE(value_output.length == 6u && value_data[6] == 0xaau);
    key_output = mut(key_data, sizeof(key_data));
    value_output = mut(value_data, sizeof(value_data));
    REQUIRE(context.ops->iter_next(context.ops->user, before,
        &key_output, &value_output) == NINLIL_STORAGE_OK);
    REQUIRE(key_output.length == 2u && key_data[0] == 'a' && key_data[1] == 0u);
    key_output = mut(key_data, sizeof(key_data));
    value_output = mut(value_data, sizeof(value_data));
    REQUIRE(context.ops->iter_next(context.ops->user, before,
        &key_output, &value_output) == NINLIL_STORAGE_OK);
    REQUIRE(key_data[0] == 0x80u);
    key_output = mut(key_data, sizeof(key_data));
    value_output = mut(value_data, sizeof(value_data));
    REQUIRE(context.ops->iter_next(context.ops->user, before,
        &key_output, &value_output) == NINLIL_STORAGE_OK);
    REQUIRE(key_data[0] == 0xffu);
    key_output = mut(key_data, sizeof(key_data));
    value_output = mut(value_data, sizeof(value_data));
    REQUIRE(context.ops->iter_next(context.ops->user, before,
        &key_output, &value_output) == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(key_output.length == 0u && value_output.length == 0u);
    context.ops->iter_close(context.ops->user, before);
    context.ops->iter_close(context.ops->user, after);
    REQUIRE(context.ops->rollback(context.ops->user, writer) == NINLIL_STORAGE_OK);
    destroy_fixture(&context);
    return 0;
}

static int test_value_boundary_net_capacity_and_capacity_output(void)
{
    fixture_context_t context = make_fixture(1u, 16u + 1u + 65536u);
    ninlil_storage_txn_t writer;
    ninlil_storage_txn_t replacement;
    ninlil_storage_txn_t over_capacity;
    ninlil_storage_txn_t reader;
    static const uint8_t key_a[] = {'a'};
    static const uint8_t key_b[] = {'b'};
    uint8_t *large = (uint8_t *)malloc(65537u);
    ninlil_storage_capacity_t capacity;

    REQUIRE(context.storage != NULL && large != NULL);
    (void)memset(large, 0x5a, 65537u);
    writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(writer != NULL);
    REQUIRE(context.ops->put(context.ops->user, writer,
        bytes(key_a, sizeof(key_a)), bytes(large, 65537u))
        == NINLIL_STORAGE_NO_SPACE);
    REQUIRE(put_value(&context, writer, key_a, sizeof(key_a), large, 65536u));
    REQUIRE(commit_txn(&context, writer));
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    REQUIRE(context.ops->capacity(context.ops->user, context.handle,
        &capacity) == NINLIL_STORAGE_OK);
    REQUIRE(capacity.used_entries == 1u);
    REQUIRE(capacity.used_bytes == 16u + 1u + 65536u);
    replacement = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(replacement != NULL);
    REQUIRE(context.ops->erase(context.ops->user, replacement,
        bytes(key_a, sizeof(key_a))) == NINLIL_STORAGE_OK);
    REQUIRE(put_value(&context, replacement, key_b, sizeof(key_b), large, 65536u));
    REQUIRE(commit_txn(&context, replacement));
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    REQUIRE(context.ops->capacity(context.ops->user, context.handle,
        &capacity) == NINLIL_STORAGE_OK);
    REQUIRE(capacity.used_entries == 1u
        && capacity.used_bytes == 16u + 1u + 65536u);
    over_capacity = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(over_capacity != NULL);
    REQUIRE(put_value(&context, over_capacity, key_a, sizeof(key_a), NULL, 0u));
    REQUIRE(context.ops->commit(context.ops->user, over_capacity,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_NO_SPACE);
    reader = begin_txn(&context, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(reader != NULL);
    {
        ninlil_mut_bytes_t output = mut(NULL, 0u);
        REQUIRE(get_status(&context, reader, key_a, sizeof(key_a),
            &output, NINLIL_STORAGE_NOT_FOUND));
        output = mut(large, 65536u);
        REQUIRE(get_status(&context, reader, key_b, sizeof(key_b),
            &output, NINLIL_STORAGE_OK));
        REQUIRE(output.length == 65536u);
    }
    REQUIRE(context.ops->rollback(context.ops->user, reader) == NINLIL_STORAGE_OK);
    free(large);
    destroy_fixture(&context);
    return 0;
}

static int committed_key_exists(
    fixture_context_t *context,
    const uint8_t *key,
    uint32_t key_length)
{
    ninlil_storage_txn_t reader = begin_txn(context, NINLIL_STORAGE_READ_ONLY);
    uint8_t data[4];
    ninlil_mut_bytes_t output = mut(data, sizeof(data));
    int exists;

    if (reader == NULL) {
        return 0;
    }
    exists = get_status(context, reader, key, key_length,
        &output, NINLIL_STORAGE_OK);
    (void)context->ops->rollback(context->ops->user, reader);
    return exists;
}

static int test_fault_fifo_unknown_truth_and_rollback(void)
{
    fixture_context_t context = make_fixture(16u, 1000000u);
    ninlil_storage_txn_t writer;
    ninlil_storage_txn_t rollback;
    static const uint8_t key[] = {'k'};
    static const uint8_t value[] = {7u};
    const ninlil_storage_status_t unknown = (ninlil_storage_status_t)999u;

    REQUIRE(context.storage != NULL);
    REQUIRE(!ninlil_test_storage_fault_enqueue(context.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 0, 0));
    REQUIRE(ninlil_test_storage_fault_enqueue(context.storage,
        NINLIL_TEST_STORAGE_OP_BEGIN, NINLIL_STORAGE_BUSY, 2u, 0, 0));
    REQUIRE(ninlil_test_storage_fault_enqueue(context.storage,
        NINLIL_TEST_STORAGE_OP_BEGIN, unknown, 1u, 0, 0));
    writer = NULL;
    REQUIRE(context.ops->begin(context.ops->user, context.handle,
        NINLIL_STORAGE_READ_WRITE, &writer) == NINLIL_STORAGE_BUSY);
    REQUIRE(writer == NULL);
    REQUIRE(context.ops->begin(context.ops->user, context.handle,
        NINLIL_STORAGE_READ_WRITE, &writer) == NINLIL_STORAGE_BUSY);
    REQUIRE(context.ops->begin(context.ops->user, context.handle,
        NINLIL_STORAGE_READ_WRITE, &writer) == unknown);
    REQUIRE((writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE)) != NULL);
    REQUIRE(put_value(&context, writer, key, sizeof(key), value, sizeof(value)));
    REQUIRE(ninlil_test_storage_fault_enqueue(context.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 1));
    REQUIRE(context.ops->commit(context.ops->user, writer,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_COMMIT_UNKNOWN);
    ninlil_test_storage_simulate_crash(context.storage);
    context.handle = NULL;
    {
        static const uint8_t name[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x00u};
        REQUIRE(context.ops->open(context.ops->user, bytes(name, sizeof(name)),
            NINLIL_STORAGE_SCHEMA_M1A, &context.handle) == NINLIL_STORAGE_OK);
    }
    REQUIRE(committed_key_exists(&context, key, sizeof(key)));
    writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(writer != NULL);
    REQUIRE(context.ops->erase(context.ops->user, writer,
        bytes(key, sizeof(key))) == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_test_storage_fault_enqueue(context.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 0));
    REQUIRE(context.ops->commit(context.ops->user, writer,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_COMMIT_UNKNOWN);
    ninlil_test_storage_simulate_crash(context.storage);
    context.handle = NULL;
    {
        static const uint8_t name[] = {0x00u, 0xffu, 0x2fu, 0x41u, 0x00u};
        REQUIRE(context.ops->open(context.ops->user, bytes(name, sizeof(name)),
            NINLIL_STORAGE_SCHEMA_M1A, &context.handle) == NINLIL_STORAGE_OK);
    }
    REQUIRE(committed_key_exists(&context, key, sizeof(key)));
    writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(writer != NULL);
    REQUIRE(context.ops->erase(context.ops->user, writer,
        bytes(key, sizeof(key))) == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_test_storage_fault_next(context.storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_IO_ERROR));
    REQUIRE(context.ops->commit(context.ops->user, writer,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_IO_ERROR);
    REQUIRE(committed_key_exists(&context, key, sizeof(key)));
    rollback = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(rollback != NULL);
    REQUIRE(context.ops->erase(context.ops->user, rollback,
        bytes(key, sizeof(key))) == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_test_storage_fault_next(context.storage,
        NINLIL_TEST_STORAGE_OP_ROLLBACK, NINLIL_STORAGE_IO_ERROR));
    REQUIRE(context.ops->rollback(context.ops->user, rollback)
        == NINLIL_STORAGE_IO_ERROR);
    REQUIRE(committed_key_exists(&context, key, sizeof(key)));
    destroy_fixture(&context);
    return 0;
}

static int test_fault_validation_nonconsumption_trace_and_shapes(void)
{
    fixture_context_t context = make_fixture(16u, 1000000u);
    ninlil_storage_txn_t writer;
    ninlil_storage_txn_t reader;
    ninlil_storage_iter_t iterator = NULL;
    static const uint8_t key[] = {'x'};
    static const uint8_t value[] = {1u};
    uint8_t data[2] = {0xaau, 0xaau};
    ninlil_mut_bytes_t output;
    const ninlil_test_storage_trace_record_t *record;
    size_t index;
    int saw_commit = 0;

    REQUIRE(context.storage != NULL);
    writer = begin_txn(&context, NINLIL_STORAGE_READ_WRITE);
    REQUIRE(writer != NULL);
    REQUIRE(put_value(&context, writer, key, sizeof(key), value, sizeof(value)));
    REQUIRE(commit_txn(&context, writer));
    reader = begin_txn(&context, NINLIL_STORAGE_READ_ONLY);
    REQUIRE(reader != NULL);
    REQUIRE(ninlil_test_storage_fault_next(context.storage,
        NINLIL_TEST_STORAGE_OP_GET, NINLIL_STORAGE_BUSY));
    output = mut(data, sizeof(data));
    output.length = 1u;
    REQUIRE(context.ops->get(context.ops->user, reader,
        bytes(key, sizeof(key)), &output) == NINLIL_STORAGE_CORRUPT);
    output = mut(data, sizeof(data));
    REQUIRE(context.ops->get(context.ops->user, reader,
        bytes(key, sizeof(key)), &output) == NINLIL_STORAGE_BUSY);
    REQUIRE(output.length == 0u && data[0] == 0xaau);
    REQUIRE(context.ops->iter_open(context.ops->user, reader,
        bytes(NULL, 0u), &iterator) == NINLIL_STORAGE_OK);
    REQUIRE(iterator != NULL);
    REQUIRE(context.ops->commit(context.ops->user, reader,
        NINLIL_DURABILITY_FULL) == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_test_storage_live_iterators(context.storage) == 0u);
    REQUIRE(ninlil_test_storage_live_transactions(context.storage) == 0u);
    output = mut(data, sizeof(data));
    REQUIRE(context.ops->iter_next(context.ops->user, iterator,
        &output, &output) == NINLIL_STORAGE_CORRUPT);
    REQUIRE(ninlil_test_storage_call_count(context.storage,
        NINLIL_TEST_STORAGE_OP_GET) >= 2u);
    REQUIRE(!ninlil_test_storage_trace_overflowed(context.storage));
    for (index = 0u; index < ninlil_test_storage_trace_count(context.storage);
         ++index) {
        record = ninlil_test_storage_trace_at(context.storage, index);
        REQUIRE(record != NULL && record->sequence == index + 1u);
        if (record->operation == NINLIL_TEST_STORAGE_OP_COMMIT) {
            REQUIRE(record->handle_id != 0u);
            REQUIRE(record->transaction_id != 0u);
            REQUIRE(record->durability == NINLIL_DURABILITY_FULL);
            saw_commit = 1;
        }
    }
    REQUIRE(saw_commit);
    destroy_fixture(&context);
    return 0;
}

int main(void)
{
    if (test_configuration_namespace_lease_and_crash() != 0
        || test_transaction_snapshots_and_lifecycle() != 0
        || test_mutable_buffers_mb1_to_mb6() != 0
        || test_iteration_order_snapshot_and_mb7_mb8() != 0
        || test_value_boundary_net_capacity_and_capacity_output() != 0
        || test_fault_fifo_unknown_truth_and_rollback() != 0
        || test_fault_validation_nonconsumption_trace_and_shapes() != 0) {
        return 1;
    }
    return 0;
}
