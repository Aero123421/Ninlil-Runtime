#include "storage_conformance.h"

#include <stdio.h>
#include <string.h>

#define CONFORM_REQUIRE(condition)                                             \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr,                                              \
                "storage conformance:%d: requirement failed: %s\n",          \
                __LINE__, #condition);                                         \
            goto fail;                                                         \
        }                                                                      \
    } while (0)

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

int ninlil_test_storage_conformance_run(
    const ninlil_storage_ops_t *ops,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    uint32_t expected_schema)
{
    static const uint8_t key_a[] = {0x10u, 0x00u, 0xffu};
    static const uint8_t key_b[] = {0x10u, 0x01u};
    static const uint8_t value_a[] = {0x61u, 0x00u, 0x62u};
    static const uint8_t value_b[] = {0xffu, 0x7fu};
    static const uint8_t missing_key[] = {0x20u};
    static const uint8_t prefix[] = {0x10u};
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_handle_t duplicate = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_bytes_view_t namespace_view =
        bytes(storage_namespace, storage_namespace_length);
    ninlil_storage_capacity_t before;
    ninlil_storage_capacity_t after;
    uint8_t output_raw[16];
    uint8_t key_raw[16];
    uint8_t value_raw[16];
    ninlil_mut_bytes_t output;
    ninlil_mut_bytes_t out_key;
    ninlil_mut_bytes_t out_value;

    CONFORM_REQUIRE(ops != NULL && storage_namespace != NULL);
    CONFORM_REQUIRE(storage_namespace_length > 0u);
    CONFORM_REQUIRE(ops->abi_version == NINLIL_ABI_VERSION);
    CONFORM_REQUIRE(ops->struct_size >= sizeof(*ops));
    CONFORM_REQUIRE(ops->open != NULL && ops->close != NULL);
    CONFORM_REQUIRE(ops->begin != NULL && ops->get != NULL);
    CONFORM_REQUIRE(ops->put != NULL && ops->erase != NULL);
    CONFORM_REQUIRE(ops->iter_open != NULL && ops->iter_next != NULL);
    CONFORM_REQUIRE(ops->iter_close != NULL && ops->capacity != NULL);
    CONFORM_REQUIRE(ops->commit != NULL && ops->rollback != NULL);

    CONFORM_REQUIRE(ops->open(
        ops->user, namespace_view, expected_schema, &handle)
        == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(handle != NULL);
    CONFORM_REQUIRE(ops->open(
        ops->user, namespace_view, expected_schema, &duplicate)
        == NINLIL_STORAGE_BUSY);
    CONFORM_REQUIRE(duplicate == NULL);

    (void)memset(&before, 0, sizeof(before));
    before.abi_version = NINLIL_ABI_VERSION;
    before.struct_size = (uint16_t)sizeof(before);
    CONFORM_REQUIRE(ops->capacity(ops->user, handle, &before)
        == NINLIL_STORAGE_OK);

    CONFORM_REQUIRE(ops->begin(
        ops->user, handle, NINLIL_STORAGE_READ_WRITE, &transaction)
        == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(transaction != NULL);
    CONFORM_REQUIRE(ops->put(
        ops->user, transaction, bytes(key_b, sizeof(key_b)),
        bytes(value_b, sizeof(value_b))) == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(ops->put(
        ops->user, transaction, bytes(key_a, sizeof(key_a)),
        bytes(value_a, sizeof(value_a))) == NINLIL_STORAGE_OK);

    output = mut(output_raw, sizeof(output_raw));
    CONFORM_REQUIRE(ops->get(
        ops->user, transaction, bytes(key_a, sizeof(key_a)), &output)
        == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(output.length == sizeof(value_a));
    CONFORM_REQUIRE(memcmp(output_raw, value_a, sizeof(value_a)) == 0);
    CONFORM_REQUIRE(ops->commit(
        ops->user, transaction, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    transaction = NULL;

    (void)memset(&after, 0, sizeof(after));
    after.abi_version = NINLIL_ABI_VERSION;
    after.struct_size = (uint16_t)sizeof(after);
    CONFORM_REQUIRE(ops->capacity(ops->user, handle, &after)
        == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(after.used_entries == before.used_entries + 2u);
    CONFORM_REQUIRE(after.used_bytes
        == before.used_bytes + sizeof(key_a) + sizeof(value_a)
            + sizeof(key_b) + sizeof(value_b) + 32u);

    CONFORM_REQUIRE(ops->begin(
        ops->user, handle, NINLIL_STORAGE_READ_ONLY, &transaction)
        == NINLIL_STORAGE_OK);
    output_raw[0] = 0xa5u;
    output = mut(output_raw, 1u);
    CONFORM_REQUIRE(ops->get(
        ops->user, transaction, bytes(key_a, sizeof(key_a)), &output)
        == NINLIL_STORAGE_BUFFER_TOO_SMALL);
    CONFORM_REQUIRE(output.length == sizeof(value_a));
    CONFORM_REQUIRE(output_raw[0] == 0xa5u);
    output = mut(output_raw, sizeof(output_raw));
    CONFORM_REQUIRE(ops->get(
        ops->user, transaction, bytes(missing_key, sizeof(missing_key)),
        &output) == NINLIL_STORAGE_NOT_FOUND);

    CONFORM_REQUIRE(ops->iter_open(
        ops->user, transaction, bytes(prefix, sizeof(prefix)), &iterator)
        == NINLIL_STORAGE_OK);
    out_key = mut(key_raw, sizeof(key_raw));
    out_value = mut(value_raw, 1u);
    value_raw[0] = 0x5au;
    CONFORM_REQUIRE(ops->iter_next(
        ops->user, iterator, &out_key, &out_value)
        == NINLIL_STORAGE_BUFFER_TOO_SMALL);
    CONFORM_REQUIRE(out_key.length == sizeof(key_a));
    CONFORM_REQUIRE(out_value.length == sizeof(value_a));
    CONFORM_REQUIRE(value_raw[0] == 0x5au);
    out_key = mut(key_raw, sizeof(key_raw));
    out_value = mut(value_raw, sizeof(value_raw));
    CONFORM_REQUIRE(ops->iter_next(
        ops->user, iterator, &out_key, &out_value) == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(out_key.length == sizeof(key_a));
    CONFORM_REQUIRE(memcmp(key_raw, key_a, sizeof(key_a)) == 0);
    CONFORM_REQUIRE(out_value.length == sizeof(value_a));
    CONFORM_REQUIRE(memcmp(value_raw, value_a, sizeof(value_a)) == 0);
    out_key = mut(key_raw, sizeof(key_raw));
    out_value = mut(value_raw, sizeof(value_raw));
    CONFORM_REQUIRE(ops->iter_next(
        ops->user, iterator, &out_key, &out_value) == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(out_key.length == sizeof(key_b));
    CONFORM_REQUIRE(memcmp(key_raw, key_b, sizeof(key_b)) == 0);
    ops->iter_close(ops->user, iterator);
    iterator = NULL;
    CONFORM_REQUIRE(ops->rollback(ops->user, transaction)
        == NINLIL_STORAGE_OK);
    transaction = NULL;

    CONFORM_REQUIRE(ops->begin(
        ops->user, handle, NINLIL_STORAGE_READ_WRITE, &transaction)
        == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(ops->erase(
        ops->user, transaction, bytes(key_a, sizeof(key_a)))
        == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(ops->rollback(ops->user, transaction)
        == NINLIL_STORAGE_OK);
    transaction = NULL;
    CONFORM_REQUIRE(ops->begin(
        ops->user, handle, NINLIL_STORAGE_READ_ONLY, &transaction)
        == NINLIL_STORAGE_OK);
    output = mut(output_raw, sizeof(output_raw));
    CONFORM_REQUIRE(ops->get(
        ops->user, transaction, bytes(key_a, sizeof(key_a)), &output)
        == NINLIL_STORAGE_OK);
    CONFORM_REQUIRE(ops->rollback(ops->user, transaction)
        == NINLIL_STORAGE_OK);
    transaction = NULL;

    ops->close(ops->user, handle);
    return 0;

fail:
    if (iterator != NULL && ops != NULL && ops->iter_close != NULL) {
        ops->iter_close(ops->user, iterator);
    }
    if (transaction != NULL && ops != NULL && ops->rollback != NULL) {
        (void)ops->rollback(ops->user, transaction);
    }
    if (handle != NULL && ops != NULL && ops->close != NULL) {
        ops->close(ops->user, handle);
    }
    return 1;
}
