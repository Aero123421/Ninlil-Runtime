/* SPDX-License-Identifier: Apache-2.0 */
/*
 *
 * Adversarial shape/alias acceptance for the private typed MFDT store adapter.
 * The fixture deliberately violates provider output contracts.  The adapter
 * must fail closed, close every returned resource exactly once, and never
 * publish a partially initialized port.
 */
#include "mfdt_v1_store_port.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                       \
                "REQUIRE_FAIL %s:%d: %s\n",                                  \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef enum malicious_mode {
    MALICIOUS_NORMAL = 0,
    MALICIOUS_BEGIN_OK_NULL,
    MALICIOUS_BEGIN_ERROR_NONNULL,
    MALICIOUS_ITER_OK_NULL,
    MALICIOUS_ITER_ERROR_NONNULL,
    MALICIOUS_GET_OVERSIZE,
    MALICIOUS_GET_REPOINT,
    MALICIOUS_GET_CAPACITY_REWRITE_OK,
    MALICIOUS_GET_CAPACITY_REWRITE_NOT_FOUND,
    MALICIOUS_ITER_KEY_REPOINT,
    MALICIOUS_ITER_KEY_CAPACITY_REWRITE_OK,
    MALICIOUS_ITER_KEY_CAPACITY_REWRITE_NOT_FOUND,
    MALICIOUS_ITER_VALUE_OVERSIZE,
    MALICIOUS_ITER_VALUE_REPOINT,
    MALICIOUS_ITER_VALUE_CAPACITY_REWRITE_OK,
    MALICIOUS_ITER_VALUE_CAPACITY_REWRITE_NOT_FOUND,
    MALICIOUS_ITER_END_INVALID
} malicious_mode_t;

typedef struct malicious_provider {
    ninlil_storage_ops_t ops;
    malicious_mode_t mode;
    uint8_t transaction_token;
    uint8_t iterator_token;
    uint8_t foreign_buffer[64];
    uint32_t begin_calls;
    uint32_t rollback_calls;
    uint32_t iter_open_calls;
    uint32_t iter_close_calls;
    uint32_t get_calls;
    uint32_t iter_next_calls;
    uint8_t transaction_live;
    uint8_t iterator_live;
} malicious_provider_t;

typedef union aligned_bytes {
    uint64_t align8;
    uint8_t bytes[
        sizeof(ninlil_mfdt_v1_store_port_t) +
        sizeof(ninlil_storage_ops_t) + 32u];
} aligned_bytes_t;

static ninlil_storage_status_t malicious_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    malicious_provider_t *provider = (malicious_provider_t *)user;

    if (provider == NULL || handle != provider || out_txn == NULL ||
        (mode != NINLIL_STORAGE_READ_ONLY &&
         mode != NINLIL_STORAGE_READ_WRITE)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    provider->begin_calls += 1u;
    if (provider->mode == MALICIOUS_BEGIN_OK_NULL) {
        *out_txn = NULL;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_BEGIN_ERROR_NONNULL) {
        *out_txn = &provider->transaction_token;
        provider->transaction_live = 1u;
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out_txn = &provider->transaction_token;
    provider->transaction_live = 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t malicious_get(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *value)
{
    malicious_provider_t *provider = (malicious_provider_t *)user;

    if (provider == NULL ||
        transaction != &provider->transaction_token ||
        provider->transaction_live == 0u || key.data == NULL ||
        key.length != NINLIL_MFDT_V1_KEY_BYTES || value == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    provider->get_calls += 1u;
    if (provider->mode == MALICIOUS_GET_OVERSIZE) {
        value->length = value->capacity + 1u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_GET_REPOINT) {
        value->data = provider->foreign_buffer;
        value->length = 1u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_GET_CAPACITY_REWRITE_OK) {
        value->capacity += 1u;
        value->length = 1u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_GET_CAPACITY_REWRITE_NOT_FOUND) {
        value->capacity += 1u;
        value->length = 0u;
        return NINLIL_STORAGE_NOT_FOUND;
    }
    value->length = 0u;
    return NINLIL_STORAGE_NOT_FOUND;
}

static ninlil_storage_status_t malicious_put(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    (void)user;
    (void)transaction;
    (void)key;
    (void)value;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t malicious_erase(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t key)
{
    (void)user;
    (void)transaction;
    (void)key;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t malicious_iter_open(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iterator)
{
    malicious_provider_t *provider = (malicious_provider_t *)user;

    (void)prefix;
    if (provider == NULL ||
        transaction != &provider->transaction_token ||
        provider->transaction_live == 0u || out_iterator == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    provider->iter_open_calls += 1u;
    if (provider->mode == MALICIOUS_ITER_OK_NULL) {
        *out_iterator = NULL;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_ITER_ERROR_NONNULL) {
        *out_iterator = &provider->iterator_token;
        provider->iterator_live = 1u;
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out_iterator = &provider->iterator_token;
    provider->iterator_live = 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t malicious_iter_next(
    void *user,
    ninlil_storage_iter_t iterator,
    ninlil_mut_bytes_t *key,
    ninlil_mut_bytes_t *value)
{
    malicious_provider_t *provider = (malicious_provider_t *)user;

    if (provider == NULL || iterator != &provider->iterator_token ||
        provider->iterator_live == 0u || key == NULL || value == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    provider->iter_next_calls += 1u;
    if (provider->mode == MALICIOUS_ITER_END_INVALID) {
        key->length = key->capacity + 1u;
        value->length = value->capacity + 1u;
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (provider->mode == MALICIOUS_ITER_KEY_REPOINT) {
        key->data = provider->foreign_buffer;
        key->length = NINLIL_MFDT_V1_KEY_BYTES;
        value->length = 0u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode ==
        MALICIOUS_ITER_KEY_CAPACITY_REWRITE_NOT_FOUND) {
        key->capacity += 1u;
        key->length = 0u;
        value->length = 0u;
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (key->capacity >= NINLIL_MFDT_V1_KEY_BYTES) {
        (void)memset(key->data, 0x31, NINLIL_MFDT_V1_KEY_BYTES);
    }
    key->length = NINLIL_MFDT_V1_KEY_BYTES;
    if (provider->mode == MALICIOUS_ITER_KEY_CAPACITY_REWRITE_OK) {
        key->capacity += 1u;
        value->length = 0u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_ITER_VALUE_OVERSIZE) {
        value->length = value->capacity + 1u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_ITER_VALUE_REPOINT) {
        value->data = provider->foreign_buffer;
        value->length = 1u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode == MALICIOUS_ITER_VALUE_CAPACITY_REWRITE_OK) {
        value->capacity += 1u;
        value->length = 1u;
        return NINLIL_STORAGE_OK;
    }
    if (provider->mode ==
        MALICIOUS_ITER_VALUE_CAPACITY_REWRITE_NOT_FOUND) {
        key->length = 0u;
        value->capacity += 1u;
        value->length = 0u;
        return NINLIL_STORAGE_NOT_FOUND;
    }
    value->length = 0u;
    return NINLIL_STORAGE_OK;
}

static void malicious_iter_close(
    void *user,
    ninlil_storage_iter_t iterator)
{
    malicious_provider_t *provider = (malicious_provider_t *)user;

    if (provider != NULL && iterator == &provider->iterator_token &&
        provider->iterator_live != 0u) {
        provider->iter_close_calls += 1u;
        provider->iterator_live = 0u;
    }
}

static ninlil_storage_status_t malicious_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *capacity)
{
    (void)user;
    (void)handle;
    if (capacity == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    (void)memset(capacity, 0, sizeof(*capacity));
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t malicious_commit(
    void *user,
    ninlil_storage_txn_t transaction,
    ninlil_durability_t durability)
{
    malicious_provider_t *provider = (malicious_provider_t *)user;

    (void)durability;
    if (provider == NULL ||
        transaction != &provider->transaction_token ||
        provider->transaction_live == 0u) {
        return NINLIL_STORAGE_CORRUPT;
    }
    provider->transaction_live = 0u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t malicious_rollback(
    void *user,
    ninlil_storage_txn_t transaction)
{
    malicious_provider_t *provider = (malicious_provider_t *)user;

    if (provider == NULL ||
        transaction != &provider->transaction_token ||
        provider->transaction_live == 0u) {
        return NINLIL_STORAGE_CORRUPT;
    }
    provider->rollback_calls += 1u;
    provider->transaction_live = 0u;
    return NINLIL_STORAGE_OK;
}

static void malicious_provider_init(malicious_provider_t *provider)
{
    (void)memset(provider, 0, sizeof(*provider));
    provider->ops.abi_version = NINLIL_ABI_VERSION;
    provider->ops.struct_size = (uint16_t)sizeof(provider->ops);
    provider->ops.user = provider;
    provider->ops.begin = malicious_begin;
    provider->ops.get = malicious_get;
    provider->ops.put = malicious_put;
    provider->ops.erase = malicious_erase;
    provider->ops.iter_open = malicious_iter_open;
    provider->ops.iter_next = malicious_iter_next;
    provider->ops.iter_close = malicious_iter_close;
    provider->ops.capacity = malicious_capacity;
    provider->ops.commit = malicious_commit;
    provider->ops.rollback = malicious_rollback;
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

static int port_init_alias_case(
    size_t port_offset,
    size_t ops_offset,
    int guarantees_overlap,
    size_t guarantees_offset)
{
    aligned_bytes_t storage;
    aligned_bytes_t before;
    malicious_provider_t provider;
    ninlil_mfdt_v1_store_guarantees_t guarantees = exact_guarantees();
    ninlil_mfdt_v1_store_port_t *port;
    const ninlil_storage_ops_t *ops;
    const ninlil_mfdt_v1_store_guarantees_t *guarantees_ptr;

    malicious_provider_init(&provider);
    (void)memset(&storage, 0xa5, sizeof(storage));
    port = (ninlil_mfdt_v1_store_port_t *)(void *)
        (storage.bytes + port_offset);
    if (ops_offset != SIZE_MAX) {
        (void)memcpy(
            storage.bytes + ops_offset,
            &provider.ops,
            sizeof(provider.ops));
        ops = (const ninlil_storage_ops_t *)(const void *)
            (storage.bytes + ops_offset);
    } else {
        ops = &provider.ops;
    }
    if (guarantees_overlap != 0) {
        (void)memcpy(
            storage.bytes + guarantees_offset,
            &guarantees,
            sizeof(guarantees));
        guarantees_ptr =
            (const ninlil_mfdt_v1_store_guarantees_t *)(const void *)
                (storage.bytes + guarantees_offset);
    } else {
        guarantees_ptr = &guarantees;
    }
    before = storage;
    REQUIRE(ninlil_mfdt_v1_store_port_init(
                port,
                ops,
                &provider,
                guarantees_ptr) == NINLIL_MFDT_V1_ERR_PARAM);
    REQUIRE(memcmp(&storage, &before, sizeof(storage)) == 0);
    return 0;
}

static int test_port_init_alias_zero_mutation(void)
{
    REQUIRE(port_init_alias_case(0u, 0u, 0, 0u) == 0);
    REQUIRE(port_init_alias_case(0u, 8u, 0, 0u) == 0);
    REQUIRE(port_init_alias_case(0u, SIZE_MAX, 1, 0u) == 0);
    REQUIRE(port_init_alias_case(0u, SIZE_MAX, 1, 8u) == 0);
    return 0;
}

static int open_port(
    malicious_provider_t *provider,
    ninlil_mfdt_v1_store_port_t *port)
{
    ninlil_mfdt_v1_store_guarantees_t guarantees = exact_guarantees();

    malicious_provider_init(provider);
    (void)memset(port, 0, sizeof(*port));
    return ninlil_mfdt_v1_store_port_init(
        port,
        &provider->ops,
        provider,
        &guarantees);
}

static int test_begin_output_shape_cleanup(void)
{
    malicious_provider_t provider;
    ninlil_mfdt_v1_store_port_t port;
    ninlil_mfdt_v1_store_snapshot_t snapshot;
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t value[8];
    uint32_t value_len = 0u;
    int present = 0;

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_BEGIN_OK_NULL;
    REQUIRE(ninlil_mfdt_v1_store_full_begin(
                &port,
                0u,
                0u) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(port.full_open == 0u);
    REQUIRE(port.rw_txn == NULL);
    REQUIRE(provider.transaction_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_BEGIN_ERROR_NONNULL;
    REQUIRE(ninlil_mfdt_v1_store_full_begin(
                &port,
                0u,
                0u) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(port.full_open == 0u);
    REQUIRE(port.rw_txn == NULL);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);

    (void)memset(key, 0x41, sizeof(key));
    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_BEGIN_OK_NULL;
    REQUIRE(ninlil_mfdt_v1_store_read(
                &port,
                key,
                value,
                sizeof(value),
                &value_len,
                &present) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.transaction_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_BEGIN_ERROR_NONNULL;
    REQUIRE(ninlil_mfdt_v1_store_read(
                &port,
                key,
                value,
                sizeof(value),
                &value_len,
                &present) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_BEGIN_OK_NULL;
    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
                &port,
                NULL,
                0u,
                &snapshot) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.transaction_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_BEGIN_ERROR_NONNULL;
    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
                &port,
                NULL,
                0u,
                &snapshot) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);
    return 0;
}

static int test_snapshot_open_shape_cleanup(void)
{
    malicious_provider_t provider;
    ninlil_mfdt_v1_store_port_t port;
    ninlil_mfdt_v1_store_snapshot_t snapshot;

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_ITER_OK_NULL;
    (void)memset(&snapshot, 0xa5, sizeof(snapshot));
    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
                &port,
                NULL,
                0u,
                &snapshot) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(port.snapshot_open == 0u);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);
    REQUIRE(provider.iterator_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_ITER_ERROR_NONNULL;
    (void)memset(&snapshot, 0xa5, sizeof(snapshot));
    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
                &port,
                NULL,
                0u,
                &snapshot) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(port.snapshot_open == 0u);
    REQUIRE(provider.iter_close_calls == 1u);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);
    REQUIRE(provider.iterator_live == 0u);
    return 0;
}

static int test_get_mutable_shape_fail_closed(void)
{
    malicious_provider_t provider;
    ninlil_mfdt_v1_store_port_t port;
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t value[8];
    uint32_t value_len;
    int present;

    (void)memset(key, 0x11, sizeof(key));
    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_GET_OVERSIZE;
    REQUIRE(ninlil_mfdt_v1_store_read(
                &port,
                key,
                value,
                sizeof(value),
                &value_len,
                &present) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_GET_REPOINT;
    REQUIRE(ninlil_mfdt_v1_store_read(
                &port,
                key,
                value,
                sizeof(value),
                &value_len,
                &present) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_GET_CAPACITY_REWRITE_OK;
    REQUIRE(ninlil_mfdt_v1_store_read(
                &port,
                key,
                value,
                sizeof(value),
                &value_len,
                &present) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = MALICIOUS_GET_CAPACITY_REWRITE_NOT_FOUND;
    REQUIRE(ninlil_mfdt_v1_store_read(
                &port,
                key,
                value,
                sizeof(value),
                &value_len,
                &present) == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);
    return 0;
}

static int snapshot_next_once(malicious_mode_t mode)
{
    malicious_provider_t provider;
    ninlil_mfdt_v1_store_port_t port;
    ninlil_mfdt_v1_store_snapshot_t snapshot;
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t value[8];
    uint32_t value_len = 0u;
    int done = 0;
    int rc;

    REQUIRE(open_port(&provider, &port) == NINLIL_MFDT_V1_OK);
    provider.mode = mode;
    REQUIRE(ninlil_mfdt_v1_store_snapshot_begin(
                &port,
                NULL,
                0u,
                &snapshot) == NINLIL_MFDT_V1_OK);
    rc = ninlil_mfdt_v1_store_snapshot_next(
        &snapshot,
        key,
        value,
        sizeof(value),
        &value_len,
        &done);
    REQUIRE(rc == NINLIL_MFDT_V1_ERR_CORRUPT);
    REQUIRE(ninlil_mfdt_v1_store_snapshot_end(&snapshot) ==
            NINLIL_MFDT_V1_OK);
    REQUIRE(provider.iter_close_calls == 1u);
    REQUIRE(provider.rollback_calls == 1u);
    REQUIRE(provider.transaction_live == 0u);
    REQUIRE(provider.iterator_live == 0u);
    return 0;
}

static int test_iter_next_mutable_shape_fail_closed(void)
{
    REQUIRE(snapshot_next_once(MALICIOUS_ITER_KEY_REPOINT) == 0);
    REQUIRE(snapshot_next_once(
                MALICIOUS_ITER_KEY_CAPACITY_REWRITE_OK) == 0);
    REQUIRE(snapshot_next_once(
                MALICIOUS_ITER_KEY_CAPACITY_REWRITE_NOT_FOUND) == 0);
    REQUIRE(snapshot_next_once(MALICIOUS_ITER_VALUE_OVERSIZE) == 0);
    REQUIRE(snapshot_next_once(MALICIOUS_ITER_VALUE_REPOINT) == 0);
    REQUIRE(snapshot_next_once(
                MALICIOUS_ITER_VALUE_CAPACITY_REWRITE_OK) == 0);
    REQUIRE(snapshot_next_once(
                MALICIOUS_ITER_VALUE_CAPACITY_REWRITE_NOT_FOUND) == 0);
    REQUIRE(snapshot_next_once(MALICIOUS_ITER_END_INVALID) == 0);
    return 0;
}

static int run_witness(const char *name, int (*test)(void))
{
    int rc = test();

    if (rc != 0) {
        (void)printf("WITNESS_FAIL %s\n", name);
        return 1;
    }
    (void)printf("WITNESS_PASS %s\n", name);
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += run_witness(
        "store_port_init_alias_zero_mutation",
        test_port_init_alias_zero_mutation);
    failures += run_witness(
        "store_begin_output_shape_cleanup",
        test_begin_output_shape_cleanup);
    failures += run_witness(
        "store_snapshot_open_shape_cleanup",
        test_snapshot_open_shape_cleanup);
    failures += run_witness(
        "store_get_mutable_shape_fail_closed",
        test_get_mutable_shape_fail_closed);
    failures += run_witness(
        "store_iter_next_mutable_shape_fail_closed",
        test_iter_next_mutable_shape_fail_closed);
    if (failures != 0) {
        (void)fprintf(
            stderr,
            "mfdt_v1_store_port_adversarial_test FAILED (%d)\n",
            failures);
        return 1;
    }
    (void)printf("mfdt_v1_store_port_adversarial_test OK\n");
    return 0;
}
