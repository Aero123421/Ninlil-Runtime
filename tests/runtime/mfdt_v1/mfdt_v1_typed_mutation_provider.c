/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_typed_mutation_provider.h"

#include "ninlil/platform.h"

#include <stdlib.h>
#include <string.h>

#define MUTATION_MAX_OPS NINLIL_MFDT_V1_HOST_FULL_OPS_MAX
#define MUTATION_VALUE_POOL_BYTES \
    ((uint32_t)NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX)
#define MUTATION_INJECT_VALUE_BYTES NINLIL_MFDT_V1_ACTIVE_VALUE_MAX

typedef struct mutation_op {
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t value_offset;
    uint32_t value_len;
    uint8_t kind; /* 1=put, 2=erase */
} mutation_op_t;

struct mfdt_v1_typed_mutation_provider {
    ninlil_mfdt_v1_host_store_t *backing;
    ninlil_mfdt_v1_store_port_t backing_port;
    ninlil_storage_ops_t ops;
    ninlil_storage_txn_t backing_txn;
    mutation_op_t staged[MUTATION_MAX_OPS];
    uint8_t staged_values[MUTATION_VALUE_POOL_BYTES];
    uint8_t injected_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t injected_value[MUTATION_INJECT_VALUE_BYTES];
    uint32_t staged_value_bytes;
    uint32_t injected_value_len;
    uint64_t txn_token;
    uint8_t txn_open;
    uint8_t txn_mode;
    uint8_t staged_count;
    uint8_t armed;
    uint8_t injected_valid;
    uint8_t snapshot_close_mutation_armed;
    uint8_t snapshot_close_mutated;
    uint8_t reject_ro_after_snapshot;
    uint64_t ro_begin_count;
    mfdt_v1_mutation_view_t armed_view;
};

static ninlil_storage_status_t mutation_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn);
static ninlil_storage_status_t mutation_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value);
static ninlil_storage_status_t mutation_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);
static ninlil_storage_status_t mutation_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key);
static ninlil_storage_status_t mutation_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter);
static ninlil_storage_status_t mutation_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value);
static void mutation_iter_close(void *user, ninlil_storage_iter_t iter);
static ninlil_storage_status_t mutation_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity);
static ninlil_storage_status_t mutation_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability);
static ninlil_storage_status_t mutation_rollback(
    void *user,
    ninlil_storage_txn_t txn);

static int view_valid(mfdt_v1_mutation_view_t view)
{
    return view >= MFDT_V1_MUTATION_PASS
        && view <= MFDT_V1_MUTATION_ABSENT;
}

static int bytes_view_valid(
    ninlil_bytes_view_t view,
    uint32_t exact_length)
{
    return view.length == exact_length
        && (view.length == 0u || view.data != NULL);
}

static int mutable_view_valid(ninlil_mut_bytes_t *view)
{
    return view != NULL && view->length <= view->capacity
        && (view->capacity == 0u ? view->data == NULL : view->data != NULL);
}

static void reset_transaction(
    mfdt_v1_typed_mutation_provider_t *provider)
{
    (void)memset(provider->staged, 0, sizeof(provider->staged));
    (void)memset(
        provider->staged_values,
        0,
        provider->staged_value_bytes);
    provider->backing_txn = NULL;
    provider->staged_value_bytes = 0u;
    provider->txn_open = 0u;
    provider->txn_mode = 0u;
    provider->staged_count = 0u;
}

static ninlil_bytes_view_t immutable_bytes(
    const uint8_t *data,
    uint32_t length)
{
    ninlil_bytes_view_t view;

    view.data = data;
    view.length = length;
    return view;
}

static ninlil_storage_status_t apply_op(
    mfdt_v1_typed_mutation_provider_t *provider,
    const mutation_op_t *op,
    int corrupt_value)
{
    if (op->kind == 2u) {
        return provider->backing_port.ops->erase(
            provider->backing_port.ops->user,
            provider->backing_txn,
            immutable_bytes(op->key, NINLIL_MFDT_V1_KEY_BYTES));
    }
    if (op->kind == 1u) {
        const uint8_t *value =
            provider->staged_values + op->value_offset;
        uint8_t *mutable_value =
            provider->staged_values + op->value_offset;
        uint8_t original = 0u;
        ninlil_storage_status_t status;

        if (corrupt_value != 0 && op->value_len != 0u) {
            original = mutable_value[0];
            mutable_value[0] ^= 0xffu;
        }
        status = provider->backing_port.ops->put(
            provider->backing_port.ops->user,
            provider->backing_txn,
            immutable_bytes(op->key, NINLIL_MFDT_V1_KEY_BYTES),
            immutable_bytes(value, op->value_len));
        if (corrupt_value != 0 && op->value_len != 0u) {
            mutable_value[0] = original;
        }
        return status;
    }
    return NINLIL_STORAGE_CORRUPT;
}

static ninlil_storage_status_t publish_injected_row(
    mfdt_v1_typed_mutation_provider_t *provider)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t status;

    if (provider->injected_valid == 0u) {
        return NINLIL_STORAGE_CORRUPT;
    }
    status = provider->backing_port.ops->begin(
        provider->backing_port.ops->user,
        provider->backing_port.handle,
        NINLIL_STORAGE_READ_WRITE,
        &transaction);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    status = provider->backing_port.ops->put(
        provider->backing_port.ops->user,
        transaction,
        immutable_bytes(
            provider->injected_key,
            NINLIL_MFDT_V1_KEY_BYTES),
        immutable_bytes(
            provider->injected_value,
            provider->injected_value_len));
    if (status == NINLIL_STORAGE_OK) {
        status = provider->backing_port.ops->commit(
            provider->backing_port.ops->user,
            transaction,
            NINLIL_DURABILITY_FULL);
    } else {
        ninlil_storage_status_t rollback_status =
            provider->backing_port.ops->rollback(
                provider->backing_port.ops->user,
                transaction);
        if (rollback_status != NINLIL_STORAGE_OK) {
            return rollback_status;
        }
    }
    return status;
}

mfdt_v1_typed_mutation_provider_t *
mfdt_v1_typed_mutation_provider_create(void)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)calloc(
            1u,
            sizeof(*provider));

    if (provider == NULL) {
        return NULL;
    }
    provider->backing = ninlil_mfdt_v1_host_store_create();
    if (provider->backing == NULL
        || ninlil_mfdt_v1_host_store_open_port(
               provider->backing,
               &provider->backing_port) != NINLIL_MFDT_V1_OK) {
        if (provider->backing != NULL) {
            ninlil_mfdt_v1_host_store_destroy(provider->backing);
        }
        free(provider);
        return NULL;
    }
    provider->ops.abi_version = NINLIL_ABI_VERSION;
    provider->ops.struct_size = (uint16_t)sizeof(provider->ops);
    provider->ops.user = provider;
    provider->ops.begin = mutation_begin;
    provider->ops.get = mutation_get;
    provider->ops.put = mutation_put;
    provider->ops.erase = mutation_erase;
    provider->ops.iter_open = mutation_iter_open;
    provider->ops.iter_next = mutation_iter_next;
    provider->ops.iter_close = mutation_iter_close;
    provider->ops.capacity = mutation_capacity;
    provider->ops.commit = mutation_commit;
    provider->ops.rollback = mutation_rollback;
    return provider;
}

void mfdt_v1_typed_mutation_provider_destroy(
    mfdt_v1_typed_mutation_provider_t *provider)
{
    if (provider == NULL) {
        return;
    }
    if (provider->txn_open != 0u && provider->backing_txn != NULL) {
        (void)provider->backing_port.ops->rollback(
            provider->backing_port.ops->user,
            provider->backing_txn);
    }
    ninlil_mfdt_v1_host_store_close_port(
        provider->backing,
        &provider->backing_port);
    ninlil_mfdt_v1_host_store_destroy(provider->backing);
    (void)memset(provider, 0, sizeof(*provider));
    free(provider);
}

int mfdt_v1_typed_mutation_provider_open_port(
    mfdt_v1_typed_mutation_provider_t *provider,
    ninlil_mfdt_v1_store_port_t *port)
{
    if (provider == NULL || port == NULL || provider->txn_open != 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    return ninlil_mfdt_v1_store_port_init(
        port,
        &provider->ops,
        (ninlil_storage_handle_t)provider,
        ninlil_mfdt_v1_host_store_guarantees());
}

void mfdt_v1_typed_mutation_provider_close_port(
    mfdt_v1_typed_mutation_provider_t *provider,
    ninlil_mfdt_v1_store_port_t *port)
{
    if (provider == NULL || port == NULL) {
        return;
    }
    if (port->full_open != 0u) {
        (void)ninlil_mfdt_v1_store_full_rollback(port);
    }
    (void)memset(port, 0, sizeof(*port));
}

int mfdt_v1_typed_mutation_provider_arm(
    mfdt_v1_typed_mutation_provider_t *provider,
    mfdt_v1_mutation_view_t view)
{
    if (provider == NULL || provider->txn_open != 0u
        || provider->armed != 0u || !view_valid(view)) {
        return 0;
    }
    provider->armed_view = view;
    provider->armed = 1u;
    return 1;
}

int mfdt_v1_typed_mutation_provider_set_injected_row(
    mfdt_v1_typed_mutation_provider_t *provider,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len)
{
    if (provider == NULL || key == NULL
        || (value == NULL && value_len != 0u)
        || value_len > sizeof(provider->injected_value)
        || provider->txn_open != 0u) {
        return 0;
    }
    (void)memcpy(
        provider->injected_key,
        key,
        NINLIL_MFDT_V1_KEY_BYTES);
    if (value_len != 0u) {
        (void)memcpy(provider->injected_value, value, value_len);
    }
    provider->injected_value_len = value_len;
    provider->injected_valid = 1u;
    return 1;
}

int mfdt_v1_typed_mutation_provider_arm_snapshot_close_mutation(
    mfdt_v1_typed_mutation_provider_t *provider,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len,
    int reject_followup_reads)
{
    if (!mfdt_v1_typed_mutation_provider_set_injected_row(
            provider,
            key,
            value,
            value_len)
        || provider->snapshot_close_mutation_armed != 0u) {
        return 0;
    }
    provider->snapshot_close_mutation_armed = 1u;
    provider->snapshot_close_mutated = 0u;
    provider->reject_ro_after_snapshot =
        reject_followup_reads != 0 ? 1u : 0u;
    provider->ro_begin_count = 0u;
    return 1;
}

uint64_t mfdt_v1_typed_mutation_provider_ro_begin_count(
    const mfdt_v1_typed_mutation_provider_t *provider)
{
    return provider != NULL ? provider->ro_begin_count : 0u;
}

int mfdt_v1_typed_mutation_provider_inventory(
    const mfdt_v1_typed_mutation_provider_t *provider,
    uint32_t *committed_keys_out,
    uint64_t *committed_logical_bytes_out,
    uint64_t *generation_out,
    uint64_t *full_count_out)
{
    if (provider == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    return ninlil_mfdt_v1_host_store_inventory(
        provider->backing,
        committed_keys_out,
        committed_logical_bytes_out,
        generation_out,
        full_count_out);
}

static ninlil_storage_status_t mutation_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;
    ninlil_storage_status_t status;

    if (provider == NULL || handle != (ninlil_storage_handle_t)provider
        || out_txn == NULL || *out_txn != NULL
        || provider->txn_open != 0u
        || (mode != NINLIL_STORAGE_READ_ONLY
            && mode != NINLIL_STORAGE_READ_WRITE)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (mode == NINLIL_STORAGE_READ_ONLY) {
        provider->ro_begin_count += 1u;
        if (provider->snapshot_close_mutated != 0u
            && provider->reject_ro_after_snapshot != 0u) {
            return NINLIL_STORAGE_IO_ERROR;
        }
    }
    status = provider->backing_port.ops->begin(
        provider->backing_port.ops->user,
        provider->backing_port.handle,
        mode,
        &provider->backing_txn);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    provider->txn_open = 1u;
    provider->txn_mode = (uint8_t)mode;
    provider->staged_count = 0u;
    provider->staged_value_bytes = 0u;
    *out_txn = (ninlil_storage_txn_t)&provider->txn_token;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mutation_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;

    if (provider == NULL
        || txn != (ninlil_storage_txn_t)&provider->txn_token
        || provider->txn_open == 0u
        || !bytes_view_valid(key, NINLIL_MFDT_V1_KEY_BYTES)
        || !mutable_view_valid(inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return provider->backing_port.ops->get(
        provider->backing_port.ops->user,
        provider->backing_txn,
        key,
        inout_value);
}

static ninlil_storage_status_t mutation_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;
    mutation_op_t *op;

    if (provider == NULL
        || txn != (ninlil_storage_txn_t)&provider->txn_token
        || provider->txn_open == 0u
        || provider->txn_mode != NINLIL_STORAGE_READ_WRITE
        || !bytes_view_valid(key, NINLIL_MFDT_V1_KEY_BYTES)
        || (value.length != 0u && value.data == NULL)
        || provider->staged_count >= MUTATION_MAX_OPS
        || value.length
            > MUTATION_VALUE_POOL_BYTES - provider->staged_value_bytes) {
        return NINLIL_STORAGE_CORRUPT;
    }
    op = &provider->staged[provider->staged_count];
    (void)memcpy(op->key, key.data, NINLIL_MFDT_V1_KEY_BYTES);
    op->value_offset = provider->staged_value_bytes;
    op->value_len = value.length;
    op->kind = 1u;
    if (value.length != 0u) {
        (void)memcpy(
            provider->staged_values + provider->staged_value_bytes,
            value.data,
            value.length);
    }
    provider->staged_value_bytes += value.length;
    provider->staged_count += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mutation_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;
    mutation_op_t *op;

    if (provider == NULL
        || txn != (ninlil_storage_txn_t)&provider->txn_token
        || provider->txn_open == 0u
        || provider->txn_mode != NINLIL_STORAGE_READ_WRITE
        || !bytes_view_valid(key, NINLIL_MFDT_V1_KEY_BYTES)
        || provider->staged_count >= MUTATION_MAX_OPS) {
        return NINLIL_STORAGE_CORRUPT;
    }
    op = &provider->staged[provider->staged_count];
    (void)memcpy(op->key, key.data, NINLIL_MFDT_V1_KEY_BYTES);
    op->kind = 2u;
    provider->staged_count += 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mutation_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;

    if (provider == NULL
        || txn != (ninlil_storage_txn_t)&provider->txn_token
        || provider->txn_open == 0u
        || provider->txn_mode != NINLIL_STORAGE_READ_ONLY) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return provider->backing_port.ops->iter_open(
        provider->backing_port.ops->user,
        provider->backing_txn,
        prefix,
        out_iter);
}

static ninlil_storage_status_t mutation_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;

    if (provider == NULL || provider->txn_open == 0u
        || provider->txn_mode != NINLIL_STORAGE_READ_ONLY) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return provider->backing_port.ops->iter_next(
        provider->backing_port.ops->user,
        iter,
        inout_key,
        inout_value);
}

static void mutation_iter_close(void *user, ninlil_storage_iter_t iter)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;

    if (provider != NULL) {
        provider->backing_port.ops->iter_close(
            provider->backing_port.ops->user,
            iter);
    }
}

static ninlil_storage_status_t mutation_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;

    if (provider == NULL
        || handle != (ninlil_storage_handle_t)provider) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return provider->backing_port.ops->capacity(
        provider->backing_port.ops->user,
        provider->backing_port.handle,
        out_capacity);
}

static ninlil_storage_status_t mutation_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;
    mfdt_v1_mutation_view_t view;
    ninlil_storage_status_t status = NINLIL_STORAGE_OK;
    uint8_t apply_count;
    uint8_t index;

    if (provider == NULL
        || txn != (ninlil_storage_txn_t)&provider->txn_token
        || provider->txn_open == 0u
        || provider->txn_mode != NINLIL_STORAGE_READ_WRITE
        || durability != NINLIL_DURABILITY_FULL
        || provider->staged_count == 0u) {
        return NINLIL_STORAGE_CORRUPT;
    }
    view = provider->armed != 0u
        ? provider->armed_view : MFDT_V1_MUTATION_PASS;
    provider->armed = 0u;

    if (view == MFDT_V1_MUTATION_OLD
        || view == MFDT_V1_MUTATION_ABSENT) {
        status = provider->backing_port.ops->rollback(
            provider->backing_port.ops->user,
            provider->backing_txn);
        reset_transaction(provider);
        return status == NINLIL_STORAGE_OK
            ? NINLIL_STORAGE_COMMIT_UNKNOWN : status;
    }

    apply_count = view == MFDT_V1_MUTATION_PARTIAL
        ? (uint8_t)1u : provider->staged_count;
    for (index = 0u; index < apply_count; ++index) {
        status = apply_op(
            provider,
            &provider->staged[index],
            view == MFDT_V1_MUTATION_THIRD && index == 0u);
        if (status != NINLIL_STORAGE_OK) {
            break;
        }
    }
    if (status == NINLIL_STORAGE_OK) {
        status = provider->backing_port.ops->commit(
            provider->backing_port.ops->user,
            provider->backing_txn,
            durability);
    } else {
        ninlil_storage_status_t rollback_status =
            provider->backing_port.ops->rollback(
                provider->backing_port.ops->user,
                provider->backing_txn);
        if (rollback_status != NINLIL_STORAGE_OK) {
            status = rollback_status;
        }
    }
    reset_transaction(provider);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    if (view == MFDT_V1_MUTATION_BOTH
        || view == MFDT_V1_MUTATION_EXTRA) {
        status = publish_injected_row(provider);
        if (status != NINLIL_STORAGE_OK) {
            return status;
        }
    }
    return view == MFDT_V1_MUTATION_PASS
        ? NINLIL_STORAGE_OK : NINLIL_STORAGE_COMMIT_UNKNOWN;
}

static ninlil_storage_status_t mutation_rollback(
    void *user,
    ninlil_storage_txn_t txn)
{
    mfdt_v1_typed_mutation_provider_t *provider =
        (mfdt_v1_typed_mutation_provider_t *)user;
    ninlil_storage_status_t status;
    ninlil_storage_status_t mutation_status = NINLIL_STORAGE_OK;
    uint8_t was_read_only;

    if (provider == NULL
        || txn != (ninlil_storage_txn_t)&provider->txn_token
        || provider->txn_open == 0u) {
        return NINLIL_STORAGE_CORRUPT;
    }
    was_read_only =
        provider->txn_mode == (uint8_t)NINLIL_STORAGE_READ_ONLY ? 1u : 0u;
    status = provider->backing_port.ops->rollback(
        provider->backing_port.ops->user,
        provider->backing_txn);
    reset_transaction(provider);
    if (status == NINLIL_STORAGE_OK && was_read_only != 0u
        && provider->snapshot_close_mutation_armed != 0u) {
        provider->snapshot_close_mutation_armed = 0u;
        mutation_status = publish_injected_row(provider);
        if (mutation_status == NINLIL_STORAGE_OK) {
            provider->snapshot_close_mutated = 1u;
        }
    }
    if (status == NINLIL_STORAGE_OK) {
        status = mutation_status;
    }
    return status;
}
