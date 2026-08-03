/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_store_port.h"

#include <stdint.h>
#include <string.h>

typedef struct mfdt_store_memory_range {
    uintptr_t begin;
    uintptr_t end;
} mfdt_store_memory_range_t;

static int memory_range_make(
    const void *pointer,
    size_t length,
    mfdt_store_memory_range_t *out)
{
    const uintptr_t begin = (uintptr_t)pointer;

    if (pointer == NULL || out == NULL || length == 0u ||
        begin > UINTPTR_MAX - length) {
        return 0;
    }
    out->begin = begin;
    out->end = begin + length;
    return 1;
}

static int memory_ranges_overlap(
    const mfdt_store_memory_range_t *left,
    const mfdt_store_memory_range_t *right)
{
    return left->begin < right->end && right->begin < left->end;
}

static int port_init_binding_safe(
    const ninlil_mfdt_v1_store_port_t *port,
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    const ninlil_mfdt_v1_store_guarantees_t *guarantees)
{
    mfdt_store_memory_range_t port_range;
    mfdt_store_memory_range_t ops_range;
    mfdt_store_memory_range_t guarantees_range;
    const uintptr_t handle_address = (uintptr_t)handle;

    if (((uintptr_t)port % _Alignof(ninlil_mfdt_v1_store_port_t)) != 0u ||
        ((uintptr_t)ops % _Alignof(ninlil_storage_ops_t)) != 0u ||
        ((uintptr_t)guarantees %
         _Alignof(ninlil_mfdt_v1_store_guarantees_t)) != 0u ||
        !memory_range_make(port, sizeof(*port), &port_range) ||
        !memory_range_make(ops, sizeof(*ops), &ops_range) ||
        !memory_range_make(
            guarantees, sizeof(*guarantees), &guarantees_range) ||
        memory_ranges_overlap(&port_range, &ops_range) ||
        memory_ranges_overlap(&port_range, &guarantees_range) ||
        memory_ranges_overlap(&ops_range, &guarantees_range) ||
        (handle_address >= port_range.begin &&
         handle_address < port_range.end)) {
        return 0;
    }
    return 1;
}

static ninlil_bytes_view_t bytes_view(const uint8_t *data, uint32_t length)
{
    ninlil_bytes_view_t out;

    out.data = data;
    out.length = length;
    return out;
}

static int ops_are_complete(const ninlil_storage_ops_t *ops)
{
    return ops != NULL
        && ops->abi_version == NINLIL_ABI_VERSION
        && ops->struct_size >= sizeof(*ops)
        && ops->begin != NULL
        && ops->get != NULL
        && ops->put != NULL
        && ops->erase != NULL
        && ops->iter_open != NULL
        && ops->iter_next != NULL
        && ops->iter_close != NULL
        && ops->commit != NULL
        && ops->rollback != NULL;
}

static int port_is_initialized(const ninlil_mfdt_v1_store_port_t *port)
{
    return port != NULL
        && port->handle != NULL
        && ops_are_complete(port->ops)
        && ninlil_mfdt_v1_store_guarantees_validate(&port->guarantees)
            == NINLIL_MFDT_V1_OK;
}

static void reset_full_state(ninlil_mfdt_v1_store_port_t *port)
{
    port->rw_txn = NULL;
    port->begin_committed_logical_bytes = 0u;
    port->staged_logical_bytes = 0u;
    port->poison_status = NINLIL_MFDT_V1_OK;
    port->begin_committed_keys = 0u;
    port->staged_put_images = 0u;
    (void)memset(port->staged_keys, 0, sizeof(port->staged_keys));
    (void)memset(port->staged_kinds, 0, sizeof(port->staged_kinds));
    port->staged_ops = 0u;
    port->full_open = 0u;
}

static int key_was_staged(
    const ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES])
{
    uint8_t index;

    for (index = 0u; index < port->staged_ops; ++index) {
        if (memcmp(
                port->staged_keys[index],
                key,
                NINLIL_MFDT_V1_KEY_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

static int poison(
    ninlil_mfdt_v1_store_port_t *port,
    int status)
{
    if (port->poison_status == NINLIL_MFDT_V1_OK) {
        port->poison_status = status;
    }
    return status;
}

int ninlil_mfdt_v1_store_map_status(ninlil_storage_status_t status)
{
    switch (status) {
    case NINLIL_STORAGE_OK:
        return NINLIL_MFDT_V1_OK;
    case NINLIL_STORAGE_NOT_FOUND:
        return NINLIL_MFDT_V1_ERR_STATE;
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
    case NINLIL_STORAGE_NO_SPACE:
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    case NINLIL_STORAGE_IO_ERROR:
        return NINLIL_MFDT_V1_ERR_STORAGE;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    case NINLIL_STORAGE_BUSY:
        return NINLIL_MFDT_V1_ERR_BUSY;
    default:
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
}

int ninlil_mfdt_v1_store_guarantees_validate(
    const ninlil_mfdt_v1_store_guarantees_t *guarantees)
{
    if (guarantees == NULL
        || guarantees->struct_size < sizeof(*guarantees)
        || guarantees->reserved0 != 0u
        || (guarantees->flags & NINLIL_MFDT_V1_STORE_REQUIRED_FLAGS)
            != NINLIL_MFDT_V1_STORE_REQUIRED_FLAGS
        || guarantees->committed_keys_max
            < NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX
        || guarantees->begin_final_row_images_max
            < NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX
        || guarantees->full_ops_max
            < NINLIL_MFDT_V1_HOST_FULL_OPS_MAX
        || guarantees->committed_logical_bytes_max
            < NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX
        || guarantees->full_staging_logical_bytes_max
            < NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX
        || guarantees->begin_final_union_logical_bytes_max
            < NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_store_port_init(
    ninlil_mfdt_v1_store_port_t *port,
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    const ninlil_mfdt_v1_store_guarantees_t *guarantees)
{
    int rc;

    if (port == NULL || ops == NULL || handle == NULL ||
        guarantees == NULL ||
        !port_init_binding_safe(port, ops, handle, guarantees) ||
        !ops_are_complete(ops)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (ops->user != NULL) {
        mfdt_store_memory_range_t port_range;
        const uintptr_t user_address = (uintptr_t)ops->user;

        if (!memory_range_make(port, sizeof(*port), &port_range) ||
            (user_address >= port_range.begin &&
             user_address < port_range.end)) {
            return NINLIL_MFDT_V1_ERR_PARAM;
        }
    }
    rc = ninlil_mfdt_v1_store_guarantees_validate(guarantees);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    (void)memset(port, 0, sizeof(*port));
    port->ops = ops;
    port->handle = handle;
    port->guarantees = *guarantees;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_store_full_begin(
    ninlil_mfdt_v1_store_port_t *port,
    uint32_t committed_keys,
    uint64_t committed_logical_bytes)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t status;

    if (!port_is_initialized(port)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (port->full_open != 0u || port->snapshot_open != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (committed_keys > NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX
        || committed_logical_bytes
            > NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    status = port->ops->begin(
        port->ops->user,
        port->handle,
        NINLIL_STORAGE_READ_WRITE,
        &txn);
    if ((status == NINLIL_STORAGE_OK) != (txn != NULL)) {
        if (txn != NULL) {
            (void)port->ops->rollback(port->ops->user, txn);
        }
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(status);
    }
    reset_full_state(port);
    port->rw_txn = txn;
    port->begin_committed_keys = committed_keys;
    port->begin_committed_logical_bytes = committed_logical_bytes;
    port->full_open = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_store_full_put(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len)
{
    uint64_t logical_charge;
    ninlil_storage_status_t status;
    uint8_t index;

    if (!port_is_initialized(port) || port->full_open == 0u
        || port->rw_txn == NULL) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (key == NULL || (value == NULL && value_len != 0u)) {
        return poison(port, NINLIL_MFDT_V1_ERR_PARAM);
    }
    if (port->poison_status != NINLIL_MFDT_V1_OK) {
        return port->poison_status;
    }
    if (port->staged_ops >= NINLIL_MFDT_V1_HOST_FULL_OPS_MAX
        || key_was_staged(port, key)) {
        return poison(
            port,
            key_was_staged(port, key)
                ? NINLIL_MFDT_V1_ERR_STATE
                : NINLIL_MFDT_V1_ERR_CAPACITY);
    }
    logical_charge =
        (uint64_t)value_len + NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES;
    if (logical_charge
            > NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX
        || port->staged_logical_bytes
            > NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX
                - logical_charge
        || port->staged_put_images
            >= NINLIL_MFDT_V1_HOST_FULL_PUT_IMAGES_MAX
        || port->begin_committed_keys
                + port->staged_put_images + 1u
            > NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX
        || port->begin_committed_logical_bytes
            > NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX
                - (port->staged_logical_bytes + logical_charge)) {
        return poison(port, NINLIL_MFDT_V1_ERR_CAPACITY);
    }
    status = port->ops->put(
        port->ops->user,
        port->rw_txn,
        bytes_view(key, NINLIL_MFDT_V1_KEY_BYTES),
        bytes_view(value, value_len));
    if (status != NINLIL_STORAGE_OK) {
        return poison(port, ninlil_mfdt_v1_store_map_status(status));
    }
    index = port->staged_ops;
    (void)memcpy(
        port->staged_keys[index],
        key,
        NINLIL_MFDT_V1_KEY_BYTES);
    port->staged_kinds[index] = 1u;
    port->staged_ops = (uint8_t)(port->staged_ops + 1u);
    port->staged_put_images += 1u;
    port->staged_logical_bytes += logical_charge;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_store_full_erase(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES])
{
    ninlil_storage_status_t status;
    uint8_t index;

    if (!port_is_initialized(port) || port->full_open == 0u
        || port->rw_txn == NULL) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (key == NULL) {
        return poison(port, NINLIL_MFDT_V1_ERR_PARAM);
    }
    if (port->poison_status != NINLIL_MFDT_V1_OK) {
        return port->poison_status;
    }
    if (port->staged_ops >= NINLIL_MFDT_V1_HOST_FULL_OPS_MAX
        || key_was_staged(port, key)) {
        return poison(
            port,
            key_was_staged(port, key)
                ? NINLIL_MFDT_V1_ERR_STATE
                : NINLIL_MFDT_V1_ERR_CAPACITY);
    }
    status = port->ops->erase(
        port->ops->user,
        port->rw_txn,
        bytes_view(key, NINLIL_MFDT_V1_KEY_BYTES));
    if (status != NINLIL_STORAGE_OK) {
        return poison(port, ninlil_mfdt_v1_store_map_status(status));
    }
    index = port->staged_ops;
    (void)memcpy(
        port->staged_keys[index],
        key,
        NINLIL_MFDT_V1_KEY_BYTES);
    port->staged_kinds[index] = 2u;
    port->staged_ops = (uint8_t)(port->staged_ops + 1u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_store_full_commit(
    ninlil_mfdt_v1_store_port_t *port)
{
    ninlil_storage_status_t status;
    int rc;

    if (!port_is_initialized(port) || port->full_open == 0u
        || port->rw_txn == NULL) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (port->poison_status != NINLIL_MFDT_V1_OK
        || port->staged_ops == 0u) {
        rc = port->poison_status != NINLIL_MFDT_V1_OK
            ? port->poison_status : NINLIL_MFDT_V1_ERR_STATE;
        status = port->ops->rollback(port->ops->user, port->rw_txn);
        reset_full_state(port);
        if (status != NINLIL_STORAGE_OK) {
            return ninlil_mfdt_v1_store_map_status(status);
        }
        return rc;
    }
    status = port->ops->commit(
        port->ops->user,
        port->rw_txn,
        NINLIL_DURABILITY_FULL);
    reset_full_state(port);
    return ninlil_mfdt_v1_store_map_status(status);
}

int ninlil_mfdt_v1_store_full_rollback(
    ninlil_mfdt_v1_store_port_t *port)
{
    ninlil_storage_status_t status;

    if (!port_is_initialized(port) || port->full_open == 0u
        || port->rw_txn == NULL) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    status = port->ops->rollback(port->ops->user, port->rw_txn);
    reset_full_state(port);
    return ninlil_mfdt_v1_store_map_status(status);
}

int ninlil_mfdt_v1_store_read(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value_out,
    uint32_t value_cap,
    uint32_t *value_len_out,
    int *present_out)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t get_status;
    ninlil_storage_status_t end_status;
    int rc;

    if (!port_is_initialized(port) || key == NULL
        || value_len_out == NULL || present_out == NULL
        || (value_cap == 0u ? value_out != NULL : value_out == NULL)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    *value_len_out = 0u;
    *present_out = 0;
    if (port->full_open != 0u || port->snapshot_open != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    get_status = port->ops->begin(
        port->ops->user,
        port->handle,
        NINLIL_STORAGE_READ_ONLY,
        &txn);
    if ((get_status == NINLIL_STORAGE_OK) != (txn != NULL)) {
        if (txn != NULL) {
            (void)port->ops->rollback(port->ops->user, txn);
        }
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (get_status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(get_status);
    }
    value.data = value_out;
    value.capacity = value_cap;
    value.length = 0u;
    get_status = port->ops->get(
        port->ops->user,
        txn,
        bytes_view(key, NINLIL_MFDT_V1_KEY_BYTES),
        &value);
    *value_len_out = value.length;
    if (value.data != value_out || value.capacity != value_cap ||
        (get_status == NINLIL_STORAGE_OK && value.length > value_cap) ||
        (get_status == NINLIL_STORAGE_NOT_FOUND && value.length != 0u) ||
        (get_status == NINLIL_STORAGE_BUFFER_TOO_SMALL &&
         value.length <= value_cap) ||
        (get_status != NINLIL_STORAGE_OK &&
         get_status != NINLIL_STORAGE_NOT_FOUND &&
         get_status != NINLIL_STORAGE_BUFFER_TOO_SMALL &&
         value.length != 0u)) {
        rc = NINLIL_MFDT_V1_ERR_CORRUPT;
    } else if (get_status == NINLIL_STORAGE_OK) {
        *present_out = 1;
        rc = NINLIL_MFDT_V1_OK;
    } else if (get_status == NINLIL_STORAGE_NOT_FOUND) {
        rc = NINLIL_MFDT_V1_OK;
    } else {
        rc = ninlil_mfdt_v1_store_map_status(get_status);
    }
    end_status = port->ops->rollback(port->ops->user, txn);
    if (end_status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(end_status);
    }
    return rc;
}

int ninlil_mfdt_v1_store_snapshot_begin(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t *prefix,
    uint32_t prefix_len,
    ninlil_mfdt_v1_store_snapshot_t *snapshot)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t status;

    if (!port_is_initialized(port) || snapshot == NULL
        || prefix_len > NINLIL_MFDT_V1_KEY_BYTES
        || (prefix_len == 0u ? prefix != NULL : prefix == NULL)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (port->full_open != 0u || port->snapshot_open != 0u) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    (void)memset(snapshot, 0, sizeof(*snapshot));
    status = port->ops->begin(
        port->ops->user,
        port->handle,
        NINLIL_STORAGE_READ_ONLY,
        &txn);
    if ((status == NINLIL_STORAGE_OK) != (txn != NULL)) {
        if (txn != NULL) {
            (void)port->ops->rollback(port->ops->user, txn);
        }
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(status);
    }
    status = port->ops->iter_open(
        port->ops->user,
        txn,
        bytes_view(prefix, prefix_len),
        &iter);
    if ((status == NINLIL_STORAGE_OK) != (iter != NULL)) {
        if (iter != NULL) {
            port->ops->iter_close(port->ops->user, iter);
        }
        (void)port->ops->rollback(port->ops->user, txn);
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        ninlil_storage_status_t rollback_status =
            port->ops->rollback(port->ops->user, txn);
        if (rollback_status != NINLIL_STORAGE_OK) {
            return ninlil_mfdt_v1_store_map_status(rollback_status);
        }
        return ninlil_mfdt_v1_store_map_status(status);
    }
    snapshot->port = port;
    snapshot->txn = txn;
    snapshot->iter = iter;
    snapshot->open = 1u;
    port->snapshot_open = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_store_snapshot_next(
    ninlil_mfdt_v1_store_snapshot_t *snapshot,
    uint8_t key_out[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value_out,
    uint32_t value_cap,
    uint32_t *value_len_out,
    int *done_out)
{
    ninlil_mfdt_v1_store_port_t *port;
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t status;

    if (snapshot == NULL || snapshot->open == 0u
        || snapshot->port == NULL || snapshot->txn == NULL
        || snapshot->iter == NULL || key_out == NULL
        || value_len_out == NULL || done_out == NULL
        || (value_cap == 0u ? value_out != NULL : value_out == NULL)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    port = snapshot->port;
    if (port->snapshot_open == 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    *value_len_out = 0u;
    *done_out = 0;
    key.data = key_out;
    key.capacity = NINLIL_MFDT_V1_KEY_BYTES;
    key.length = 0u;
    value.data = value_out;
    value.capacity = value_cap;
    value.length = 0u;
    status = port->ops->iter_next(
        port->ops->user,
        snapshot->iter,
        &key,
        &value);
    *value_len_out = value.length;
    if (status == NINLIL_STORAGE_NOT_FOUND) {
        if (key.data != key_out || value.data != value_out ||
            key.capacity != NINLIL_MFDT_V1_KEY_BYTES ||
            value.capacity != value_cap ||
            key.length != 0u || value.length != 0u) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        *done_out = 1;
        return NINLIL_MFDT_V1_OK;
    }
    if (key.data != key_out || value.data != value_out ||
        key.capacity != NINLIL_MFDT_V1_KEY_BYTES ||
        value.capacity != value_cap) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status == NINLIL_STORAGE_OK &&
        (key.length != NINLIL_MFDT_V1_KEY_BYTES ||
         value.length > value_cap)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status == NINLIL_STORAGE_BUFFER_TOO_SMALL &&
        key.length <= NINLIL_MFDT_V1_KEY_BYTES &&
        value.length <= value_cap) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK &&
        status != NINLIL_STORAGE_BUFFER_TOO_SMALL &&
        (key.length != 0u || value.length != 0u)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        return ninlil_mfdt_v1_store_map_status(status);
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_store_snapshot_end(
    ninlil_mfdt_v1_store_snapshot_t *snapshot)
{
    ninlil_mfdt_v1_store_port_t *port;
    ninlil_storage_status_t status;

    if (snapshot == NULL || snapshot->open == 0u
        || snapshot->port == NULL || snapshot->txn == NULL
        || snapshot->iter == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    port = snapshot->port;
    port->ops->iter_close(port->ops->user, snapshot->iter);
    status = port->ops->rollback(port->ops->user, snapshot->txn);
    port->snapshot_open = 0u;
    (void)memset(snapshot, 0, sizeof(*snapshot));
    return ninlil_mfdt_v1_store_map_status(status);
}
