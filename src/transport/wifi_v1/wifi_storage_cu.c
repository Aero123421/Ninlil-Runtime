/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_storage_cu.h"

#include <string.h>

static ninlil_bytes_view_t view(const void *data, uint32_t length)
{
    ninlil_bytes_view_t result;
    result.data = (const uint8_t *)data;
    result.length = length;
    return result;
}

static ninlil_wifi_status_t map_storage(ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_WIFI_OK;
    }
    if (status == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN;
    }
    if (status == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (status == NINLIL_STORAGE_NO_SPACE
        || status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        return NINLIL_WIFI_CAPACITY;
    }
    if (status == NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
        return NINLIL_WIFI_UNSUPPORTED;
    }
    return NINLIL_WIFI_IO_ERROR;
}

static int ops_valid(const ninlil_storage_ops_t *storage)
{
    return storage != NULL && storage->open != NULL && storage->close != NULL
        && storage->begin != NULL && storage->get != NULL
        && storage->put != NULL && storage->commit != NULL;
}

static ninlil_wifi_status_t finish_read(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    ninlil_storage_txn_t transaction)
{
    ninlil_storage_status_t status;
    if (storage->rollback != NULL) {
        status = storage->rollback(storage_user, transaction);
    } else {
        status =
            storage->commit(storage_user, transaction, NINLIL_DURABILITY_FULL);
    }
    return map_storage(status);
}

ninlil_wifi_status_t ninlil_wifi_storage_read(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const char *key_utf8,
    uint8_t *out_value,
    uint32_t value_capacity,
    uint32_t *out_length,
    int *out_present)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_wifi_status_t finish_status;
    ninlil_mut_bytes_t value;
    size_t path_length;
    size_t key_length;

    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_present != NULL) {
        *out_present = 0;
    }
    if (!ops_valid(storage) || path_utf8 == NULL || key_utf8 == NULL
        || out_value == NULL || value_capacity == 0u || out_length == NULL
        || out_present == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    path_length = strlen(path_utf8);
    key_length = strlen(key_utf8);
    if (path_length == 0u || path_length > UINT32_MAX || key_length == 0u
        || key_length > UINT32_MAX) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }

    storage_status = storage->open(
        storage_user,
        view(path_utf8, (uint32_t)path_length),
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (storage_status != NINLIL_STORAGE_OK || handle == NULL) {
        return storage_status == NINLIL_STORAGE_OK
            ? NINLIL_WIFI_CORRUPT
            : map_storage(storage_status);
    }
    storage_status = storage->begin(
        storage_user, handle, NINLIL_STORAGE_READ_ONLY, &transaction);
    if (storage_status != NINLIL_STORAGE_OK || transaction == NULL) {
        storage->close(storage_user, handle);
        return storage_status == NINLIL_STORAGE_OK
            ? NINLIL_WIFI_CORRUPT
            : map_storage(storage_status);
    }
    value.data = out_value;
    value.capacity = value_capacity;
    value.length = 0u;
    storage_status = storage->get(
        storage_user,
        transaction,
        view(key_utf8, (uint32_t)key_length),
        &value);
    finish_status = finish_read(storage, storage_user, transaction);
    storage->close(storage_user, handle);
    if (finish_status != NINLIL_WIFI_OK) {
        return finish_status;
    }
    if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
        if (value.length != 0u) {
            return NINLIL_WIFI_CORRUPT;
        }
        return NINLIL_WIFI_OK;
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        return map_storage(storage_status);
    }
    if (value.length > value_capacity) {
        return NINLIL_WIFI_CORRUPT;
    }
    *out_length = value.length;
    *out_present = 1;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_storage_cu_put_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const char *key_utf8,
    const uint8_t *intended,
    uint32_t intended_length,
    ninlil_wifi_cu_class_t *out_class)
{
    uint8_t old_value[NINLIL_WIFI_STORAGE_CU_VALUE_MAX];
    uint8_t observed[NINLIL_WIFI_STORAGE_CU_VALUE_MAX];
    uint32_t old_length = 0u;
    uint32_t observed_length = 0u;
    int old_present = 0;
    int observed_present = 0;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_wifi_status_t status;
    size_t path_length;
    size_t key_length;

    if (out_class != NULL) {
        *out_class = NINLIL_WIFI_CU_NONE;
    }
    if (!ops_valid(storage) || path_utf8 == NULL || key_utf8 == NULL
        || intended == NULL || intended_length == 0u
        || intended_length > sizeof(old_value) || out_class == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    path_length = strlen(path_utf8);
    key_length = strlen(key_utf8);
    if (path_length == 0u || path_length > UINT32_MAX || key_length == 0u
        || key_length > UINT32_MAX) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }

    status = ninlil_wifi_storage_read(
        storage,
        storage_user,
        path_utf8,
        key_utf8,
        old_value,
        sizeof(old_value),
        &old_length,
        &old_present);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }

    storage_status = storage->open(
        storage_user,
        view(path_utf8, (uint32_t)path_length),
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (storage_status != NINLIL_STORAGE_OK || handle == NULL) {
        return storage_status == NINLIL_STORAGE_OK
            ? NINLIL_WIFI_CORRUPT
            : map_storage(storage_status);
    }
    storage_status = storage->begin(
        storage_user, handle, NINLIL_STORAGE_READ_WRITE, &transaction);
    if (storage_status != NINLIL_STORAGE_OK || transaction == NULL) {
        storage->close(storage_user, handle);
        return storage_status == NINLIL_STORAGE_OK
            ? NINLIL_WIFI_CORRUPT
            : map_storage(storage_status);
    }
    storage_status = storage->put(
        storage_user,
        transaction,
        view(key_utf8, (uint32_t)key_length),
        view(intended, intended_length));
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage->rollback != NULL) {
            (void)storage->rollback(storage_user, transaction);
        }
        storage->close(storage_user, handle);
        return map_storage(storage_status);
    }
    storage_status = storage->commit(
        storage_user, transaction, NINLIL_DURABILITY_FULL);
    /*
     * The handle that participated in an uncertain commit is never reused for
     * reconciliation.  Close it first, then open a fresh durable observation.
     */
    storage->close(storage_user, handle);
    if (storage_status != NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return map_storage(storage_status);
    }

    status = ninlil_wifi_storage_read(
        storage,
        storage_user,
        path_utf8,
        key_utf8,
        observed,
        sizeof(observed),
        &observed_length,
        &observed_present);
    if (status != NINLIL_WIFI_OK) {
        *out_class = NINLIL_WIFI_CU_OTHER;
        return NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN;
    }
    if (observed_present != 0 && observed_length == intended_length
        && memcmp(observed, intended, intended_length) == 0) {
        *out_class = NINLIL_WIFI_CU_INTENDED;
    } else if (
        old_present != 0 && observed_present != 0
        && observed_length == old_length
        && memcmp(observed, old_value, old_length) == 0) {
        *out_class = NINLIL_WIFI_CU_OLD;
    } else if (old_present == 0 && observed_present == 0) {
        *out_class = NINLIL_WIFI_CU_ABSENT;
    } else {
        *out_class = NINLIL_WIFI_CU_OTHER;
    }
    return NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN;
}
