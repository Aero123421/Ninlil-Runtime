#include "runtime_store_orchestrator.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TEMP_VALUE_ALIGNMENT ((uint32_t)1u)

typedef struct read_result {
    ninlil_model_runtime_store_presence_class_t presence;
} read_result_t;

static int ranges_are_disjoint(
    const void *left,
    size_t left_length,
    const void *right,
    size_t right_length)
{
    uintptr_t left_start;
    uintptr_t right_start;

    if (left_length == 0u || right_length == 0u) {
        return 1;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_length > UINTPTR_MAX - left_start
        || right_length > UINTPTR_MAX - right_start) {
        return 0;
    }
    return left_start + left_length <= right_start
        || right_start + right_length <= left_start;
}

static int storage_status_is_known(ninlil_storage_status_t status)
{
    return status <= NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}

static int storage_status_requires_fence(ninlil_storage_status_t status)
{
    return status == NINLIL_STORAGE_COMMIT_UNKNOWN
        || !storage_status_is_known(status);
}

static ninlil_status_t map_storage_status(ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_BUSY) {
        return NINLIL_E_WOULD_BLOCK;
    }
    if (status == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    if (status == NINLIL_STORAGE_IO_ERROR) {
        return NINLIL_E_STORAGE;
    }
    if (status == NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

static void fence_handle(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_runtime_store_bootstrap_result_t *result)
{
    if (*inout_handle != NULL) {
        storage->close(storage->user, *inout_handle);
        *inout_handle = NULL;
    }
    result->reopen_required = 1u;
}

static ninlil_status_t rollback_read(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_storage_txn_t transaction,
    ninlil_status_t primary,
    ninlil_runtime_store_bootstrap_result_t *result)
{
    ninlil_storage_status_t status = storage->rollback(
        storage->user, transaction);

    if (status == NINLIL_STORAGE_OK) {
        return primary;
    }
    result->cleanup_status = status;
    fence_handle(storage, inout_handle, result);
    if (primary != NINLIL_OK) {
        return primary;
    }
    return map_storage_status(status);
}

static uint32_t value_capacity_for_index(uint32_t index)
{
    if (index == 0u) {
        return NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES;
    }
    if (index == 1u) {
        return NINLIL_MODEL_RUNTIME_STORE_IDENTITY_VALUE_BYTES;
    }
    if (index < 6u) {
        return NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES;
    }
    return NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES;
}

static uint8_t *value_buffer_for_index(
    ninlil_runtime_store_bootstrap_workspace_t *workspace,
    uint32_t index)
{
    uint32_t cursor = 0u;
    uint32_t current;

    for (current = 0u; current < index; ++current) {
        cursor += value_capacity_for_index(current);
    }
    return &workspace->phase.existing.encoded_values[cursor];
}

static ninlil_status_t scan_one_row(
    const ninlil_storage_ops_t *storage,
    const ninlil_allocator_ops_t *allocator,
    ninlil_storage_iter_t iterator,
    ninlil_runtime_store_bootstrap_workspace_t *workspace,
    ninlil_model_runtime_store_scan_result_t *inout_scan,
    uint32_t *inout_previous_key_length,
    uint32_t *out_fence,
    uint32_t *out_end)
{
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t status;
    uint8_t *temporary = NULL;
    uint32_t required_key = 0u;
    uint32_t required_value = 0u;
    ninlil_bytes_view_t key_view;
    ninlil_model_runtime_store_key_id_t key_id;
    ninlil_status_t key_status;
    int future;

    (void)memset(&key, 0, sizeof(key));
    (void)memset(&value, 0, sizeof(value));
    key.data = workspace->phase.scan.key;
    key.capacity = (uint32_t)sizeof(workspace->phase.scan.key);
    value.data = workspace->phase.scan.value;
    value.capacity = (uint32_t)sizeof(workspace->phase.scan.value);
    status = storage->iter_next(storage->user, iterator, &key, &value);
    if (status == NINLIL_STORAGE_NOT_FOUND) {
        if (key.length != 0u || value.length != 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        *out_end = 1u;
        return NINLIL_OK;
    }
    if (status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        required_key = key.length;
        required_value = value.length;
        if (required_key < 1u
            || required_key > (uint32_t)sizeof(workspace->phase.scan.key)
            || required_value
                <= (uint32_t)sizeof(workspace->phase.scan.value)
            || required_value > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        temporary = (uint8_t *)allocator->allocate(
            allocator->user, required_value, TEMP_VALUE_ALIGNMENT);
        if (temporary == NULL) {
            return NINLIL_E_CAPACITY_EXHAUSTED;
        }
        key.length = 0u;
        value.data = temporary;
        value.capacity = required_value;
        value.length = 0u;
        status = storage->iter_next(storage->user, iterator, &key, &value);
        if (status != NINLIL_STORAGE_OK) {
            allocator->deallocate(allocator->user, temporary,
                required_value, TEMP_VALUE_ALIGNMENT);
            if (storage_status_requires_fence(status)) {
                *out_fence = 1u;
            }
            if (status == NINLIL_STORAGE_BUFFER_TOO_SMALL
                || status == NINLIL_STORAGE_NOT_FOUND
                || !storage_status_is_known(status)
                || key.length != 0u || value.length != 0u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            return map_storage_status(status);
        }
        if (key.length != required_key || value.length != required_value) {
            allocator->deallocate(allocator->user, temporary,
                required_value, TEMP_VALUE_ALIGNMENT);
            return NINLIL_E_STORAGE_CORRUPT;
        }
    } else if (status == NINLIL_STORAGE_OK) {
        if (key.length < 1u || key.length > key.capacity
            || value.length > value.capacity) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    } else {
        if (storage_status_requires_fence(status)) {
            *out_fence = 1u;
        }
        if (key.length != 0u || value.length != 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return map_storage_status(status);
    }

    key_view.data = key.data;
    key_view.length = key.length;
    if (*inout_previous_key_length != 0u) {
        uint32_t common = *inout_previous_key_length < key.length
            ? *inout_previous_key_length : key.length;
        int order = memcmp(workspace->phase.scan.previous_key,
            key.data, common);
        if (order > 0
            || (order == 0 && *inout_previous_key_length >= key.length)) {
            if (temporary != NULL) {
                allocator->deallocate(allocator->user, temporary,
                    required_value, TEMP_VALUE_ALIGNMENT);
            }
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    (void)memcpy(workspace->phase.scan.previous_key,
        key.data, key.length);
    *inout_previous_key_length = key.length;
    key_status = ninlil_model_runtime_store_parse_key(key_view, &key_id);
    future = key_status == NINLIL_E_UNSUPPORTED;
    if (temporary != NULL) {
        allocator->deallocate(allocator->user, temporary,
            required_value, TEMP_VALUE_ALIGNMENT);
    }
    if (future) {
        if (*inout_scan
                == NINLIL_MODEL_RUNTIME_STORE_SCAN_CURRENT_OR_UNKNOWN_EXTRA) {
            *inout_scan = NINLIL_MODEL_RUNTIME_STORE_SCAN_MIXED;
        } else if (*inout_scan == NINLIL_MODEL_RUNTIME_STORE_SCAN_EMPTY) {
            *inout_scan =
                NINLIL_MODEL_RUNTIME_STORE_SCAN_RECOGNIZABLE_FUTURE;
        }
    } else {
        if (*inout_scan
                == NINLIL_MODEL_RUNTIME_STORE_SCAN_RECOGNIZABLE_FUTURE) {
            *inout_scan = NINLIL_MODEL_RUNTIME_STORE_SCAN_MIXED;
        } else if (*inout_scan == NINLIL_MODEL_RUNTIME_STORE_SCAN_EMPTY) {
            *inout_scan =
                NINLIL_MODEL_RUNTIME_STORE_SCAN_CURRENT_OR_UNKNOWN_EXTRA;
        }
    }
    *out_end = 0u;
    return NINLIL_OK;
}

static ninlil_status_t scan_empty_namespace(
    const ninlil_storage_ops_t *storage,
    const ninlil_allocator_ops_t *allocator,
    ninlil_storage_txn_t transaction,
    ninlil_runtime_store_bootstrap_workspace_t *workspace,
    ninlil_model_runtime_store_scan_result_t *out_scan,
    uint32_t *out_shape_violation,
    uint32_t *out_fence)
{
    ninlil_storage_iter_t iterator = NULL;
    ninlil_bytes_view_t prefix;
    ninlil_storage_status_t status;
    ninlil_status_t api_status = NINLIL_OK;
    uint32_t end = 0u;
    uint32_t previous_key_length = 0u;

    prefix.data = NULL;
    prefix.length = 0u;
    *out_scan = NINLIL_MODEL_RUNTIME_STORE_SCAN_EMPTY;
    (void)memset(&workspace->phase.scan, 0,
        sizeof(workspace->phase.scan));
    status = storage->iter_open(
        storage->user, transaction, prefix, &iterator);
    if ((status == NINLIL_STORAGE_OK) != (iterator != NULL)) {
        if (iterator != NULL) {
            storage->iter_close(storage->user, iterator);
        }
        *out_shape_violation = 1u;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(status)) {
            *out_fence = 1u;
        }
        return map_storage_status(status);
    }
    while (end == 0u && api_status == NINLIL_OK) {
        api_status = scan_one_row(storage, allocator, iterator,
            workspace, out_scan, &previous_key_length, out_fence, &end);
    }
    storage->iter_close(storage->user, iterator);
    return api_status;
}

static ninlil_status_t load_snapshot(
    const ninlil_storage_ops_t *storage,
    const ninlil_allocator_ops_t *allocator,
    ninlil_storage_handle_t *inout_handle,
    ninlil_runtime_store_bootstrap_workspace_t *workspace,
    ninlil_runtime_store_bootstrap_result_t *result,
    read_result_t *out_read)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_status_t primary = NINLIL_OK;
    ninlil_model_runtime_store_presence_input_t presence;
    uint32_t index;
    uint32_t shape_violation = 0u;
    uint32_t fence_after_cleanup = 0u;

    (void)memset(&presence, 0, sizeof(presence));
    storage_status = storage->begin(storage->user, *inout_handle,
        NINLIL_STORAGE_READ_ONLY, &transaction);
    if ((storage_status == NINLIL_STORAGE_OK) != (transaction != NULL)) {
        if (transaction != NULL) {
            ninlil_storage_status_t cleanup = storage->rollback(
                storage->user, transaction);
            if (cleanup != NINLIL_STORAGE_OK) {
                result->cleanup_status = cleanup;
            }
        }
        fence_handle(storage, inout_handle, result);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(storage_status)) {
            fence_handle(storage, inout_handle, result);
        }
        return map_storage_status(storage_status);
    }

    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_model_runtime_store_key_t key;
        ninlil_bytes_view_t key_view;
        ninlil_mut_bytes_t value;
        uint32_t capacity = value_capacity_for_index(index);

        (void)memset(&key, 0, sizeof(key));
        if (ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)(index + 1u), &key)
            != NINLIL_OK) {
            primary = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        key_view.data = key.bytes;
        key_view.length = key.length;
        (void)memset(&value, 0, sizeof(value));
        value.data = value_buffer_for_index(workspace, index);
        value.capacity = capacity;
        storage_status = storage->get(
            storage->user, transaction, key_view, &value);
        if (storage_status == NINLIL_STORAGE_OK) {
            if (value.length > value.capacity) {
                primary = NINLIL_E_STORAGE_CORRUPT;
                break;
            }
            presence.present_mask |= (uint32_t)1u << index;
            workspace->phase.existing.encoded.values[index].data =
                value.data;
            workspace->phase.existing.encoded.values[index].length =
                value.length;
        } else if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
            if (value.length != 0u) {
                primary = NINLIL_E_STORAGE_CORRUPT;
                break;
            }
        } else {
            if (value.length != 0u) {
                primary = NINLIL_E_STORAGE_CORRUPT;
            } else {
                primary = map_storage_status(storage_status);
            }
            if (storage_status_requires_fence(storage_status)) {
                fence_after_cleanup = 1u;
            }
            break;
        }
    }
    if (primary == NINLIL_OK && presence.present_mask == 0u) {
        primary = scan_empty_namespace(storage, allocator, transaction,
            workspace, &presence.zero_record_scan, &shape_violation,
            &fence_after_cleanup);
    }
    if (primary == NINLIL_OK) {
        primary = ninlil_model_runtime_store_classify_presence(
            &presence, &out_read->presence);
    }
    primary = rollback_read(storage, inout_handle, transaction,
        primary, result);
    if (shape_violation != 0u && *inout_handle != NULL) {
        fence_handle(storage, inout_handle, result);
    }
    if (fence_after_cleanup != 0u && *inout_handle != NULL) {
        fence_handle(storage, inout_handle, result);
    }
    return primary;
}

static ninlil_status_t rollback_write_failure(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_storage_txn_t transaction,
    ninlil_status_t primary,
    uint32_t force_fence,
    ninlil_runtime_store_bootstrap_result_t *result)
{
    ninlil_storage_status_t rollback_status = storage->rollback(
        storage->user, transaction);
    if (rollback_status != NINLIL_STORAGE_OK) {
        result->cleanup_status = rollback_status;
        fence_handle(storage, inout_handle, result);
    } else if (force_fence != 0u) {
        fence_handle(storage, inout_handle, result);
    }
    return primary;
}

static ninlil_status_t commit_new_bootstrap(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_runtime_store_hook_dispatcher_t *hooks,
    ninlil_runtime_store_bootstrap_workspace_t *workspace,
    ninlil_runtime_store_bootstrap_result_t *result)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_status_t storage_status;
    uint32_t index;

    storage_status = storage->begin(storage->user, *inout_handle,
        NINLIL_STORAGE_READ_WRITE, &transaction);
    if ((storage_status == NINLIL_STORAGE_OK) != (transaction != NULL)) {
        if (transaction != NULL) {
            ninlil_storage_status_t cleanup = storage->rollback(
                storage->user, transaction);
            if (cleanup != NINLIL_STORAGE_OK) {
                result->cleanup_status = cleanup;
            }
        }
        fence_handle(storage, inout_handle, result);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(storage_status)) {
            fence_handle(storage, inout_handle, result);
        }
        return map_storage_status(storage_status);
    }
    for (index = 0u;
         index < NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        ninlil_bytes_view_t key;
        ninlil_bytes_view_t value;
        ninlil_status_t status =
            ninlil_model_runtime_store_bootstrap_record_at(
                &workspace->phase.bootstrap.plan, index,
                &workspace->phase.bootstrap.record);
        if (status != NINLIL_OK) {
            return rollback_write_failure(storage, inout_handle,
                transaction, status, 0u, result);
        }
        key.data = workspace->phase.bootstrap.record.key.bytes;
        key.length = workspace->phase.bootstrap.record.key.length;
        value.data = workspace->phase.bootstrap.record.value;
        value.length = workspace->phase.bootstrap.record.value_length;
        storage_status = storage->put(
            storage->user, transaction, key, value);
        if (storage_status != NINLIL_STORAGE_OK) {
            return rollback_write_failure(storage, inout_handle,
                transaction, map_storage_status(storage_status),
                storage_status_requires_fence(storage_status) ? 1u : 0u,
                result);
        }
        (void)memset(&workspace->phase.bootstrap.record, 0xa5,
            sizeof(workspace->phase.bootstrap.record));
    }
    if (hooks != NULL && hooks->dispatch != NULL) {
        hooks->dispatch(hooks->user,
            NINLIL_RUNTIME_STORE_HOOK_BEFORE_NAMESPACE_BINDING_COMMIT);
    }
    storage_status = storage->commit(
        storage->user, transaction, NINLIL_DURABILITY_FULL);
    if (storage_status == NINLIL_STORAGE_OK) {
        if (hooks != NULL && hooks->dispatch != NULL) {
            hooks->dispatch(hooks->user,
                NINLIL_RUNTIME_STORE_HOOK_AFTER_NAMESPACE_BINDING_COMMIT);
        }
        result->outcome = NINLIL_RUNTIME_STORE_NEW_BOOTSTRAP_COMMITTED;
        return NINLIL_OK;
    }
    if (storage_status_requires_fence(storage_status)) {
        fence_handle(storage, inout_handle, result);
    }
    return map_storage_status(storage_status);
}

ninlil_status_t ninlil_runtime_store_orchestrate_bootstrap(
    const ninlil_storage_ops_t *storage,
    const ninlil_allocator_ops_t *allocator,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    const ninlil_runtime_store_hook_dispatcher_t *hooks,
    ninlil_runtime_store_bootstrap_workspace_t *workspace,
    ninlil_runtime_store_bootstrap_result_t *out_result)
{
    read_result_t read;
    ninlil_status_t status;
    ninlil_model_runtime_store_binding_comparison_t comparison;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(out_result, sizeof(*out_result),
            storage, storage == NULL ? 0u : sizeof(*storage))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            allocator, allocator == NULL ? 0u : sizeof(*allocator))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            inout_handle,
            inout_handle == NULL ? 0u : sizeof(*inout_handle))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            validation, validation == NULL ? 0u : sizeof(*validation))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            hooks, hooks == NULL ? 0u : sizeof(*hooks))
        || !ranges_are_disjoint(out_result, sizeof(*out_result),
            workspace, workspace == NULL ? 0u : sizeof(*workspace))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (storage == NULL || allocator == NULL || inout_handle == NULL
        || validation == NULL || workspace == NULL
        || !ranges_are_disjoint(workspace, sizeof(*workspace),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(validation, sizeof(*validation),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(validation, sizeof(*validation),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(storage, sizeof(*storage),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(storage, sizeof(*storage),
            inout_handle, sizeof(*inout_handle))
        || !ranges_are_disjoint(allocator, sizeof(*allocator),
            workspace, sizeof(*workspace))
        || !ranges_are_disjoint(allocator, sizeof(*allocator),
            inout_handle, sizeof(*inout_handle))
        || (hooks != NULL
            && !ranges_are_disjoint(hooks, sizeof(*hooks),
                workspace, sizeof(*workspace)))
        || (hooks != NULL
            && !ranges_are_disjoint(hooks, sizeof(*hooks),
                inout_handle, sizeof(*inout_handle)))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (*inout_handle == NULL || storage->close == NULL
        || storage->begin == NULL || storage->get == NULL
        || storage->put == NULL || storage->iter_open == NULL
        || storage->iter_next == NULL || storage->iter_close == NULL
        || storage->commit == NULL || storage->rollback == NULL
        || allocator->allocate == NULL || allocator->deallocate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(workspace, 0, sizeof(*workspace));
    status = ninlil_model_runtime_store_build_bootstrap_plan(
        validation, &workspace->phase.bootstrap.plan);
    if (status != NINLIL_OK) {
        return status;
    }
    workspace->candidate_binding = workspace->phase.bootstrap.plan.binding;
    (void)memset(&workspace->phase, 0, sizeof(workspace->phase));
    (void)memset(&read, 0, sizeof(read));
    status = load_snapshot(storage, allocator, inout_handle,
        workspace, out_result, &read);
    if (status != NINLIL_OK) {
        return status;
    }
    if (read.presence == NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NEW) {
        status = ninlil_model_runtime_store_build_bootstrap_plan(
            validation, &workspace->phase.bootstrap.plan);
        if (status != NINLIL_OK) {
            return status;
        }
        return commit_new_bootstrap(storage, inout_handle, hooks,
            workspace, out_result);
    }
    if (read.presence
        != NINLIL_MODEL_RUNTIME_STORE_PRESENCE_ALL_PRESENT_UNVALIDATED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_model_runtime_store_validate_snapshot(
        &workspace->phase.existing.encoded,
        &workspace->phase.existing.validated);
    if (status != NINLIL_OK) {
        return status;
    }
    comparison = NINLIL_MODEL_RUNTIME_STORE_BINDING_COMPARISON_NONE;
    status = ninlil_model_runtime_store_compare_binding(
        &workspace->phase.existing.validated,
        &workspace->candidate_binding, &comparison);
    if (status != NINLIL_OK) {
        return status;
    }
    if (comparison != NINLIL_MODEL_RUNTIME_STORE_BINDING_EXACT) {
        return NINLIL_E_UNSUPPORTED;
    }
    out_result->outcome =
        NINLIL_RUNTIME_STORE_EXISTING_PROFILE_EXACT_RECOVERY_REQUIRED;
    return NINLIL_OK;
}
