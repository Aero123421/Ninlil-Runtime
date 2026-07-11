#include "domain_store_scanner.h"

#include "domain_store_codec.h"

#include <stdint.h>
#include <string.h>

static const uint8_t CURRENT_ROOT[8] = {
    0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
};

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

static int storage_ops_required_nonnull(const ninlil_storage_ops_t *storage)
{
    return storage != NULL
        && storage->begin != NULL
        && storage->get != NULL
        && storage->iter_open != NULL
        && storage->iter_next != NULL
        && storage->iter_close != NULL
        && storage->rollback != NULL
        && storage->close != NULL;
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

static int is_exact_family14_catalog_key(
    const uint8_t *key,
    uint32_t length)
{
    if (key == NULL || length < 9u) {
        return 0;
    }
    if (memcmp(key, CURRENT_ROOT, sizeof(CURRENT_ROOT)) != 0) {
        return 0;
    }
    if (length == 9u && (key[8] == 0x01u || key[8] == 0x02u)) {
        return 1;
    }
    if (length == 10u) {
        if (key[8] == 0x03u && key[9] >= 1u && key[9] <= 4u) {
            return 1;
        }
        if (key[8] == 0x04u && key[9] >= 1u && key[9] <= 11u) {
            return 1;
        }
    }
    return 0;
}

static int key_strictly_increases(
    const uint8_t *previous,
    uint32_t previous_length,
    const uint8_t *key,
    uint32_t key_length)
{
    uint32_t common;
    int order;

    common = previous_length < key_length ? previous_length : key_length;
    order = memcmp(previous, key, common);
    if (order < 0) {
        return 1;
    }
    if (order > 0) {
        return 0;
    }
    return key_length > previous_length;
}

static int begin_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    const ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_scan_workspace_t *workspace)
{
    const size_t session_bytes = sizeof(*session);
    const size_t workspace_bytes = sizeof(*workspace);
    const size_t ops_bytes = sizeof(*storage);
    const size_t handle_slot_bytes = sizeof(*inout_handle);

    if (!ranges_are_disjoint(session, session_bytes, workspace, workspace_bytes)
        || !ranges_are_disjoint(session, session_bytes, storage, ops_bytes)
        || !ranges_are_disjoint(
            session, session_bytes, inout_handle, handle_slot_bytes)
        || !ranges_are_disjoint(
            workspace, workspace_bytes, storage, ops_bytes)
        || !ranges_are_disjoint(
            workspace, workspace_bytes, inout_handle, handle_slot_bytes)
        || !ranges_are_disjoint(
            storage, ops_bytes, inout_handle, handle_slot_bytes)) {
        return 0;
    }
    return 1;
}

/*
 * out_result must not overlap session, bound workspace, bound ops object, or
 * bound handle slot. Validated before any cleanup/output mutation.
 */
static int result_alias_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_domain_scan_result_t *out_result)
{
    const size_t session_bytes = sizeof(*session);
    const size_t result_bytes = sizeof(*out_result);
    const ninlil_storage_ops_t *storage = session->bound_storage;
    ninlil_storage_handle_t *handle_slot = session->bound_handle_slot;
    ninlil_domain_scan_workspace_t *workspace = session->bound_workspace;

    if (storage == NULL || handle_slot == NULL || workspace == NULL) {
        return 0;
    }
    if (!ranges_are_disjoint(session, session_bytes, out_result, result_bytes)
        || !ranges_are_disjoint(
            workspace, sizeof(*workspace), out_result, result_bytes)
        || !ranges_are_disjoint(
            storage, sizeof(*storage), out_result, result_bytes)
        || !ranges_are_disjoint(
            handle_slot, sizeof(*handle_slot), out_result, result_bytes)) {
        return 0;
    }
    return 1;
}

static void set_sticky_primary(
    ninlil_domain_scan_session_t *session,
    ninlil_status_t status)
{
    if (session->has_sticky_primary == 0u) {
        session->has_sticky_primary = 1u;
        session->sticky_primary = status;
    }
}

static ninlil_status_t checked_inc_u64(uint64_t *counter)
{
    if (*counter == UINT64_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *counter += 1u;
    return NINLIL_OK;
}

/*
 * Close the ORIGINAL begin-time handle exactly once through bound_storage.
 * Clear *bound_handle_slot only if it still equals that original value.
 * Foreign slot contents and NULL slots are left untouched (never closed).
 * Double-close is prevented by original_handle_authority.
 */
static void fence_original_handle(ninlil_domain_scan_session_t *session)
{
    const ninlil_storage_ops_t *storage = session->bound_storage;
    ninlil_storage_handle_t *slot = session->bound_handle_slot;

    if (session->original_handle_authority != 0u
        && storage != NULL
        && session->bound_handle_value != NULL) {
        storage->close(storage->user, session->bound_handle_value);
        session->original_handle_authority = 0u;
        if (slot != NULL && *slot == session->bound_handle_value) {
            *slot = NULL;
        }
    } else {
        session->original_handle_authority = 0u;
    }
    session->reopen_required = 1u;
    session->fence_pending = 0u;
}

/*
 * Exact match only while scanner still holds authority: slot must equal the
 * original begin-time handle. NULL or foreign during a live session is drift
 * (unless authority was already consumed by a prior fence).
 */
static int handle_slot_exact_match(
    const ninlil_domain_scan_session_t *session)
{
    if (session->bound_handle_slot == NULL) {
        return 0;
    }
    if (session->original_handle_authority == 0u) {
        /* Already fenced/consumed; no live Port dependency on slot match. */
        return 1;
    }
    return *session->bound_handle_slot == session->bound_handle_value;
}

/*
 * Single cleanup tree (§15.6) on bound Port only:
 * 1) iter_close if live and parent still ACTIVE
 * 2) rollback if txn live (consumes remaining children)
 * 3) fence only when required, after children are consumed — always closes
 *    the original bound handle value, never a foreign slot replacement
 */
static ninlil_status_t cleanup_tree(
    ninlil_domain_scan_session_t *session,
    ninlil_status_t primary)
{
    ninlil_status_t outcome = primary;
    ninlil_storage_status_t rollback_status;
    const ninlil_storage_ops_t *storage = session->bound_storage;

    if (storage == NULL) {
        session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
        if (session->has_sticky_primary != 0u) {
            return session->sticky_primary;
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (session->iter_live != 0u && session->txn_live != 0u) {
        storage->iter_close(storage->user, session->iter);
        session->iter = NULL;
        session->iter_live = 0u;
    } else if (session->iter_live != 0u) {
        /* Parent already gone: do not call iter_close on consumed txn. */
        session->iter = NULL;
        session->iter_live = 0u;
    }

    if (session->txn_live != 0u) {
        rollback_status = storage->rollback(storage->user, session->txn);
        session->txn = NULL;
        session->txn_live = 0u;
        session->iter = NULL;
        session->iter_live = 0u;
        if (rollback_status != NINLIL_STORAGE_OK) {
            session->cleanup_status = rollback_status;
            fence_original_handle(session);
            if (session->has_sticky_primary == 0u) {
                outcome = map_storage_status(rollback_status);
            } else {
                outcome = session->sticky_primary;
            }
        }
    }

    if (session->fence_pending != 0u) {
        fence_original_handle(session);
    }

    /* Cleanup completed without a fence: the handle remains caller-owned,
     * and this terminal scanner session relinquishes close authority. */
    session->original_handle_authority = 0u;
    session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
    return outcome;
}

static ninlil_status_t aggregate_finalize_outcome(
    const ninlil_domain_scan_session_t *session,
    ninlil_status_t cleanup_outcome)
{
    if (session->has_sticky_primary != 0u) {
        return session->sticky_primary;
    }
    if (cleanup_outcome != NINLIL_OK) {
        return cleanup_outcome;
    }
    if (session->profile_mismatch != 0u
        || session->future_profile_candidate != 0u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (session->recognizable_future_seen != 0u) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

static void publish_result(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result,
    ninlil_status_t status,
    uint32_t adopted)
{
    out_result->adopted = adopted;
    out_result->status = status;
    out_result->reopen_required = session->reopen_required;
    out_result->cleanup_status = session->cleanup_status;
    out_result->family14_row_count = session->family14_row_count;
    out_result->current_domain_key_count = session->current_domain_key_count;
    out_result->ok_row_count = session->ok_row_count;
    out_result->recognizable_future_seen = session->recognizable_future_seen;
}

static ninlil_status_t classify_ok_row(
    ninlil_domain_scan_session_t *session,
    const ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length)
{
    ninlil_bytes_view_t key_view;
    ninlil_bytes_view_t value_view;
    ninlil_model_domain_key_class_t row_class;
    ninlil_status_t status;

    if (is_exact_family14_catalog_key(workspace->key, key_length)) {
        return checked_inc_u64(&session->family14_row_count);
    }

    key_view.data = workspace->key;
    key_view.length = key_length;
    value_view.data = value_length == 0u ? NULL : workspace->value;
    value_view.length = value_length;
    status = ninlil_model_domain_classify_row(key_view, value_view, &row_class);
    if (status != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (row_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_CURRENT) {
        return checked_inc_u64(&session->current_domain_key_count);
    }
    if (row_class == NINLIL_MODEL_DOMAIN_KEY_CLASS_RECOGNIZABLE_FUTURE) {
        session->recognizable_future_seen = 1u;
        return NINLIL_OK;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

static ninlil_status_t process_ok_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length)
{
    ninlil_status_t class_status;

    if (session->has_previous != 0u) {
        if (!key_strictly_increases(
                workspace->previous_key,
                session->previous_key_length,
                workspace->key,
                key_length)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }

    /*
     * Preflight total ok_row headroom before any classification sub-counter
     * or previous-key mutation. Then checked sub-counter, then previous-key
     * copy, then known-safe ok increment (never wraps; no partial diagnostics).
     */
    if (session->ok_row_count == UINT64_MAX) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    class_status = classify_ok_row(
        session, workspace, key_length, value_length);
    if (class_status != NINLIL_OK) {
        return class_status;
    }

    (void)memcpy(workspace->previous_key, workspace->key, key_length);
    session->previous_key_length = key_length;
    session->has_previous = 1u;
    session->ok_row_count += 1u;
    return NINLIL_OK;
}

static void bind_session(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace)
{
    session->bound_storage = storage;
    session->bound_handle_slot = inout_handle;
    session->bound_workspace = workspace;
    session->bound_handle_value = *inout_handle;
    session->original_handle_authority = 1u;
}

void ninlil_domain_scan_session_init(ninlil_domain_scan_session_t *session)
{
    if (session == NULL) {
        return;
    }
    /* Caller contract: only fresh/non-live storage. Not safe on live sessions. */
    (void)memset(session, 0, sizeof(*session));
    session->state = NINLIL_DOMAIN_SCAN_STATE_IDLE;
    session->sticky_primary = NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_begin(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_storage_status_t storage_status;
    ninlil_bytes_view_t prefix;
    ninlil_status_t primary;

    if (session == NULL || workspace == NULL || inout_handle == NULL
        || !storage_ops_required_nonnull(storage)
        || *inout_handle == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!begin_alias_ok(session, storage, inout_handle, workspace)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_IDLE) {
        return NINLIL_E_INVALID_STATE;
    }

    /* Bind before any Port call so cleanup always uses the correct provider. */
    bind_session(session, storage, inout_handle, workspace);

    storage_status = storage->begin(
        storage->user, *inout_handle, NINLIL_STORAGE_READ_ONLY, &transaction);
    if ((storage_status == NINLIL_STORAGE_OK) != (transaction != NULL)) {
        /* Handle-shape corruption: consume child if any, then fence. */
        if (transaction != NULL) {
            ninlil_storage_status_t cleanup = storage->rollback(
                storage->user, transaction);
            if (cleanup != NINLIL_STORAGE_OK) {
                session->cleanup_status = cleanup;
            }
        }
        session->fence_pending = 1u;
        fence_original_handle(session);
        session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(storage_status)) {
            fence_original_handle(session);
        } else {
            /* No scanner child was acquired; ownership returns to caller. */
            session->original_handle_authority = 0u;
        }
        session->state = NINLIL_DOMAIN_SCAN_STATE_DONE;
        primary = map_storage_status(storage_status);
        set_sticky_primary(session, primary);
        return primary;
    }

    session->txn = transaction;
    session->txn_live = 1u;

    prefix.data = NULL;
    prefix.length = 0u;
    storage_status = storage->iter_open(
        storage->user, transaction, prefix, &iterator);
    if ((storage_status == NINLIL_STORAGE_OK) != (iterator != NULL)) {
        /*
         * iter_open handle-shape corruption: consume abnormal iter if any,
         * then cleanup tree with fence pending so Storage is fenced even when
         * rollback succeeds.
         */
        if (iterator != NULL) {
            storage->iter_close(storage->user, iterator);
        }
        session->fence_pending = 1u;
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        return cleanup_tree(session, NINLIL_E_STORAGE_CORRUPT);
    }
    if (storage_status != NINLIL_STORAGE_OK) {
        if (storage_status_requires_fence(storage_status)) {
            session->fence_pending = 1u;
        }
        primary = map_storage_status(storage_status);
        set_sticky_primary(session, primary);
        return cleanup_tree(session, primary);
    }

    session->iter = iterator;
    session->iter_live = 1u;
    session->has_previous = 0u;
    session->previous_key_length = 0u;
    session->state = NINLIL_DOMAIN_SCAN_STATE_OPEN;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_advance(
    ninlil_domain_scan_session_t *session,
    uint32_t row_budget)
{
    uint32_t consumed = 0u;
    const ninlil_storage_ops_t *storage;
    ninlil_domain_scan_workspace_t *workspace;

    if (session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        return NINLIL_E_INVALID_STATE;
    }
    if (row_budget == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    storage = session->bound_storage;
    workspace = session->bound_workspace;
    if (storage == NULL || workspace == NULL
        || session->bound_handle_slot == NULL
        || !storage_ops_required_nonnull(storage)) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (handle_slot_exact_match(session) == 0) {
        /*
         * Drift (NULL or foreign while authority live): fail closed.
         * Cleanup later closes the ORIGINAL bound handle only, never foreign.
         */
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->fence_pending = 1u;
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (session->iter_live == 0u || session->txn_live == 0u) {
        set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return NINLIL_E_STORAGE_CORRUPT;
    }

    while (consumed < row_budget) {
        ninlil_mut_bytes_t key;
        ninlil_mut_bytes_t value;
        ninlil_storage_status_t storage_status;
        ninlil_status_t row_status;

        (void)memset(&key, 0, sizeof(key));
        (void)memset(&value, 0, sizeof(value));
        key.data = workspace->key;
        key.capacity = NINLIL_DOMAIN_SCAN_KEY_CAPACITY;
        key.length = 0u;
        value.data = workspace->value;
        value.capacity = NINLIL_DOMAIN_SCAN_VALUE_CAPACITY;
        value.length = 0u;

        storage_status = storage->iter_next(
            storage->user, session->iter, &key, &value);

        if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
                session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
                return NINLIL_E_STORAGE_CORRUPT;
            }
            session->state = NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED;
            return NINLIL_OK;
        }

        if (storage_status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (storage_status == NINLIL_STORAGE_OK) {
            if (key.data == NULL
                || key.length < 1u
                || key.length > key.capacity
                || key.length > NINLIL_DOMAIN_SCAN_KEY_CAPACITY
                || value.length > value.capacity
                || value.length > NINLIL_DOMAIN_SCAN_VALUE_CAPACITY
                || (value.length != 0u && value.data == NULL)) {
                set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
                session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
                return NINLIL_E_STORAGE_CORRUPT;
            }

            row_status = process_ok_row(
                session, workspace, key.length, value.length);
            if (row_status != NINLIL_OK) {
                set_sticky_primary(session, row_status);
                session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
                return row_status;
            }
            consumed += 1u;
            continue;
        }

        if (key.length != 0u || value.length != 0u) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (storage_status_requires_fence(storage_status)
            || !storage_status_is_known(storage_status)) {
            session->fence_pending = 1u;
        }
        if (!storage_status_is_known(storage_status)) {
            set_sticky_primary(session, NINLIL_E_STORAGE_CORRUPT);
            session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
            return NINLIL_E_STORAGE_CORRUPT;
        }
        row_status = map_storage_status(storage_status);
        set_sticky_primary(session, row_status);
        session->state = NINLIL_DOMAIN_SCAN_STATE_FAILED;
        return row_status;
    }

    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_scan_finalize(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result)
{
    ninlil_status_t cleanup_outcome;
    ninlil_status_t final_status;
    uint32_t adopted = 0u;
    ninlil_domain_scan_state_t prior_state;

    if (session == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED
        && session->state != NINLIL_DOMAIN_SCAN_STATE_FAILED) {
        return NINLIL_E_INVALID_STATE;
    }
    /* Alias check before any cleanup/output mutation. */
    if (!result_alias_ok(session, out_result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    prior_state = session->state;
    cleanup_outcome = cleanup_tree(session, NINLIL_OK);
    final_status = aggregate_finalize_outcome(session, cleanup_outcome);

    if (prior_state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED
        && session->has_sticky_primary == 0u
        && session->profile_mismatch == 0u
        && session->future_profile_candidate == 0u
        && session->recognizable_future_seen == 0u
        && cleanup_outcome == NINLIL_OK
        && final_status == NINLIL_OK
        && session->reopen_required == 0u) {
        adopted = 1u;
    }

    publish_result(session, out_result, final_status, adopted);
    return final_status;
}

ninlil_status_t ninlil_domain_scan_abort(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result)
{
    ninlil_status_t cleanup_outcome;
    ninlil_status_t final_status;

    if (session == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (session->state != NINLIL_DOMAIN_SCAN_STATE_OPEN
        && session->state != NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED
        && session->state != NINLIL_DOMAIN_SCAN_STATE_FAILED) {
        return NINLIL_E_INVALID_STATE;
    }
    if (!result_alias_ok(session, out_result)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    cleanup_outcome = cleanup_tree(session, NINLIL_OK);
    if (session->has_sticky_primary != 0u) {
        final_status = session->sticky_primary;
    } else if (cleanup_outcome != NINLIL_OK) {
        final_status = cleanup_outcome;
    } else {
        final_status = NINLIL_OK;
    }
    publish_result(session, out_result, final_status, 0u);
    return final_status;
}
