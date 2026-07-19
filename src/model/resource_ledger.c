#include "resource_ledger.h"

#include <stddef.h>
#include <string.h>

static int resource_kind_is_known(ninlil_resource_kind_t kind)
{
    return kind >= NINLIL_RESOURCE_SERVICE
        && kind <= NINLIL_RESOURCE_DEFERRED_TOKEN;
}

static int checked_total(
    const ninlil_model_capacity_entry_t *entry,
    uint64_t *out_total)
{
    if (entry->used > UINT64_MAX - entry->reserved) {
        return 0;
    }
    *out_total = entry->used + entry->reserved;
    return 1;
}

static int capacity_entry_is_valid(
    const ninlil_model_capacity_entry_t *entry)
{
    uint64_t total;

    if (!resource_kind_is_known(entry->kind)
        || entry->blocked > 1u
        || entry->counter_exhausted_marker > 1u
        || entry->capacity_epoch == 0u
        || !checked_total(entry, &total)
        || total > entry->limit
        || entry->high_water < total
        || entry->high_water > entry->limit) {
        return 0;
    }

    return entry->counter_exhausted_marker == 0u
        || (entry->capacity_epoch == UINT64_MAX && entry->blocked == 0u);
}

static int operation_shape_is_valid(
    const ninlil_model_capacity_transition_input_t *input)
{
    switch (input->operation) {
    case NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK:
    case NINLIL_MODEL_CAPACITY_COMMIT_RESERVED:
        return input->amount > 0u
            && input->used_release == 0u
            && input->reserved_release == 0u
            && input->reopens_blocked_class == 0u;
    case NINLIL_MODEL_CAPACITY_RELEASE:
        return input->amount == 0u
            && (input->used_release > 0u
                || input->reserved_release > 0u)
            && input->reopens_blocked_class <= 1u;
    default:
        return 0;
    }
}

static void copy_entry(
    ninlil_model_capacity_entry_t *destination,
    const ninlil_model_capacity_entry_t *source)
{
    destination->kind = source->kind;
    destination->limit = source->limit;
    destination->used = source->used;
    destination->reserved = source->reserved;
    destination->high_water = source->high_water;
    destination->capacity_epoch = source->capacity_epoch;
    destination->blocked = source->blocked;
    destination->counter_exhausted_marker =
        source->counter_exhausted_marker;
}

static ninlil_status_t reserve_or_block(
    const ninlil_model_capacity_transition_input_t *input,
    ninlil_model_capacity_transition_result_t *result)
{
    uint64_t total;
    uint64_t available;

    copy_entry(&result->next, &input->current);
    if (input->current.counter_exhausted_marker != 0u) {
        result->action = NINLIL_MODEL_CAPACITY_COUNTER_EXHAUSTED;
        return NINLIL_OK;
    }

    if (!checked_total(&input->current, &total)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    available = input->current.limit - total;
    if (input->amount <= available) {
        result->next.reserved += input->amount;
        total += input->amount;
        if (result->next.high_water < total) {
            result->next.high_water = total;
        }
        result->action = NINLIL_MODEL_CAPACITY_RESERVED;
        return NINLIL_OK;
    }

    if (input->current.blocked == 0u) {
        result->next.blocked = 1u;
        result->action = NINLIL_MODEL_CAPACITY_BLOCK_SET_REQUIRED;
    } else {
        result->action = NINLIL_MODEL_CAPACITY_ALREADY_BLOCKED;
    }
    return NINLIL_OK;
}

static ninlil_status_t commit_reserved(
    const ninlil_model_capacity_transition_input_t *input,
    ninlil_model_capacity_transition_result_t *result)
{
    if (input->amount > input->current.reserved) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    copy_entry(&result->next, &input->current);
    result->next.reserved -= input->amount;
    result->next.used += input->amount;
    result->action = NINLIL_MODEL_CAPACITY_COMMITTED;
    return NINLIL_OK;
}

static ninlil_status_t release_capacity(
    const ninlil_model_capacity_transition_input_t *input,
    ninlil_model_capacity_transition_result_t *result)
{
    if (input->used_release > input->current.used
        || input->reserved_release > input->current.reserved) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    copy_entry(&result->next, &input->current);
    result->next.used -= input->used_release;
    result->next.reserved -= input->reserved_release;
    result->action = NINLIL_MODEL_CAPACITY_RELEASED;

    if (input->current.blocked != 0u
        && input->reopens_blocked_class != 0u) {
        result->next.blocked = 0u;
        if (input->current.capacity_epoch == UINT64_MAX) {
            result->next.counter_exhausted_marker = 1u;
            result->counter_exhausted_marker_newly_set = 1u;
            result->action =
                NINLIL_MODEL_CAPACITY_RELEASED_EPOCH_EXHAUSTED;
        } else {
            result->next.capacity_epoch += 1u;
            result->action =
                NINLIL_MODEL_CAPACITY_RELEASED_AND_UNBLOCKED;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_capacity_entry_transition(
    const ninlil_model_capacity_transition_input_t *input,
    ninlil_model_capacity_transition_result_t *out_result)
{
    ninlil_status_t status;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));

    if (input == NULL || !operation_shape_is_valid(input)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!capacity_entry_is_valid(&input->current)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    switch (input->operation) {
    case NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK:
        status = reserve_or_block(input, out_result);
        break;
    case NINLIL_MODEL_CAPACITY_COMMIT_RESERVED:
        status = commit_reserved(input, out_result);
        break;
    case NINLIL_MODEL_CAPACITY_RELEASE:
        status = release_capacity(input, out_result);
        break;
    default:
        status = NINLIL_E_INVALID_ARGUMENT;
        break;
    }

    if (status != NINLIL_OK) {
        (void)memset(out_result, 0, sizeof(*out_result));
    }
    return status;
}

ninlil_status_t ninlil_model_resource_ledger_init(
    const ninlil_model_capacity_limits_t *limits,
    ninlil_model_resource_ledger_t *out_ledger)
{
    size_t index;

    if (out_ledger == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_ledger, 0, sizeof(*out_ledger));
    if (limits == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        out_ledger->entries[index].kind =
            (ninlil_resource_kind_t)(index + 1u);
        out_ledger->entries[index].limit = limits->values[index];
        out_ledger->entries[index].capacity_epoch = 1u;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_resource_ledger_project(
    const ninlil_model_resource_ledger_t *ledger,
    ninlil_model_capacity_snapshot_view_t *out_snapshot)
{
    size_t index;

    if (out_snapshot == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
    if (ledger == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        const ninlil_model_capacity_entry_t *source =
            &ledger->entries[index];
        ninlil_model_capacity_entry_view_t *destination =
            &out_snapshot->entries[index];

        if (source->kind != (ninlil_resource_kind_t)(index + 1u)
            || !capacity_entry_is_valid(source)) {
            (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
            return NINLIL_E_STORAGE_CORRUPT;
        }
        destination->kind = source->kind;
        destination->limit = source->limit;
        destination->used = source->used;
        destination->reserved = source->reserved;
        destination->high_water = source->high_water;
        destination->capacity_epoch = source->capacity_epoch;
    }
    out_snapshot->entry_count = NINLIL_MODEL_RESOURCE_KIND_COUNT;
    return NINLIL_OK;
}
