#include "resource_ledger_batch.h"

#include <stddef.h>
#include <string.h>

static int batch_operation_is_known(
    ninlil_model_capacity_batch_operation_t operation)
{
    return operation >= NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK
        && operation <= NINLIL_MODEL_CAPACITY_BATCH_RELEASE;
}

static int request_is_zero(
    const ninlil_model_capacity_batch_request_t *request)
{
    return request->kind == (ninlil_resource_kind_t)0u
        && request->reopens_blocked_class == 0u
        && request->amount == 0u
        && request->used_release == 0u
        && request->reserved_release == 0u;
}

static int request_shape_is_valid(
    const ninlil_model_capacity_batch_request_t *request,
    ninlil_model_capacity_batch_operation_t operation)
{
    if (request->kind < NINLIL_RESOURCE_SERVICE
        || request->kind > NINLIL_RESOURCE_DEFERRED_TOKEN) {
        return 0;
    }

    switch (operation) {
    case NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK:
    case NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED:
        return request->reopens_blocked_class == 0u
            && request->amount > 0u
            && request->used_release == 0u
            && request->reserved_release == 0u;
    case NINLIL_MODEL_CAPACITY_BATCH_RELEASE:
        return request->reopens_blocked_class <= 1u
            && request->amount == 0u
            && (request->used_release > 0u
                || request->reserved_release > 0u);
    default:
        return 0;
    }
}

static int batch_shape_is_valid(
    const ninlil_model_capacity_batch_input_t *input)
{
    size_t index;
    ninlil_resource_kind_t previous_kind = (ninlil_resource_kind_t)0u;

    if (!batch_operation_is_known(input->operation)
        || input->request_count == 0u
        || input->request_count > NINLIL_MODEL_RESOURCE_KIND_COUNT) {
        return 0;
    }

    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        const ninlil_model_capacity_batch_request_t *request =
            &input->requests[index];

        if (index < input->request_count) {
            if (!request_shape_is_valid(request, input->operation)
                || request->kind <= previous_kind) {
                return 0;
            }
            previous_kind = request->kind;
        } else if (!request_is_zero(request)) {
            return 0;
        }
    }
    return 1;
}

static void copy_capacity_entry(
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

static void copy_ledger(
    ninlil_model_resource_ledger_t *destination,
    const ninlil_model_resource_ledger_t *source)
{
    size_t index;

    (void)memset(destination, 0, sizeof(*destination));
    for (index = 0u; index < NINLIL_MODEL_RESOURCE_KIND_COUNT; ++index) {
        copy_capacity_entry(
            &destination->entries[index],
            &source->entries[index]);
    }
}

static uint32_t kind_mask(ninlil_resource_kind_t kind)
{
    return (uint32_t)1u << (kind - 1u);
}

static void make_entry_input(
    const ninlil_model_capacity_batch_input_t *batch,
    size_t request_index,
    const ninlil_model_capacity_entry_t *current,
    ninlil_model_capacity_transition_input_t *out_input)
{
    const ninlil_model_capacity_batch_request_t *request =
        &batch->requests[request_index];

    (void)memset(out_input, 0, sizeof(*out_input));
    copy_capacity_entry(&out_input->current, current);
    out_input->amount = request->amount;
    out_input->used_release = request->used_release;
    out_input->reserved_release = request->reserved_release;
    out_input->reopens_blocked_class = request->reopens_blocked_class;

    switch (batch->operation) {
    case NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK:
        out_input->operation = NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK;
        break;
    case NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED:
        out_input->operation = NINLIL_MODEL_CAPACITY_COMMIT_RESERVED;
        break;
    case NINLIL_MODEL_CAPACITY_BATCH_RELEASE:
        out_input->operation = NINLIL_MODEL_CAPACITY_RELEASE;
        break;
    default:
        break;
    }
}

static ninlil_status_t reserve_batch(
    const ninlil_model_capacity_batch_input_t *input,
    ninlil_model_capacity_batch_result_t *result)
{
    ninlil_model_resource_ledger_t working;
    size_t index;

    copy_ledger(&working, &input->current);
    for (index = 0u; index < input->request_count; ++index) {
        const ninlil_model_capacity_batch_request_t *request =
            &input->requests[index];
        size_t entry_index = (size_t)(request->kind - 1u);
        ninlil_model_capacity_transition_input_t entry_input;
        ninlil_model_capacity_transition_result_t entry_result;
        ninlil_status_t status;

        make_entry_input(
            input,
            index,
            &working.entries[entry_index],
            &entry_input);
        status = ninlil_model_capacity_entry_transition(
            &entry_input,
            &entry_result);
        if (status != NINLIL_OK) {
            return status;
        }
        if (entry_result.action == NINLIL_MODEL_CAPACITY_RESERVED) {
            copy_capacity_entry(
                &working.entries[entry_index],
                &entry_result.next);
            continue;
        }

        {
            size_t failure_index = index;
            size_t rollback_index = index;

            while (rollback_index > 0u) {
                const ninlil_model_capacity_batch_request_t
                    *rollback_request =
                    &input->requests[rollback_index - 1u];
                size_t rollback_entry_index =
                    (size_t)(rollback_request->kind - 1u);

                copy_capacity_entry(
                    &working.entries[rollback_entry_index],
                    &input->current.entries[rollback_entry_index]);
                --rollback_index;
            }
            result->rolled_back_count = (uint32_t)failure_index;
            result->failing_request_ordinal = (uint32_t)(failure_index + 1u);
        }
        copy_ledger(&result->next, &working);
        result->failing_kind = request->kind;
        result->failing_entry_action = entry_result.action;

        if (entry_result.action
            == NINLIL_MODEL_CAPACITY_BLOCK_SET_REQUIRED) {
            copy_capacity_entry(
                &result->next.entries[entry_index],
                &entry_result.next);
            result->action =
                NINLIL_MODEL_CAPACITY_BATCH_BLOCK_SET_REQUIRED;
            result->mutation_required = 1u;
            result->changed_kind_mask = kind_mask(request->kind);
        } else if (entry_result.action
            == NINLIL_MODEL_CAPACITY_ALREADY_BLOCKED) {
            result->action = NINLIL_MODEL_CAPACITY_BATCH_ALREADY_BLOCKED;
        } else if (entry_result.action
            == NINLIL_MODEL_CAPACITY_COUNTER_EXHAUSTED) {
            result->action =
                NINLIL_MODEL_CAPACITY_BATCH_COUNTER_EXHAUSTED;
        } else {
            return NINLIL_E_INVALID_STATE;
        }
        return NINLIL_OK;
    }

    copy_ledger(&result->next, &working);
    result->action = NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED;
    result->mutation_required = 1u;
    for (index = 0u; index < input->request_count; ++index) {
        result->changed_kind_mask |= kind_mask(input->requests[index].kind);
    }
    return NINLIL_OK;
}

static ninlil_status_t commit_or_release_batch(
    const ninlil_model_capacity_batch_input_t *input,
    ninlil_model_capacity_batch_result_t *result)
{
    ninlil_model_resource_ledger_t working;
    size_t index;

    copy_ledger(&working, &input->current);
    for (index = 0u; index < input->request_count; ++index) {
        const ninlil_model_capacity_batch_request_t *request =
            &input->requests[index];
        size_t entry_index = (size_t)(request->kind - 1u);
        ninlil_model_capacity_transition_input_t entry_input;
        ninlil_model_capacity_transition_result_t entry_result;
        ninlil_status_t status;

        make_entry_input(
            input,
            index,
            &working.entries[entry_index],
            &entry_input);
        status = ninlil_model_capacity_entry_transition(
            &entry_input,
            &entry_result);
        if (status != NINLIL_OK) {
            return status;
        }
        if (input->operation
                == NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED
            && entry_result.action != NINLIL_MODEL_CAPACITY_COMMITTED) {
            return NINLIL_E_INVALID_STATE;
        }
        if (input->operation == NINLIL_MODEL_CAPACITY_BATCH_RELEASE
            && entry_result.action != NINLIL_MODEL_CAPACITY_RELEASED
            && entry_result.action
                != NINLIL_MODEL_CAPACITY_RELEASED_AND_UNBLOCKED
            && entry_result.action
                != NINLIL_MODEL_CAPACITY_RELEASED_EPOCH_EXHAUSTED) {
            return NINLIL_E_INVALID_STATE;
        }
        copy_capacity_entry(
            &working.entries[entry_index],
            &entry_result.next);
        result->changed_kind_mask |= kind_mask(request->kind);
        if (entry_result.action
                == NINLIL_MODEL_CAPACITY_RELEASED_AND_UNBLOCKED
            || entry_result.action
                == NINLIL_MODEL_CAPACITY_RELEASED_EPOCH_EXHAUSTED) {
            result->unblocked_kind_mask |= kind_mask(request->kind);
        }
        if (entry_result.counter_exhausted_marker_newly_set != 0u) {
            result->counter_marker_newly_set_mask |=
                kind_mask(request->kind);
        }
    }

    copy_ledger(&result->next, &working);
    result->mutation_required = 1u;
    result->action = input->operation
            == NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED
        ? NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED
        : NINLIL_MODEL_CAPACITY_BATCH_ALL_RELEASED;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_capacity_batch_transition(
    const ninlil_model_capacity_batch_input_t *input,
    ninlil_model_capacity_batch_result_t *out_result)
{
    ninlil_model_capacity_snapshot_view_t validation_snapshot;
    ninlil_status_t status;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    if (input == NULL || !batch_shape_is_valid(input)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = ninlil_model_resource_ledger_project(
        &input->current,
        &validation_snapshot);
    if (status != NINLIL_OK) {
        return status;
    }

    if (input->operation
        == NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK) {
        status = reserve_batch(input, out_result);
    } else {
        status = commit_or_release_batch(input, out_result);
    }
    if (status != NINLIL_OK) {
        (void)memset(out_result, 0, sizeof(*out_result));
    }
    return status;
}
