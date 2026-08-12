/* SPDX-License-Identifier: Apache-2.0 */
#include "runtime_terminal_owner_projection.h"

#include "runtime_internal.h"

#include <string.h>

static uint64_t terminal_owner_u64be(const uint8_t bytes[8])
{
    uint64_t value = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        value = (value << 8u) | (uint64_t)bytes[i];
    }
    return value;
}

ninlil_status_t ninlil_rt_private_has_pending_work_v1(
    ninlil_runtime_t *runtime, uint32_t *out_present)
{
    ninlil_status_t status;

    if (out_present == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_present = 0u;
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    *out_present = runtime->pending_work != 0u ? 1u : 0u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_private_terminal_owner_next_v1(
    ninlil_runtime_t *runtime,
    uint32_t *inout_cursor,
    uint32_t *inout_wrap_pending,
    ninlil_rt_private_terminal_owner_v1_t *out_owner,
    uint32_t *out_present,
    uint32_t *out_more)
{
    ninlil_status_t status;
    uint32_t i;

    if (inout_cursor == NULL || inout_wrap_pending == NULL
        || out_owner == NULL || out_present == NULL || out_more == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_owner, 0, sizeof(*out_owner));
    *out_present = 0u;
    *out_more = 0u;
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (*inout_cursor > runtime->transaction_capacity
        || (runtime->transaction_capacity != 0u
            && runtime->transactions == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    for (i = *inout_cursor; i < runtime->transaction_capacity; ++i) {
        const ninlil_rt_transaction_slot_t *slot = &runtime->transactions[i];
        uint64_t token;
        if (slot->in_use == 0u || slot->terminal == 0u) {
            *inout_cursor = i + 1u;
            continue;
        }
        if (slot->record_revision == 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        token = terminal_owner_u64be(slot->transaction_id.bytes);
        if (token == 0u) {
            token = terminal_owner_u64be(slot->transaction_id.bytes + 8u);
        }
        if (token == 0u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        *inout_cursor = i + 1u;
        out_owner->transaction_id = slot->transaction_id;
        out_owner->release_token = token;
        *out_present = 1u;
        *out_more = *inout_cursor < runtime->transaction_capacity ? 1u : 0u;
        return NINLIL_OK;
    }
    if (*inout_wrap_pending != 0u) {
        *inout_cursor = 0u;
        *inout_wrap_pending = 0u;
        *out_more = 1u;
    } else {
        *inout_cursor = runtime->transaction_capacity;
    }
    return NINLIL_OK;
}
