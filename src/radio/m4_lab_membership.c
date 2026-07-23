/*
 * M4 LAB site membership registry.
 */

#include "m4_lab_membership.h"

#include <string.h>

static int m4_member_id_equal(
    ninlil_m4_lab_bytes_t a,
    ninlil_m4_lab_bytes_t b)
{
    if (a.length != b.length) {
        return 0;
    }
    if (a.length == 0u) {
        return 0;
    }
    return (memcmp(a.bytes, b.bytes, (size_t)a.length) == 0) ? 1 : 0;
}

void ninlil_m4_lab_membership_init(ninlil_m4_lab_membership_registry_t *reg)
{
    if (reg == NULL) {
        return;
    }
    (void)memset(reg, 0, sizeof(*reg));
}

ninlil_m4_lab_status_t ninlil_m4_lab_membership_register(
    ninlil_m4_lab_membership_registry_t *reg,
    ninlil_m4_lab_bytes_t stable_id,
    ninlil_m4_lab_membership_state_t state,
    uint64_t membership_epoch)
{
    uint32_t index;
    ninlil_m4_lab_member_row_t *row;

    if (reg == NULL || stable_id.bytes == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (stable_id.length == 0u
        || stable_id.length > NINLIL_M4_LAB_STABLE_ID_MAX
        || membership_epoch == 0u) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (state == NINLIL_M4_LAB_MEMBERSHIP_NONE) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    for (index = 0u; index < reg->count; index++) {
        ninlil_m4_lab_bytes_t existing = {
            reg->rows[index].stable_id,
            reg->rows[index].stable_id_len
        };
        if (m4_member_id_equal(stable_id, existing) != 0) {
            reg->rows[index].state = state;
            reg->rows[index].membership_epoch = membership_epoch;
            if (membership_epoch > reg->site_membership_epoch) {
                reg->site_membership_epoch = membership_epoch;
            }
            return NINLIL_M4_LAB_OK;
        }
    }

    if (reg->count >= NINLIL_M4_LAB_MEMBERSHIP_MAX) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    row = &reg->rows[reg->count];
    (void)memset(row, 0, sizeof(*row));
    row->stable_id_len = stable_id.length;
    (void)memcpy(row->stable_id, stable_id.bytes, (size_t)stable_id.length);
    row->state = state;
    row->membership_epoch = membership_epoch;
    reg->count += 1u;
    if (membership_epoch > reg->site_membership_epoch) {
        reg->site_membership_epoch = membership_epoch;
    }
    return NINLIL_M4_LAB_OK;
}

ninlil_m4_lab_status_t ninlil_m4_lab_membership_confirm_active(
    const ninlil_m4_lab_membership_registry_t *reg,
    ninlil_m4_lab_bytes_t stable_id,
    uint64_t membership_epoch)
{
    const ninlil_m4_lab_member_row_t *row;

    if (reg == NULL || stable_id.bytes == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    row = ninlil_m4_lab_membership_lookup(reg, stable_id);
    if (row == NULL) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (row->state != NINLIL_M4_LAB_MEMBERSHIP_ACTIVE) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    if (row->membership_epoch != membership_epoch) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }
    return NINLIL_M4_LAB_OK;
}

const ninlil_m4_lab_member_row_t *ninlil_m4_lab_membership_lookup(
    const ninlil_m4_lab_membership_registry_t *reg,
    ninlil_m4_lab_bytes_t stable_id)
{
    uint32_t index;

    if (reg == NULL || stable_id.bytes == NULL || stable_id.length == 0u) {
        return NULL;
    }
    for (index = 0u; index < reg->count; index++) {
        ninlil_m4_lab_bytes_t existing = {
            reg->rows[index].stable_id,
            reg->rows[index].stable_id_len
        };
        if (m4_member_id_equal(stable_id, existing) != 0) {
            return &reg->rows[index];
        }
    }
    return NULL;
}
