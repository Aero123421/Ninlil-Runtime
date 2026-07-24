#ifndef NINLIL_M4_LAB_MEMBERSHIP_H
#define NINLIL_M4_LAB_MEMBERSHIP_H

/*
 * M4 LAB site membership registry (docs/03 Membership lifecycle).
 * Bounded fixed table; no heap. Production-private.
 */

#include "m4_lab_primitive.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_M4_LAB_MEMBERSHIP_MAX ((uint32_t)32u)

typedef enum ninlil_m4_lab_membership_state {
    NINLIL_M4_LAB_MEMBERSHIP_NONE = 0,
    NINLIL_M4_LAB_MEMBERSHIP_PENDING = 1,
    NINLIL_M4_LAB_MEMBERSHIP_ACTIVE = 2,
    NINLIL_M4_LAB_MEMBERSHIP_SUSPENDED = 3,
    NINLIL_M4_LAB_MEMBERSHIP_REVOKED = 4
} ninlil_m4_lab_membership_state_t;

typedef struct ninlil_m4_lab_member_row {
    uint8_t stable_id_len;
    uint8_t stable_id[NINLIL_M4_LAB_STABLE_ID_MAX];
    ninlil_m4_lab_membership_state_t state;
    uint8_t pad[3];
    uint64_t membership_epoch;
} ninlil_m4_lab_member_row_t;

typedef struct ninlil_m4_lab_membership_registry {
    uint64_t site_membership_epoch;
    uint32_t count;
    uint32_t pad;
    ninlil_m4_lab_member_row_t rows[NINLIL_M4_LAB_MEMBERSHIP_MAX];
} ninlil_m4_lab_membership_registry_t;

void ninlil_m4_lab_membership_init(ninlil_m4_lab_membership_registry_t *reg);

ninlil_m4_lab_status_t ninlil_m4_lab_membership_register(
    ninlil_m4_lab_membership_registry_t *reg,
    ninlil_m4_lab_bytes_t stable_id,
    ninlil_m4_lab_membership_state_t state,
    uint64_t membership_epoch);

ninlil_m4_lab_status_t ninlil_m4_lab_membership_confirm_active(
    const ninlil_m4_lab_membership_registry_t *reg,
    ninlil_m4_lab_bytes_t stable_id,
    uint64_t membership_epoch);

const ninlil_m4_lab_member_row_t *ninlil_m4_lab_membership_lookup(
    const ninlil_m4_lab_membership_registry_t *reg,
    ninlil_m4_lab_bytes_t stable_id);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_M4_LAB_MEMBERSHIP_H */
