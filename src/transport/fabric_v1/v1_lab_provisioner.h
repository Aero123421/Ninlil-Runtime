/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_PROVISIONER_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_PROVISIONER_H

/*
 * Private ADR-0036 durable LAB provisioner.
 *
 * It coordinates the one V1 ordering that spans two Storage namespaces:
 * floor scan -> fresh N6 reset -> N6 install -> exact NLB1 FULL publish.
 * It is deliberately not an installed/public provisioning framework.
 */

#include "v1_lab_n6_owner.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_PROVISIONER_MAGIC ((uint32_t)0x9ac64172u)
#define NINLIL_V1_LAB_FLOOR_MAX ((uint8_t)4u)
#define NINLIL_V1_LAB_ACTIVE_PAIR_MAX ((uint8_t)2u)

#define NINLIL_V1_LAB_ADOPT_NONE ((uint8_t)0u)
#define NINLIL_V1_LAB_ADOPT_CONTROLLER ((uint8_t)1u)
#define NINLIL_V1_LAB_ADOPT_PEER ((uint8_t)2u)

typedef uint32_t ninlil_v1_lab_provision_status_t;
#define NINLIL_V1_LAB_PROVISION_OK \
    ((ninlil_v1_lab_provision_status_t)0u)
#define NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT \
    ((ninlil_v1_lab_provision_status_t)1u)
#define NINLIL_V1_LAB_PROVISION_INVALID_STATE \
    ((ninlil_v1_lab_provision_status_t)2u)
#define NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED \
    ((ninlil_v1_lab_provision_status_t)3u)
#define NINLIL_V1_LAB_PROVISION_STORAGE \
    ((ninlil_v1_lab_provision_status_t)4u)
#define NINLIL_V1_LAB_PROVISION_COMMIT_UNKNOWN \
    ((ninlil_v1_lab_provision_status_t)5u)
#define NINLIL_V1_LAB_PROVISION_CAPACITY \
    ((ninlil_v1_lab_provision_status_t)6u)
#define NINLIL_V1_LAB_PROVISION_CORRUPT \
    ((ninlil_v1_lab_provision_status_t)7u)
#define NINLIL_V1_LAB_PROVISION_CRYPTO \
    ((ninlil_v1_lab_provision_status_t)8u)
#define NINLIL_V1_LAB_PROVISION_FENCED \
    ((ninlil_v1_lab_provision_status_t)9u)

typedef struct ninlil_v1_lab_floor_record {
    uint8_t occupied;
    uint8_t reserved_zero[7];
    uint8_t pair_id[32];
    uint64_t pair_generation;
    uint64_t radio_membership_epoch;
    uint8_t secret_digests[4][32];
} ninlil_v1_lab_floor_record_t;

typedef struct ninlil_v1_lab_provisioner {
    uint32_t magic;
    uint8_t active;
    uint8_t fenced;
    uint8_t n6_started;
    uint8_t n6_reset_done;
    uint8_t floor_count;
    uint8_t active_pair_count;
    uint8_t local_controller_mode;
    uint8_t mode_fixed;
    uint8_t local_runtime_bound;
    uint8_t runtime_adopt_mode;
    uint8_t reserved_state[2];
    ninlil_n6_t *n6;
    ninlil_storage_ops_t storage;
    ninlil_n6_crypto_ops_t n6_crypto;
    ninlil_r7_crypto_provider r7_crypto;
    ninlil_r2_authority_clock_result_t authority_result;
    uint8_t local_runtime_id[16];
    uint64_t global_membership_floor;
    uint64_t boot_radio_membership_epoch;
    ninlil_v1_lab_floor_record_t floors[NINLIL_V1_LAB_FLOOR_MAX];
    uint8_t active_pair_ids[NINLIL_V1_LAB_ACTIVE_PAIR_MAX][32];
    ninlil_n6_status_t last_n6_status;
    ninlil_v1_lab_n6_owner_t n6_owner;
} ninlil_v1_lab_provisioner_t;

/*
 * Scans only the dedicated NLB1 floor namespace. N6 remains INIT and no
 * namespace mutation occurs until the first accepted install_pair call.
 */
ninlil_v1_lab_provision_status_t ninlil_v1_lab_provisioner_init(
    ninlil_v1_lab_provisioner_t *provisioner,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const uint8_t local_runtime_id[16],
    const ninlil_r2_authority_clock_result_t *authority_result);

/*
 * USB-parent bootstrap variant. The first accepted binding adopts its derived
 * Controller Runtime ID.
 */
ninlil_v1_lab_provision_status_t
ninlil_v1_lab_provisioner_init_controller(
    ninlil_v1_lab_provisioner_t *provisioner,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const ninlil_r2_authority_clock_result_t *authority_result);

/*
 * Generic peer bootstrap variant. The first accepted binding adopts the
 * endpoint opposite controller_side and then fixes that identity for the
 * remainder of the boot.
 */
ninlil_v1_lab_provision_status_t ninlil_v1_lab_provisioner_init_peer(
    ninlil_v1_lab_provisioner_t *provisioner,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const ninlil_r2_authority_clock_result_t *authority_result);

/*
 * Synchronous and failure-atomic at the publication boundary: handles are
 * returned only after exact NLB1 FULL commit succeeds.
 */
ninlil_v1_lab_provision_status_t ninlil_v1_lab_provisioner_install_pair(
    ninlil_v1_lab_provisioner_t *provisioner,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    ninlil_v1_lab_n6_handles_t *out_handles);

int ninlil_v1_lab_provisioner_is_fenced(
    const ninlil_v1_lab_provisioner_t *provisioner);

void ninlil_v1_lab_provisioner_clear(
    ninlil_v1_lab_provisioner_t *provisioner);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_PROVISIONER_H */
