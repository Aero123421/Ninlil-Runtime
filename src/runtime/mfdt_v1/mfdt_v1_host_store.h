/* SPDX-License-Identifier: Apache-2.0
 * ADR-0021 exact Host MFDT reference provider.
 *
 * Source-only, default-OFF, not installed, and not part of the public ABI.
 */
#ifndef NINLIL_MFDT_V1_HOST_STORE_H
#define NINLIL_MFDT_V1_HOST_STORE_H

#include "mfdt_v1_store_port.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_mfdt_v1_host_store ninlil_mfdt_v1_host_store_t;

typedef enum ninlil_mfdt_v1_host_store_operation {
    NINLIL_MFDT_V1_HOST_STORE_OP_OPEN = 0,
    NINLIL_MFDT_V1_HOST_STORE_OP_BEGIN = 1,
    NINLIL_MFDT_V1_HOST_STORE_OP_GET = 2,
    NINLIL_MFDT_V1_HOST_STORE_OP_PUT = 3,
    NINLIL_MFDT_V1_HOST_STORE_OP_ERASE = 4,
    NINLIL_MFDT_V1_HOST_STORE_OP_ITER_OPEN = 5,
    NINLIL_MFDT_V1_HOST_STORE_OP_ITER_NEXT = 6,
    NINLIL_MFDT_V1_HOST_STORE_OP_CAPACITY = 7,
    NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT = 8,
    NINLIL_MFDT_V1_HOST_STORE_OP_ROLLBACK = 9,
    NINLIL_MFDT_V1_HOST_STORE_OP_COUNT = 10
} ninlil_mfdt_v1_host_store_operation_t;

typedef enum ninlil_mfdt_v1_host_store_commit_truth {
    NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NONE = 0,
    NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_OLD = 1,
    NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NEW = 2
} ninlil_mfdt_v1_host_store_commit_truth_t;

/*
 * The provider RAM is deliberately outside the exact 280064-byte Host owner.
 * It uses fixed two-bank storage and does not grow or leak an append-only pool.
 */
ninlil_mfdt_v1_host_store_t *ninlil_mfdt_v1_host_store_create(void);
void ninlil_mfdt_v1_host_store_destroy(
    ninlil_mfdt_v1_host_store_t *store);

const ninlil_storage_ops_t *ninlil_mfdt_v1_host_store_ops(
    ninlil_mfdt_v1_host_store_t *store);

const ninlil_mfdt_v1_store_guarantees_t *
ninlil_mfdt_v1_host_store_guarantees(void);

/* Opens the provider's fixed MFDT namespace and initializes the private port. */
int ninlil_mfdt_v1_host_store_open_port(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_store_port_t *port);

/* Rolls back an adapter-owned FULL if necessary, then closes the typed handle. */
void ninlil_mfdt_v1_host_store_close_port(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_store_port_t *port);

/*
 * Script one otherwise-valid provider call. COMMIT_UNKNOWN is accepted only
 * for COMMIT with exact OLD/NEW truth; every other fault uses TRUTH_NONE.
 */
int ninlil_mfdt_v1_host_store_fault_next(
    ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_host_store_operation_t operation,
    ninlil_storage_status_t status,
    ninlil_mfdt_v1_host_store_commit_truth_t commit_truth);

uint64_t ninlil_mfdt_v1_host_store_call_count(
    const ninlil_mfdt_v1_host_store_t *store,
    ninlil_mfdt_v1_host_store_operation_t operation);

int ninlil_mfdt_v1_host_store_inventory(
    const ninlil_mfdt_v1_host_store_t *store,
    uint32_t *committed_keys_out,
    uint64_t *committed_logical_bytes_out,
    uint64_t *generation_out,
    uint64_t *full_count_out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_HOST_STORE_H */
