/* SPDX-License-Identifier: Apache-2.0
 * ADR-0021 Host MFDT private storage boundary.
 *
 * Source-only, default-OFF, not installed, and not part of the public ABI.
 */
#ifndef NINLIL_MFDT_V1_STORE_PORT_H
#define NINLIL_MFDT_V1_STORE_PORT_H

#include "mfdt_v1.h"
#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MFDT_V1_STORE_ATOMIC_FULL \
    ((uint32_t)1u << 0)
#define NINLIL_MFDT_V1_STORE_SNAPSHOT_ITER \
    ((uint32_t)1u << 1)
#define NINLIL_MFDT_V1_STORE_NO_PARTIAL_VIEW \
    ((uint32_t)1u << 2)

#define NINLIL_MFDT_V1_STORE_REQUIRED_FLAGS \
    (NINLIL_MFDT_V1_STORE_ATOMIC_FULL | \
     NINLIL_MFDT_V1_STORE_SNAPSHOT_ITER | \
     NINLIL_MFDT_V1_STORE_NO_PARTIAL_VIEW)

#define NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX \
    ((uint32_t)32u)
#define NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX \
    ((uint64_t)384476u)
#define NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX \
    ((uint64_t)50303u)
#define NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX \
    ((uint32_t)34u)
#define NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX \
    ((uint64_t)434779u)
#define NINLIL_MFDT_V1_HOST_FULL_OPS_MAX \
    ((uint32_t)4u)
#define NINLIL_MFDT_V1_HOST_FULL_PUT_IMAGES_MAX \
    ((uint32_t)2u)
#define NINLIL_MFDT_V1_STORE_ROW_OVERHEAD_BYTES \
    ((uint32_t)16u)
#define NINLIL_MFDT_V1_STORE_ROW_LOGICAL_FIXED_BYTES \
    ((uint32_t)(NINLIL_MFDT_V1_KEY_BYTES + \
                NINLIL_MFDT_V1_STORE_ROW_OVERHEAD_BYTES))

typedef struct ninlil_mfdt_v1_store_guarantees {
    uint32_t struct_size;
    uint32_t flags;
    uint32_t committed_keys_max;
    uint32_t begin_final_row_images_max;
    uint32_t full_ops_max;
    uint32_t reserved0;
    uint64_t committed_logical_bytes_max;
    uint64_t full_staging_logical_bytes_max;
    uint64_t begin_final_union_logical_bytes_max;
} ninlil_mfdt_v1_store_guarantees_t;

/*
 * The first three fields are the frozen provider boundary. Fields after them
 * are adapter-owned transaction accounting; callers must zero/init through
 * ninlil_mfdt_v1_store_port_init().
 */
typedef struct ninlil_mfdt_v1_store_port {
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle;
    ninlil_mfdt_v1_store_guarantees_t guarantees;
    ninlil_storage_txn_t rw_txn;
    uint64_t begin_committed_logical_bytes;
    uint64_t staged_logical_bytes;
    int poison_status;
    uint32_t begin_committed_keys;
    uint32_t staged_put_images;
    uint8_t staged_keys[NINLIL_MFDT_V1_HOST_FULL_OPS_MAX]
                       [NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t staged_kinds[NINLIL_MFDT_V1_HOST_FULL_OPS_MAX];
    uint8_t staged_ops;
    uint8_t full_open;
    uint8_t snapshot_open;
    uint8_t reserved0;
} ninlil_mfdt_v1_store_port_t;

typedef struct ninlil_mfdt_v1_store_snapshot {
    ninlil_mfdt_v1_store_port_t *port;
    ninlil_storage_txn_t txn;
    ninlil_storage_iter_t iter;
    uint8_t open;
    uint8_t reserved[7];
} ninlil_mfdt_v1_store_snapshot_t;

/* Known raw storage status -> private MFDT status, fail-closed for unknown. */
int ninlil_mfdt_v1_store_map_status(ninlil_storage_status_t status);

/* Requires every exact Host guarantee; larger providers are accepted. */
int ninlil_mfdt_v1_store_guarantees_validate(
    const ninlil_mfdt_v1_store_guarantees_t *guarantees);

/*
 * The caller owns and keeps ops/handle alive. Init does not open or close the
 * typed provider handle and does not infer guarantees from capacity().
 */
int ninlil_mfdt_v1_store_port_init(
    ninlil_mfdt_v1_store_port_t *port,
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    const ninlil_mfdt_v1_store_guarantees_t *guarantees);

/*
 * Begin one serialized RW FULL. Exact current MFDT inventory is supplied by
 * the coordinator and is used only for begin+final union preflight.
 */
int ninlil_mfdt_v1_store_full_begin(
    ninlil_mfdt_v1_store_port_t *port,
    uint32_t committed_keys,
    uint64_t committed_logical_bytes);

int ninlil_mfdt_v1_store_full_put(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len);

int ninlil_mfdt_v1_store_full_erase(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES]);

/*
 * COMMIT_UNKNOWN is always returned as ERR_COMMIT_UNKNOWN. The adapter never
 * promotes a provider's unknown outcome to external success.
 */
int ninlil_mfdt_v1_store_full_commit(
    ninlil_mfdt_v1_store_port_t *port);

int ninlil_mfdt_v1_store_full_rollback(
    ninlil_mfdt_v1_store_port_t *port);

/*
 * One-shot exact-key read. A missing key is successful with *present_out=0.
 * No read is admitted while a FULL or snapshot is open.
 */
int ninlil_mfdt_v1_store_read(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value_out,
    uint32_t value_cap,
    uint32_t *value_len_out,
    int *present_out);

/*
 * One read-only snapshot iterator is permitted. prefix_len is 0..20.
 * Snapshot next reports end with *done_out=1 and NINLIL_MFDT_V1_OK.
 */
int ninlil_mfdt_v1_store_snapshot_begin(
    ninlil_mfdt_v1_store_port_t *port,
    const uint8_t *prefix,
    uint32_t prefix_len,
    ninlil_mfdt_v1_store_snapshot_t *snapshot);

int ninlil_mfdt_v1_store_snapshot_next(
    ninlil_mfdt_v1_store_snapshot_t *snapshot,
    uint8_t key_out[NINLIL_MFDT_V1_KEY_BYTES],
    uint8_t *value_out,
    uint32_t value_cap,
    uint32_t *value_len_out,
    int *done_out);

int ninlil_mfdt_v1_store_snapshot_end(
    ninlil_mfdt_v1_store_snapshot_t *snapshot);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_STORE_PORT_H */
