/* SPDX-License-Identifier: Apache-2.0
 *
 * Test-only typed storage provider that materializes post-COMMIT_UNKNOWN
 * durable views. Never compile this fixture into production or ESP packages.
 */
#ifndef NINLIL_MFDT_V1_TYPED_MUTATION_PROVIDER_H
#define NINLIL_MFDT_V1_TYPED_MUTATION_PROVIDER_H

#include "mfdt_v1_host_store.h"

#include <stdint.h>

typedef struct mfdt_v1_typed_mutation_provider
    mfdt_v1_typed_mutation_provider_t;

typedef enum mfdt_v1_mutation_view {
    MFDT_V1_MUTATION_PASS = 0,
    MFDT_V1_MUTATION_OLD = 1,
    MFDT_V1_MUTATION_NEW = 2,
    MFDT_V1_MUTATION_PARTIAL = 3,
    MFDT_V1_MUTATION_BOTH = 4,
    MFDT_V1_MUTATION_EXTRA = 5,
    MFDT_V1_MUTATION_THIRD = 6,
    MFDT_V1_MUTATION_ABSENT = 7
} mfdt_v1_mutation_view_t;

mfdt_v1_typed_mutation_provider_t *
mfdt_v1_typed_mutation_provider_create(void);

void mfdt_v1_typed_mutation_provider_destroy(
    mfdt_v1_typed_mutation_provider_t *provider);

int mfdt_v1_typed_mutation_provider_open_port(
    mfdt_v1_typed_mutation_provider_t *provider,
    ninlil_mfdt_v1_store_port_t *port);

void mfdt_v1_typed_mutation_provider_close_port(
    mfdt_v1_typed_mutation_provider_t *provider,
    ninlil_mfdt_v1_store_port_t *port);

/*
 * Arm exactly one RW commit. PASS publishes normally; every other view returns
 * STORAGE_COMMIT_UNKNOWN after materializing the named durable view.
 */
int mfdt_v1_typed_mutation_provider_arm(
    mfdt_v1_typed_mutation_provider_t *provider,
    mfdt_v1_mutation_view_t view);

/*
 * BOTH/EXTRA may publish one additional row after the intended transaction.
 * The test controls the exact row so coordinator recovery sees the same typed
 * storage path as a real provider guarantee violation.
 */
int mfdt_v1_typed_mutation_provider_set_injected_row(
    mfdt_v1_typed_mutation_provider_t *provider,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len);

/*
 * Test the coordinator's cold-recovery snapshot authority.  The provider
 * publishes the supplied replacement row only after the first armed
 * read-only transaction closes.  When reject_followup_reads is non-zero, any
 * later read-only transaction fails with IO_ERROR.  A correct recovery either
 * publishes the first snapshot coherently or fails closed without a second
 * transaction; it can never assemble state from per-key re-reads.
 */
int mfdt_v1_typed_mutation_provider_arm_snapshot_close_mutation(
    mfdt_v1_typed_mutation_provider_t *provider,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len,
    int reject_followup_reads);

uint64_t mfdt_v1_typed_mutation_provider_ro_begin_count(
    const mfdt_v1_typed_mutation_provider_t *provider);

int mfdt_v1_typed_mutation_provider_inventory(
    const mfdt_v1_typed_mutation_provider_t *provider,
    uint32_t *committed_keys_out,
    uint64_t *committed_logical_bytes_out,
    uint64_t *generation_out,
    uint64_t *full_count_out);

#endif /* NINLIL_MFDT_V1_TYPED_MUTATION_PROVIDER_H */
