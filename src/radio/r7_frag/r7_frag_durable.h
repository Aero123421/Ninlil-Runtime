/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_R7_FRAG_DURABLE_H
#define NINLIL_R7_FRAG_DURABLE_H

/*
 * TEST/CRASH durability writepoint simulator for r7_frag session lab paths.
 *
 * SEMANTIC: R7_FRAG_TEST_DURABLE_SIMULATOR_NOT_N6
 * SEMANTIC: NOT_PRODUCTION_N6_CONTEXT_STORE
 * SEMANTIC: NOT_MFDT_DURABLE_CUSTODY
 *
 * FULL_OK / DEFINITE_FAILURE / COMMIT_UNKNOWN / CORRUPT classification only.
 * Host/session tests may use inject + crash/restart. Production N6/R2/R1
 * orchestration MUST NOT claim this as real durable counters or MFDT.
 */

#include "r7_frag_state.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_R7_FRAG_DUR_OK ((int32_t)0)
#define NINLIL_R7_FRAG_DUR_INVALID ((int32_t)1)
#define NINLIL_R7_FRAG_DUR_DEFINITE_FAILURE ((int32_t)2)
#define NINLIL_R7_FRAG_DUR_COMMIT_UNKNOWN ((int32_t)3)
#define NINLIL_R7_FRAG_DUR_CORRUPT ((int32_t)4)
#define NINLIL_R7_FRAG_DUR_NOT_FOUND ((int32_t)5)
#define NINLIL_R7_FRAG_DUR_BUSY ((int32_t)6)

#define NINLIL_R7_FRAG_DUR_RESULT_FULL_OK ((uint8_t)0u)
#define NINLIL_R7_FRAG_DUR_RESULT_DEFINITE_FAILURE ((uint8_t)1u)
#define NINLIL_R7_FRAG_DUR_RESULT_COMMIT_UNKNOWN ((uint8_t)2u)
#define NINLIL_R7_FRAG_DUR_RESULT_CORRUPT ((uint8_t)3u)

#define NINLIL_R7_FRAG_DUR_MAX_KEYS ((size_t)32u)
#define NINLIL_R7_FRAG_DUR_KEY_MAX ((size_t)48u)
#define NINLIL_R7_FRAG_DUR_VAL_MAX ((size_t)68u)

/* Inject for next commit only (0 = normal FULL_OK). */
#define NINLIL_R7_FRAG_DUR_INJECT_NONE ((uint8_t)0u)
#define NINLIL_R7_FRAG_DUR_INJECT_FAIL ((uint8_t)1u)
#define NINLIL_R7_FRAG_DUR_INJECT_CU ((uint8_t)2u)
#define NINLIL_R7_FRAG_DUR_INJECT_CORRUPT ((uint8_t)3u)

typedef struct ninlil_r7_frag_dur_record {
    uint8_t in_use;
    uint8_t key_len;
    uint8_t val_len;
    uint8_t key[NINLIL_R7_FRAG_DUR_KEY_MAX];
    uint8_t val[NINLIL_R7_FRAG_DUR_VAL_MAX];
} ninlil_r7_frag_dur_record;

typedef struct ninlil_r7_frag_dur_pending {
    uint8_t active;
    uint8_t old_present;
    uint8_t key_len;
    uint8_t old_len;
    uint8_t proposed_len;
    uint8_t key[NINLIL_R7_FRAG_DUR_KEY_MAX];
    uint8_t old_val[NINLIL_R7_FRAG_DUR_VAL_MAX];
    uint8_t proposed_val[NINLIL_R7_FRAG_DUR_VAL_MAX];
} ninlil_r7_frag_dur_pending;

/*
 * Caller/object-owned CU recovery workspace (not stack).
 * Single-owner non-reentrant: recover_cu sets live=1 for the call duration.
 * Zeroize after use / on store zeroize.
 */
typedef struct ninlil_r7_frag_dur_cu_workspace {
    uint8_t live;
    uint8_t reserved0[7];
    ninlil_r7_frag_state_cu_entry entries[NINLIL_R7_FRAG_STATE_CU_MAX_ENTRIES];
} ninlil_r7_frag_dur_cu_workspace;

typedef struct ninlil_r7_frag_dur_store {
    ninlil_r7_frag_dur_record rows[NINLIL_R7_FRAG_DUR_MAX_KEYS];
    ninlil_r7_frag_dur_pending pending[NINLIL_R7_FRAG_DUR_MAX_KEYS];
    size_t pending_count;
    uint8_t inject; /* one-shot on next commit */
    uint8_t fenced;
    uint32_t commit_count;
    uint32_t cu_count;
    /*
     * Optional caller/instance-owned CU workspace pointer (not embedded).
     * Required non-NULL for recover_cu. Keeps sizeof(store) free of 33KiB
     * CU entry arrays so ESP BSS budgets remain tractable.
     */
    ninlil_r7_frag_dur_cu_workspace *cu_ws;
} ninlil_r7_frag_dur_store;

void ninlil_r7_frag_dur_init(ninlil_r7_frag_dur_store *st);
void ninlil_r7_frag_dur_zeroize(ninlil_r7_frag_dur_store *st);
void ninlil_r7_frag_dur_set_inject(ninlil_r7_frag_dur_store *st, uint8_t inj);

/* Begin write-set; call put then commit. */
void ninlil_r7_frag_dur_begin(ninlil_r7_frag_dur_store *st);

int32_t ninlil_r7_frag_dur_put(
    ninlil_r7_frag_dur_store *st,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *proposed,
    size_t proposed_len);

/*
 * Commit write-set. Returns FULL_OK status 0, or DEFINITE_FAILURE /
 * COMMIT_UNKNOWN / CORRUPT. On CU, durable value may be old or proposed
 * (simulated by inject choosing proposed flip 50% — fixed: leave dual-truth
 * by applying proposed only on FULL_OK; CU leaves pre-state and sticky fence).
 */
int32_t ninlil_r7_frag_dur_commit(ninlil_r7_frag_dur_store *st);

int32_t ninlil_r7_frag_dur_get(
    const ninlil_r7_frag_dur_store *st,
    const uint8_t *key,
    size_t key_len,
    uint8_t *out_val,
    size_t out_cap,
    size_t *out_len);

/*
 * After COMMIT_UNKNOWN: classify pending write-set vs current store using
 * r7_frag_state_cu_classify. Clears fence only on ALL_OLD / ALL_PROPOSED.
 *
 * Requires st->cu_ws non-NULL (caller/instance-owned, not stack, not global).
 * Non-reentrant: nested recover_cu returns BUSY. Workspace zeroized on return.
 */
int32_t ninlil_r7_frag_dur_recover_cu(
    ninlil_r7_frag_dur_store *st,
    ninlil_r7_frag_state_cu_result *out_class);

/*
 * Snapshot entire store for crash/restart tests (schema v1 + CRC32).
 * Encode: sorted unique keys, reserved zeros, CRC trailer.
 * Decode: fail-closed — temp validate then commit; on any failure *st is
 * unchanged (no half-publish). klen must be 1..KEY_MAX; vlen 0..VAL_MAX.
 */
int32_t ninlil_r7_frag_dur_snapshot_encode(
    const ninlil_r7_frag_dur_store *st,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);

int32_t ninlil_r7_frag_dur_snapshot_decode(
    ninlil_r7_frag_dur_store *st,
    const uint8_t *in,
    size_t in_len);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_DURABLE_H */
