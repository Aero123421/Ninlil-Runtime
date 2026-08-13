/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_RUNTIME_V1_SPINE_DURABLE_H
#define NINLIL_RUNTIME_V1_SPINE_DURABLE_H

#include "runtime_internal.h"
#include "v1_durable_allowlist.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_V1_SERVICE_LEDGER_KEY_MAX_BYTES ((uint32_t)155u)
#define NINLIL_RT_V1_SERVICE_LEDGER_VALUE_MAX_BYTES ((uint32_t)768u)

/*
 * Build the stable durable SERVICE registry key for a descriptor identity.
 * Key identity is local_application_instance + namespace + service + revision.
 */
ninlil_status_t ninlil_rt_v1_spine_service_ledger_key(
    const ninlil_service_descriptor_t *descriptor,
    uint8_t *out_key,
    uint32_t out_capacity,
    uint32_t *out_length);

/*
 * Encode semantic SERVICE registry + current quota window into V1-LAB ledger
 * value bytes (NSL1 envelope + CRC32C).  Pointer/callback state is never
 * persisted.
 */
ninlil_status_t ninlil_rt_v1_spine_service_ledger_encode(
    const ninlil_rt_service_slot_t *slot,
    uint8_t *out_bytes,
    uint32_t out_capacity,
    uint32_t *out_length);

/*
 * Decode NSL1 SERVICE ledger into a service slot.  Restored slots are always
 * unattached (callbacks zero, attached=0).  Public handle is filled by the
 * caller after slot index assignment.
 */
ninlil_status_t ninlil_rt_v1_spine_service_ledger_decode(
    ninlil_bytes_view_t record,
    ninlil_rt_service_slot_t *out_slot);

/*
 * FULL durable first registration of a SERVICE registry row.  Publishes only
 * after commit OK; COMMIT_UNKNOWN fences mutation.
 */
ninlil_status_t ninlil_rt_v1_spine_service_register_commit(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    uint32_t slot_index);

/* FULL durable first SERVICE-capacity refusal (blocked=1). */
ninlil_status_t ninlil_rt_v1_spine_service_capacity_reject_commit(
    ninlil_runtime_t *runtime);

/*
 * Stage SERVICE ledger put into an open RW txn under the given writer-gate
 * operation. First registration uses SERVICE_REGISTER_COMMIT; admission
 * quota rewrite uses SUBMIT_ADMISSION_COMMIT; origin terminal FULL uses
 * the terminal delivery/cancel/discard operation (allowlist must include
 * SPINE_SERVICE_MARKER for that op).
 */
ninlil_status_t ninlil_rt_v1_spine_service_ledger_stage(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t txn,
    const ninlil_rt_service_slot_t *slot,
    ninlil_v1_durable_operation_t operation);

/*
 * Restart path: scan durable SERVICE ledger rows into unattached service
 * slots. Must run after storage recovery and before transaction/capacity
 * restart validation so SERVICE used can be checked against the restored
 * semantic registry count. Never installs callbacks or publishes handles.
 */
ninlil_status_t ninlil_rt_v1_spine_service_restore(
    ninlil_runtime_t *runtime);

/*
 * Classify whether a durable quota window identity matches the trusted sample.
 * Returns 1 when same epoch + same floor(now/window) bucket; 0 when a new
 * bucket should be evaluated from zero counters (epoch/window mismatch).
 * Returns -1 for fail-closed clock/identity errors.
 */
int ninlil_rt_v1_spine_quota_window_is_current(
    const ninlil_rt_service_slot_t *slot,
    const ninlil_time_sample_t *sample);

ninlil_status_t ninlil_rt_v1_spine_submit_admission(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result);

ninlil_status_t ninlil_rt_v1_spine_cancel_admission(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result);

/*
 * Dual-truth row class for independent map / TX durable rows after CU.
 * BOTH means map and TX both present and equal to proposed; CORRUPT covers
 * mixed or third-value observations.
 */
typedef enum ninlil_rt_v1_map_truth_class {
    NINLIL_RT_V1_MAP_TRUTH_ABSENT = 0,
    NINLIL_RT_V1_MAP_TRUTH_OLD = 1,
    NINLIL_RT_V1_MAP_TRUTH_PROPOSED = 2,
    NINLIL_RT_V1_MAP_TRUTH_BOTH = 3,
    NINLIL_RT_V1_MAP_TRUTH_THIRD = 4,
    NINLIL_RT_V1_MAP_TRUTH_CORRUPT = 5,
    NINLIL_RT_V1_MAP_TRUTH_MIXED = 6
} ninlil_rt_v1_map_truth_class_t;

/*
 * Read-classify independent IDEMPOTENCY_MAP (+ optional EVENT_ID_MAP) against
 * proposed admission snapshot. Fail-closed classes yield no publication path.
 */
ninlil_status_t ninlil_rt_v1_map_read_classify(
    ninlil_runtime_t *runtime,
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_digest256_t *canonical_digest,
    const ninlil_id128_t *proposed_txn_id,
    ninlil_rt_v1_map_truth_class_t *out_class);

#ifdef __cplusplus
}
#endif

#endif
