#ifndef NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_H
#define NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_H

#include "runtime_lifecycle_model.h"
#include "runtime_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MODEL_RUNTIME_STORE_PRESENT_ALL_MASK ((uint32_t)0x1ffffu)

typedef enum ninlil_model_runtime_store_scan_result {
    NINLIL_MODEL_RUNTIME_STORE_SCAN_NOT_CONFIRMED = 0,
    NINLIL_MODEL_RUNTIME_STORE_SCAN_EMPTY = 1,
    NINLIL_MODEL_RUNTIME_STORE_SCAN_CURRENT_OR_UNKNOWN_EXTRA = 2,
    NINLIL_MODEL_RUNTIME_STORE_SCAN_RECOGNIZABLE_FUTURE = 3,
    NINLIL_MODEL_RUNTIME_STORE_SCAN_MIXED = 4
} ninlil_model_runtime_store_scan_result_t;

typedef struct ninlil_model_runtime_store_presence_input {
    uint32_t present_mask;
    ninlil_model_runtime_store_scan_result_t zero_record_scan;
} ninlil_model_runtime_store_presence_input_t;

typedef enum ninlil_model_runtime_store_presence_class {
    NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NONE = 0,
    NINLIL_MODEL_RUNTIME_STORE_PRESENCE_NEW = 1,
    NINLIL_MODEL_RUNTIME_STORE_PRESENCE_ALL_PRESENT_UNVALIDATED = 2
} ninlil_model_runtime_store_presence_class_t;

typedef enum ninlil_model_runtime_store_binding_comparison {
    NINLIL_MODEL_RUNTIME_STORE_BINDING_COMPARISON_NONE = 0,
    NINLIL_MODEL_RUNTIME_STORE_BINDING_EXACT = 1,
    NINLIL_MODEL_RUNTIME_STORE_BINDING_UNSUPPORTED = 2
} ninlil_model_runtime_store_binding_comparison_t;

typedef enum ninlil_model_runtime_store_identity_decision {
    NINLIL_MODEL_RUNTIME_STORE_IDENTITY_DECISION_NONE = 0,
    NINLIL_MODEL_RUNTIME_STORE_IDENTITY_EXACT = 1,
    NINLIL_MODEL_RUNTIME_STORE_IDENTITY_FORWARD_ROTATION = 2,
    NINLIL_MODEL_RUNTIME_STORE_IDENTITY_CONFLICT = 3
} ninlil_model_runtime_store_identity_decision_t;

typedef struct ninlil_model_runtime_store_bootstrap_plan {
    ninlil_model_runtime_store_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_capacity_limits_t capacity_limits;
    uint32_t record_count;
    uint32_t encoded_key_value_bytes;
    uint32_t logical_bytes;
} ninlil_model_runtime_store_bootstrap_plan_t;

typedef struct ninlil_model_runtime_store_bootstrap_record {
    ninlil_model_runtime_store_key_t key;
    uint8_t value[NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES];
    uint32_t value_length;
} ninlil_model_runtime_store_bootstrap_record_t;

typedef struct ninlil_model_runtime_store_encoded_snapshot {
    /* index i maps exactly to key_id (i + 1); all views are call-borrowed. */
    ninlil_bytes_view_t values[
        NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT];
} ninlil_model_runtime_store_encoded_snapshot_t;

typedef struct ninlil_model_runtime_store_validated_snapshot {
    /* Produced only by validate_snapshot after all 17 records validate. */
    ninlil_model_runtime_store_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_runtime_store_counter_t counters[4];
    ninlil_model_runtime_store_capacity_t capacities[11];
} ninlil_model_runtime_store_validated_snapshot_t;

/*
 * All participating object and byte ranges are pairwise non-overlapping.
 * Alias/range overflow returns INVALID_ARGUMENT with every range unchanged.
 * A non-alias failure zeroes the output. A successful plan is immutable.
 * record_at borrows the plan for one call and writes one caller-owned scratch
 * record whose bytes remain caller-owned and may be reused after Storage put.
 */

ninlil_status_t ninlil_model_runtime_store_validate_snapshot(
    const ninlil_model_runtime_store_encoded_snapshot_t *encoded,
    ninlil_model_runtime_store_validated_snapshot_t *out_snapshot);

ninlil_status_t ninlil_model_runtime_store_classify_presence(
    const ninlil_model_runtime_store_presence_input_t *input,
    ninlil_model_runtime_store_presence_class_t *out_class);

ninlil_status_t ninlil_model_runtime_store_compare_binding(
    const ninlil_model_runtime_store_validated_snapshot_t *stored,
    const ninlil_model_runtime_store_binding_t *candidate,
    ninlil_model_runtime_store_binding_comparison_t *out_comparison);

ninlil_status_t ninlil_model_runtime_store_decide_identity(
    const ninlil_model_runtime_store_validated_snapshot_t *stored,
    const ninlil_model_runtime_store_identity_t *requested,
    ninlil_model_runtime_store_identity_decision_t *out_decision);

ninlil_status_t ninlil_model_runtime_store_build_bootstrap_plan(
    const ninlil_model_runtime_validation_result_t *validation,
    ninlil_model_runtime_store_bootstrap_plan_t *out_plan);

ninlil_status_t ninlil_model_runtime_store_bootstrap_record_at(
    const ninlil_model_runtime_store_bootstrap_plan_t *plan,
    uint32_t index,
    ninlil_model_runtime_store_bootstrap_record_t *out_record);

#ifdef __cplusplus
}
#endif

#endif
