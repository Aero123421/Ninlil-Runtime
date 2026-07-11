#ifndef NINLIL_MODEL_RESOURCE_LEDGER_H
#define NINLIL_MODEL_RESOURCE_LEDGER_H

#include <stdint.h>

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MODEL_RESOURCE_KIND_COUNT ((uint32_t)11u)

typedef enum ninlil_model_capacity_operation {
    NINLIL_MODEL_CAPACITY_RESERVE_OR_BLOCK = 1,
    NINLIL_MODEL_CAPACITY_COMMIT_RESERVED = 2,
    NINLIL_MODEL_CAPACITY_RELEASE = 3
} ninlil_model_capacity_operation_t;

typedef enum ninlil_model_capacity_action {
    NINLIL_MODEL_CAPACITY_RESERVED = 1,
    NINLIL_MODEL_CAPACITY_BLOCK_SET_REQUIRED = 2,
    NINLIL_MODEL_CAPACITY_ALREADY_BLOCKED = 3,
    NINLIL_MODEL_CAPACITY_COUNTER_EXHAUSTED = 4,
    NINLIL_MODEL_CAPACITY_COMMITTED = 5,
    NINLIL_MODEL_CAPACITY_RELEASED = 6,
    NINLIL_MODEL_CAPACITY_RELEASED_AND_UNBLOCKED = 7,
    NINLIL_MODEL_CAPACITY_RELEASED_EPOCH_EXHAUSTED = 8
} ninlil_model_capacity_action_t;

typedef struct ninlil_model_capacity_entry {
    ninlil_resource_kind_t kind;
    uint64_t limit;
    uint64_t used;
    uint64_t reserved;
    uint64_t high_water;
    uint64_t capacity_epoch;
    uint32_t blocked;
    uint32_t counter_exhausted_marker;
} ninlil_model_capacity_entry_t;

typedef struct ninlil_model_capacity_transition_input {
    ninlil_model_capacity_entry_t current;
    ninlil_model_capacity_operation_t operation;
    uint64_t amount;
    uint64_t used_release;
    uint64_t reserved_release;
    uint32_t reopens_blocked_class;
} ninlil_model_capacity_transition_input_t;

typedef struct ninlil_model_capacity_transition_result {
    ninlil_model_capacity_entry_t next;
    ninlil_model_capacity_action_t action;
    uint32_t counter_exhausted_marker_newly_set;
} ninlil_model_capacity_transition_result_t;

typedef struct ninlil_model_capacity_limits {
    uint64_t values[NINLIL_MODEL_RESOURCE_KIND_COUNT];
} ninlil_model_capacity_limits_t;

typedef struct ninlil_model_resource_ledger {
    ninlil_model_capacity_entry_t entries[NINLIL_MODEL_RESOURCE_KIND_COUNT];
} ninlil_model_resource_ledger_t;

/* ABI-header-free semantic projection for a later Runtime API adapter. */
typedef struct ninlil_model_capacity_entry_view {
    ninlil_resource_kind_t kind;
    uint64_t limit;
    uint64_t used;
    uint64_t reserved;
    uint64_t high_water;
    uint64_t capacity_epoch;
} ninlil_model_capacity_entry_view_t;

typedef struct ninlil_model_capacity_snapshot_view {
    ninlil_model_capacity_entry_view_t
        entries[NINLIL_MODEL_RESOURCE_KIND_COUNT];
    uint32_t entry_count;
} ninlil_model_capacity_snapshot_view_t;

ninlil_status_t ninlil_model_capacity_entry_transition(
    const ninlil_model_capacity_transition_input_t *input,
    ninlil_model_capacity_transition_result_t *out_result);

ninlil_status_t ninlil_model_resource_ledger_init(
    const ninlil_model_capacity_limits_t *limits,
    ninlil_model_resource_ledger_t *out_ledger);

ninlil_status_t ninlil_model_resource_ledger_project(
    const ninlil_model_resource_ledger_t *ledger,
    ninlil_model_capacity_snapshot_view_t *out_snapshot);

#ifdef __cplusplus
}
#endif

#endif
