#ifndef NINLIL_MODEL_RESOURCE_LEDGER_BATCH_H
#define NINLIL_MODEL_RESOURCE_LEDGER_BATCH_H

#include "resource_ledger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ninlil_model_capacity_batch_operation {
    NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK = 1,
    NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED = 2,
    NINLIL_MODEL_CAPACITY_BATCH_RELEASE = 3
} ninlil_model_capacity_batch_operation_t;

typedef enum ninlil_model_capacity_batch_action {
    NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED = 1,
    NINLIL_MODEL_CAPACITY_BATCH_BLOCK_SET_REQUIRED = 2,
    NINLIL_MODEL_CAPACITY_BATCH_ALREADY_BLOCKED = 3,
    NINLIL_MODEL_CAPACITY_BATCH_COUNTER_EXHAUSTED = 4,
    NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED = 5,
    NINLIL_MODEL_CAPACITY_BATCH_ALL_RELEASED = 6
} ninlil_model_capacity_batch_action_t;

typedef struct ninlil_model_capacity_batch_request {
    ninlil_resource_kind_t kind;
    uint32_t reopens_blocked_class;
    uint64_t amount;
    uint64_t used_release;
    uint64_t reserved_release;
} ninlil_model_capacity_batch_request_t;

typedef struct ninlil_model_capacity_batch_input {
    ninlil_model_resource_ledger_t current;
    ninlil_model_capacity_batch_operation_t operation;
    uint32_t request_count;
    ninlil_model_capacity_batch_request_t
        requests[NINLIL_MODEL_RESOURCE_KIND_COUNT];
} ninlil_model_capacity_batch_input_t;

typedef struct ninlil_model_capacity_batch_result {
    ninlil_model_resource_ledger_t next;
    ninlil_model_capacity_batch_action_t action;
    uint32_t mutation_required;
    uint32_t changed_kind_mask;
    uint32_t unblocked_kind_mask;
    uint32_t counter_marker_newly_set_mask;
    uint32_t failing_request_ordinal;
    ninlil_resource_kind_t failing_kind;
    ninlil_model_capacity_action_t failing_entry_action;
    uint32_t rolled_back_count;
} ninlil_model_capacity_batch_result_t;

ninlil_status_t ninlil_model_capacity_batch_transition(
    const ninlil_model_capacity_batch_input_t *input,
    ninlil_model_capacity_batch_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
