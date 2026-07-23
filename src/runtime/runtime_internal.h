#ifndef NINLIL_RUNTIME_INTERNAL_H
#define NINLIL_RUNTIME_INTERNAL_H

/*
 * V1-LAB unit 2a private runtime body (spine). Not public ABI.
 */

#include "runtime_lifecycle_model.h"
#include "resource_ledger.h"
#include "runtime_store_stage5_seam.h"
#include "stage5_empty_metadata.h"
#include "submission_preflight.h"
#include "v1_durable_allowlist.h"

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_MAGIC ((uint32_t)0x4e524c31u)

typedef enum ninlil_rt_lifecycle {
    NINLIL_RT_LIFECYCLE_CREATING = 1,
    NINLIL_RT_LIFECYCLE_LIVE = 2,
    NINLIL_RT_LIFECYCLE_DESTROYING = 3,
    NINLIL_RT_LIFECYCLE_DESTROYED = 4
} ninlil_rt_lifecycle_t;

typedef enum ninlil_rt_step_phase {
    NINLIL_RT_STEP_PHASE_IDLE = 0,
    NINLIL_RT_STEP_PHASE_CLOCK = 1,
    NINLIL_RT_STEP_PHASE_RECOVERY = 2,
    NINLIL_RT_STEP_PHASE_BEARER = 3,
    NINLIL_RT_STEP_PHASE_WORK = 4,
    NINLIL_RT_STEP_PHASE_PROJECT = 5
} ninlil_rt_step_phase_t;

struct ninlil_service {
    uint32_t magic;
    struct ninlil_runtime *runtime;
    uint32_t slot_index;
};

typedef struct ninlil_rt_service_slot {
    uint32_t in_use;
    uint32_t attached;
    ninlil_service_t public_handle;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_model_submission_service_t model_service;
    uint64_t quota_inflight;
    uint64_t quota_admissions;
    uint64_t quota_payload_bytes;
    uint8_t quota_window_epoch[16];
    uint64_t quota_window_start_ms;
} ninlil_rt_service_slot_t;

typedef enum ninlil_rt_delivery_phase {
    NINLIL_RT_DELIVERY_NONE = 0,
    NINLIL_RT_DELIVERY_QUEUED = 1,
    NINLIL_RT_DELIVERY_STARTED = 2,
    NINLIL_RT_DELIVERY_EVIDENCED = 3,
    NINLIL_RT_DELIVERY_OUTCOME = 4,
    NINLIL_RT_DELIVERY_PARKED = 5
} ninlil_rt_delivery_phase_t;

typedef struct ninlil_rt_transaction_slot {
    uint32_t in_use;
    uint32_t terminal;
    ninlil_id128_t transaction_id;
    ninlil_id128_t service_app_id;
    ninlil_id128_t event_id;
    ninlil_digest256_t content_digest;
    ninlil_family_t family;
    uint64_t transaction_sequence;
    ninlil_cancel_kind_t cancel_kind;
    ninlil_outcome_t outcome;
    ninlil_reason_t reason;
    uint32_t pending_dispatch;
    ninlil_rt_delivery_phase_t delivery_phase;
    uint64_t delivery_count;
    uint64_t spool_revision;
    uint32_t event_park_cause;
    uint32_t event_discarded;
    uint32_t retry_budget;
    uint64_t next_retry_ms;
    uint64_t effect_deadline_ms;
    uint64_t generation;
    uint32_t resume_op_count;
    ninlil_id128_t last_resume_operation_id;
    uint32_t evidence_recorded;
    uint32_t outcome_recorded;
    uint32_t payload_length;
    uint8_t semantic_priority;
    uint8_t bearer_route;
    uint32_t reservation_active;
    uint32_t reservation_evidence_units;
    uint64_t admitted_at_ms;
    uint64_t retry_backoff_ms;
} ninlil_rt_transaction_slot_t;

struct ninlil_runtime {
    uint32_t magic;
    ninlil_rt_lifecycle_t lifecycle;
    uint64_t owner_context_id;
    const ninlil_platform_ops_t *platform;
    ninlil_model_runtime_config_projection_t config;
    ninlil_model_capacity_limits_t capacity_limits;
    ninlil_model_resource_ledger_t resource_ledger;
    uint8_t *namespace_bytes;
    uint32_t namespace_length;
    ninlil_storage_handle_t storage;
    ninlil_bearer_handle_t bearer;
    uint32_t storage_recovery_complete;
    uint32_t commit_unknown_fence;
    ninlil_time_sample_t started_sample;
    ninlil_id128_t metrics_epoch_id;
    ninlil_runtime_health_t health;
    ninlil_reason_t degraded_reason;
    uint64_t transaction_sequence;
    uint64_t last_assigned_scheduler_owner_sequence;
    uint64_t last_assigned_ordered_input_sequence;
    uint64_t last_visited_scheduler_owner_sequence;
    ninlil_rt_service_slot_t *services;
    uint32_t service_count;
    uint32_t service_capacity;
    ninlil_rt_transaction_slot_t *transactions;
    uint32_t transaction_count;
    uint32_t transaction_capacity;
    uint32_t nonterminal_transaction_count;
    uint32_t in_step;
    uint32_t in_callback;
    ninlil_rt_step_phase_t step_phase;
    uint32_t pending_work;
    ninlil_runtime_store_stage5_workspace_t stage5_ws;
    ninlil_stage5_empty_metadata_workspace_t empty_ws;
};

ninlil_status_t ninlil_rt_validate_live_runtime(
    ninlil_runtime_t *runtime,
    uint32_t allow_destroying);

ninlil_status_t ninlil_rt_validate_owner_thread(
    ninlil_runtime_t *runtime,
    uint32_t allow_callback);

void ninlil_rt_zero_submission_result(ninlil_submission_result_t *result);
void ninlil_rt_zero_cancel_result(ninlil_cancel_result_t *result);
void ninlil_rt_zero_step_result(ninlil_step_result_t *result);

ninlil_rt_transaction_slot_t *ninlil_rt_find_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id);

ninlil_rt_transaction_slot_t *ninlil_rt_alloc_transaction(
    ninlil_runtime_t *runtime);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_INTERNAL_H */
