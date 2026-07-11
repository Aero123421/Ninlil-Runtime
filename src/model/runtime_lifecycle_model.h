#ifndef NINLIL_MODEL_RUNTIME_LIFECYCLE_MODEL_H
#define NINLIL_MODEL_RUNTIME_LIFECYCLE_MODEL_H

#include "resource_ledger.h"

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MODEL_RUNTIME_HEALTH_PRIORITY_COUNT ((uint32_t)8u)
#define NINLIL_MODEL_RUNTIME_METRICS_ENTROPY_ATTEMPTS ((uint32_t)4u)

typedef enum ninlil_model_runtime_validation_failure_field {
    NINLIL_MODEL_RUNTIME_VALIDATION_NONE = 0,
    NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_POINTER = 1,
    NINLIL_MODEL_RUNTIME_VALIDATION_PLATFORM_POINTER = 2,
    NINLIL_MODEL_RUNTIME_VALIDATION_CONFIG_HEADER = 3,
    NINLIL_MODEL_RUNTIME_VALIDATION_PLATFORM_HEADER = 4,
    NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_POINTER = 5,
    NINLIL_MODEL_RUNTIME_VALIDATION_NESTED_HEADER = 6,
    NINLIL_MODEL_RUNTIME_VALIDATION_REQUIRED_FUNCTION = 7,
    NINLIL_MODEL_RUNTIME_VALIDATION_NAMESPACE = 8,
    NINLIL_MODEL_RUNTIME_VALIDATION_RESERVED = 9,
    NINLIL_MODEL_RUNTIME_VALIDATION_UNKNOWN_ROLE = 10,
    NINLIL_MODEL_RUNTIME_VALIDATION_UNKNOWN_ENVIRONMENT = 11,
    NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ROLE = 12,
    NINLIL_MODEL_RUNTIME_VALIDATION_UNSUPPORTED_ENVIRONMENT = 13,
    NINLIL_MODEL_RUNTIME_VALIDATION_RUNTIME_ID = 14,
    NINLIL_MODEL_RUNTIME_VALIDATION_LOCAL_IDENTITY = 15,
    NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_LOWER_OR_CONDITIONAL = 16,
    NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_CROSS_FIELD = 17,
    NINLIL_MODEL_RUNTIME_VALIDATION_RETENTION = 18,
    NINLIL_MODEL_RUNTIME_VALIDATION_CAPACITY_DERIVATION_OVERFLOW = 19,
    NINLIL_MODEL_RUNTIME_VALIDATION_LIMIT_PROFILE_UPPER = 20
} ninlil_model_runtime_validation_failure_field_t;

typedef struct ninlil_model_runtime_validation_result {
    ninlil_status_t status;
    ninlil_model_runtime_validation_failure_field_t failure_field;
    ninlil_model_capacity_limits_t capacity_limits;
} ninlil_model_runtime_validation_result_t;

typedef struct ninlil_model_runtime_create_gate {
    ninlil_status_t api_status;
    uint32_t continue_create;
    uint32_t close_returned_handle;
} ninlil_model_runtime_create_gate_t;

typedef struct ninlil_model_runtime_clock_input {
    ninlil_port_status_t port_status;
    ninlil_time_sample_t sample;
    uint32_t has_external_baseline;
    ninlil_id128_t external_baseline_clock_epoch_id;
    uint64_t external_baseline_now_ms;
} ninlil_model_runtime_clock_input_t;

typedef struct ninlil_model_runtime_health_projection {
    ninlil_runtime_health_t health;
    ninlil_reason_t degraded_reason;
} ninlil_model_runtime_health_projection_t;

typedef struct ninlil_model_runtime_stage9_health_input {
    uint32_t storage_recovery_complete;
    uint64_t durable_active_reference_count[
        NINLIL_MODEL_RUNTIME_HEALTH_PRIORITY_COUNT];
} ninlil_model_runtime_stage9_health_input_t;

typedef struct ninlil_model_runtime_entropy_observation {
    ninlil_port_status_t port_status;
    ninlil_id128_t candidate;
} ninlil_model_runtime_entropy_observation_t;

typedef enum ninlil_model_runtime_entropy_action {
    NINLIL_MODEL_RUNTIME_ENTROPY_SELECTED = 1,
    NINLIL_MODEL_RUNTIME_ENTROPY_MORE_REQUIRED = 2,
    NINLIL_MODEL_RUNTIME_ENTROPY_EXHAUSTED = 3
} ninlil_model_runtime_entropy_action_t;

typedef struct ninlil_model_runtime_entropy_result {
    ninlil_status_t api_status;
    ninlil_model_runtime_entropy_action_t action;
    uint32_t calls_consumed;
    ninlil_id128_t metrics_epoch_id;
} ninlil_model_runtime_entropy_result_t;

ninlil_status_t ninlil_model_runtime_validate_and_derive(
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform,
    ninlil_model_runtime_validation_result_t *out_result);

ninlil_status_t ninlil_model_runtime_derive_capacity_limits(
    const ninlil_resource_limits_t *limits,
    ninlil_model_capacity_limits_t *out_limits);

ninlil_status_t ninlil_model_runtime_map_storage_open(
    ninlil_storage_status_t port_status,
    uint32_t handle_present,
    ninlil_model_runtime_create_gate_t *out_gate);

ninlil_status_t ninlil_model_runtime_map_bearer_open(
    ninlil_bearer_status_t port_status,
    uint32_t handle_present,
    ninlil_model_runtime_create_gate_t *out_gate);

ninlil_status_t ninlil_model_runtime_classify_clock_with_external_baseline(
    const ninlil_model_runtime_clock_input_t *input,
    ninlil_model_runtime_create_gate_t *out_gate);

ninlil_status_t ninlil_model_runtime_project_health(
    const uint64_t active_reference_count[
        NINLIL_MODEL_RUNTIME_HEALTH_PRIORITY_COUNT],
    ninlil_model_runtime_health_projection_t *out_projection);

ninlil_status_t ninlil_model_runtime_project_stage9_health(
    const ninlil_model_runtime_stage9_health_input_t *input,
    ninlil_model_runtime_health_projection_t *out_projection);

ninlil_status_t ninlil_model_runtime_map_metrics_entropy(
    const ninlil_model_runtime_entropy_observation_t *observations,
    uint32_t observation_count,
    ninlil_model_runtime_entropy_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
