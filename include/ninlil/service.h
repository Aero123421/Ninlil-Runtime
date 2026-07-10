#ifndef NINLIL_SERVICE_H
#define NINLIL_SERVICE_H

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_service_descriptor {
    NINLIL_STRUCT_HEADER;
    ninlil_bytes_view_t namespace_id;
    ninlil_bytes_view_t service_id;
    ninlil_bytes_view_t schema_id;
    uint64_t descriptor_revision;
    ninlil_digest256_t descriptor_digest;
    ninlil_id128_t local_application_instance_id;
    uint16_t schema_major;
    uint16_t schema_minor_min;
    uint16_t schema_minor_max;
    uint16_t reserved_zero_u16;
    ninlil_family_t family;
    ninlil_direction_t direction;
    ninlil_admission_authority_t admission_authority;
    ninlil_apply_contract_t apply_contract;
    ninlil_custody_policy_t custody_policy;
    uint32_t supported_evidence_mask;
    uint32_t logical_payload_limit;
    uint32_t target_limit;
    uint32_t inflight_limit;
    uint32_t max_attempts_per_target_per_cycle;
    uint32_t admission_window_ms;
    uint32_t max_admissions_per_window;
    uint32_t max_payload_bytes_per_window;
    uint32_t reserved_zero_u32;
    uint64_t minimum_deadline_ms;
    uint64_t maximum_deadline_ms;
    uint64_t maximum_evidence_grace_ms;
    uint64_t attempt_receipt_timeout_ms;
    uint64_t retry_backoff_ms;
    uint64_t application_completion_timeout_ms;
    uint64_t required_dedup_window_ms;
} ninlil_service_descriptor_t;

typedef struct ninlil_delivery_view {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t event_id;
    ninlil_party_t source;
    ninlil_concrete_target_t local_target;
    ninlil_service_identity_t service;
    ninlil_digest256_t content_digest;
    uint64_t generation;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_evidence_stage_t required_evidence;
    uint64_t delivery_count;
    ninlil_bytes_view_t payload;
} ninlil_delivery_view_t;

typedef struct ninlil_application_result {
    NINLIL_STRUCT_HEADER;
    ninlil_application_result_kind_t kind;
    ninlil_evidence_stage_t evidence_stage;
    ninlil_disposition_t disposition;
    ninlil_reason_t reason;
    ninlil_effect_certainty_t effect_certainty;
    ninlil_retry_guidance_t retry_guidance;
    uint64_t retry_delay_ms;
    ninlil_bytes_view_t evidence;
} ninlil_application_result_t;

typedef struct ninlil_reconcile_view {
    NINLIL_STRUCT_HEADER;
    ninlil_delivery_view_t delivery;
    uint64_t delivery_started_at_ms;
    uint64_t prior_callback_invocations;
} ninlil_reconcile_view_t;

typedef ninlil_callback_action_t (*ninlil_on_delivery_fn)(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result);

typedef ninlil_reconcile_action_t (*ninlil_on_reconcile_fn)(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result);

typedef struct ninlil_service_callbacks {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_on_delivery_fn on_delivery;
    ninlil_on_reconcile_fn on_reconcile;
} ninlil_service_callbacks_t;

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SERVICE_H */
