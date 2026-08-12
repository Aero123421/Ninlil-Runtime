/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Service registration and Application callback contract.
 *
 * ninlil_service_register() borrows descriptor/callback inputs for the call,
 * copies descriptor values and callback-table values, and returns a Runtime-
 * owned opaque Service handle. Callback function code and `user` remain
 * caller-owned and must outlive Runtime destruction.
 *
 * Delivery/reconcile structs, nested payload/evidence views, and token/view
 * pointers are valid only for that callback invocation. Applications may copy
 * a delivery token value for later ninlil_delivery_complete(), but must not
 * retain any callback pointer or byte view. Synchronous result evidence must
 * remain valid across callback return until Runtime's immediate deep-copy
 * completes; it must not point to callback automatic storage and Runtime does
 * not retain the borrowed view afterward. Callbacks run inside
 * ninlil_runtime_step() on the owner context; mutating Runtime re-entry is
 * rejected; the read-only query/list/capacity/metrics callback exceptions are
 * allowed on the same owner context. Callback action/result fields describe
 * Application semantics, independently of the enclosing ninlil_status_t API
 * result.
 */
#ifndef NINLIL_SERVICE_H
#define NINLIL_SERVICE_H

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Registration borrows this descriptor and all text views, then copies the
 * complete semantic descriptor before publishing a Service handle.
 */
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

/*
 * token/delivery/out_sync_result and nested views are borrowed for this
 * invocation. Valid actions are NINLIL_CALLBACK_COMPLETE,
 * NINLIL_CALLBACK_DEFER, and NINLIL_CALLBACK_FATAL. Only COMPLETE reads the
 * semantic result. Its Application-owned evidence must survive callback return
 * until Runtime immediately deep-copies it; callback automatic storage is too
 * short-lived. DEFER may copy the token value, never its pointer or payload.
 */
typedef ninlil_callback_action_t (*ninlil_on_delivery_fn)(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result);

/*
 * delivery/out_known_result and nested views are borrowed for this invocation.
 * Valid actions are NINLIL_RECONCILE_REDELIVER,
 * NINLIL_RECONCILE_KNOWN_RESULT, NINLIL_RECONCILE_RETRY_LATER, and
 * NINLIL_RECONCILE_OUTCOME_UNKNOWN. Only KNOWN_RESULT reads the semantic result;
 * its evidence follows the same post-return immediate deep-copy lifetime.
 */
typedef ninlil_reconcile_action_t (*ninlil_on_reconcile_fn)(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result);

/*
 * Registration copies this table's user/function pointer values, not its
 * address. The caller owns non-NULL user pointees and callable code until
 * runtime_destroy returns; Runtime never frees either.
 */
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
