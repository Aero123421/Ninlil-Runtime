#ifndef NINLIL_PLATFORM_H
#define NINLIL_PLATFORM_H

#include "ninlil/version.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *ninlil_storage_handle_t;
typedef void *ninlil_storage_txn_t;
typedef void *ninlil_storage_iter_t;
typedef void *ninlil_bearer_handle_t;

typedef struct ninlil_runtime ninlil_runtime_t;
typedef struct ninlil_service ninlil_service_t;

typedef struct ninlil_delivery_token {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t context_id;
    uint64_t generation;
    ninlil_id128_t clock_epoch_id;
    uint64_t expires_at_ms;
} ninlil_delivery_token_t;

typedef struct ninlil_allocator_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    void *(*allocate)(void *user, uint64_t size, uint32_t alignment);
    void (*deallocate)(void *user, void *ptr, uint64_t size, uint32_t alignment);
} ninlil_allocator_ops_t;

typedef struct ninlil_execution_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    uint64_t (*current_context_id)(void *user);
} ninlil_execution_ops_t;

#define NINLIL_CLOCK_TRUSTED               ((ninlil_clock_trust_t)1u)
#define NINLIL_CLOCK_UNCERTAIN             ((ninlil_clock_trust_t)2u)

#define NINLIL_PORT_OK                     ((ninlil_port_status_t)0u)
#define NINLIL_PORT_TEMPORARY_FAILURE      ((ninlil_port_status_t)1u)
#define NINLIL_PORT_PERMANENT_FAILURE      ((ninlil_port_status_t)2u)

typedef struct ninlil_time_sample {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t clock_epoch_id;
    uint64_t now_ms;
    ninlil_clock_trust_t trust;
    uint32_t reserved_zero;
} ninlil_time_sample_t;

typedef struct ninlil_clock_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_port_status_t (*now)(void *user, ninlil_time_sample_t *out_sample);
} ninlil_clock_ops_t;

typedef struct ninlil_entropy_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_port_status_t (*fill)(void *user, uint8_t *out, uint32_t length);
} ninlil_entropy_ops_t;

#define NINLIL_STORAGE_OK                  ((ninlil_storage_status_t)0u)
#define NINLIL_STORAGE_NOT_FOUND           ((ninlil_storage_status_t)1u)
#define NINLIL_STORAGE_BUFFER_TOO_SMALL    ((ninlil_storage_status_t)2u)
#define NINLIL_STORAGE_NO_SPACE            ((ninlil_storage_status_t)3u)
#define NINLIL_STORAGE_IO_ERROR            ((ninlil_storage_status_t)4u)
#define NINLIL_STORAGE_CORRUPT             ((ninlil_storage_status_t)5u)
#define NINLIL_STORAGE_COMMIT_UNKNOWN      ((ninlil_storage_status_t)6u)
#define NINLIL_STORAGE_BUSY                ((ninlil_storage_status_t)7u)
#define NINLIL_STORAGE_UNSUPPORTED_SCHEMA  ((ninlil_storage_status_t)8u)

#define NINLIL_STORAGE_READ_ONLY           ((ninlil_storage_mode_t)1u)
#define NINLIL_STORAGE_READ_WRITE          ((ninlil_storage_mode_t)2u)

#define NINLIL_DURABILITY_VOLATILE         ((ninlil_durability_t)1u)
#define NINLIL_DURABILITY_CHECKPOINTED     ((ninlil_durability_t)2u)
#define NINLIL_DURABILITY_FULL             ((ninlil_durability_t)3u)

typedef struct ninlil_storage_capacity {
    NINLIL_STRUCT_HEADER;
    uint64_t max_entries;
    uint64_t used_entries;
    uint64_t max_bytes;
    uint64_t used_bytes;
} ninlil_storage_capacity_t;

typedef struct ninlil_storage_ops {
    NINLIL_STRUCT_HEADER;
    void *user;

    ninlil_storage_status_t (*open)(
        void *user,
        ninlil_bytes_view_t storage_namespace,
        uint32_t expected_schema,
        ninlil_storage_handle_t *out_handle);

    void (*close)(void *user, ninlil_storage_handle_t handle);

    ninlil_storage_status_t (*begin)(
        void *user,
        ninlil_storage_handle_t handle,
        ninlil_storage_mode_t mode,
        ninlil_storage_txn_t *out_txn);

    ninlil_storage_status_t (*get)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t key,
        ninlil_mut_bytes_t *inout_value);

    ninlil_storage_status_t (*put)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t key,
        ninlil_bytes_view_t value);

    ninlil_storage_status_t (*erase)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t key);

    ninlil_storage_status_t (*iter_open)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_bytes_view_t prefix,
        ninlil_storage_iter_t *out_iter);

    ninlil_storage_status_t (*iter_next)(
        void *user,
        ninlil_storage_iter_t iter,
        ninlil_mut_bytes_t *inout_key,
        ninlil_mut_bytes_t *inout_value);

    void (*iter_close)(void *user, ninlil_storage_iter_t iter);

    ninlil_storage_status_t (*capacity)(
        void *user,
        ninlil_storage_handle_t handle,
        ninlil_storage_capacity_t *out_capacity);

    ninlil_storage_status_t (*commit)(
        void *user,
        ninlil_storage_txn_t txn,
        ninlil_durability_t durability);

    ninlil_storage_status_t (*rollback)(void *user, ninlil_storage_txn_t txn);
} ninlil_storage_ops_t;

#define NINLIL_BEARER_OK                   ((ninlil_bearer_status_t)0u)
#define NINLIL_BEARER_EMPTY                ((ninlil_bearer_status_t)1u)
#define NINLIL_BEARER_WOULD_BLOCK          ((ninlil_bearer_status_t)2u)
#define NINLIL_BEARER_UNAVAILABLE          ((ninlil_bearer_status_t)3u)
#define NINLIL_BEARER_DENIED               ((ninlil_bearer_status_t)4u)
#define NINLIL_BEARER_LOST_UNKNOWN         ((ninlil_bearer_status_t)5u)
#define NINLIL_BEARER_CORRUPT              ((ninlil_bearer_status_t)6u)

#define NINLIL_BEARER_MESSAGE_APPLICATION  ((ninlil_bearer_message_kind_t)1u)
#define NINLIL_BEARER_MESSAGE_RECEIPT      ((ninlil_bearer_message_kind_t)2u)
#define NINLIL_BEARER_MESSAGE_DISPOSITION  ((ninlil_bearer_message_kind_t)3u)
#define NINLIL_BEARER_MESSAGE_CANCEL_REQUEST ((ninlil_bearer_message_kind_t)4u)
#define NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED ((ninlil_bearer_message_kind_t)5u)
#define NINLIL_BEARER_MESSAGE_CANCEL_RESULT ((ninlil_bearer_message_kind_t)6u)

#define NINLIL_BEARER_SEND_ACCEPTED        ((ninlil_bearer_send_kind_t)1u)
#define NINLIL_BEARER_SEND_DURABLE_CUSTODY ((ninlil_bearer_send_kind_t)2u)

typedef struct ninlil_party {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t runtime_id;
    ninlil_id128_t application_instance_id;
    ninlil_local_identity_t local_identity;
} ninlil_party_t;

#define NINLIL_TARGET_HAS_DEVICE           ((uint32_t)1u << 0)
#define NINLIL_TARGET_HAS_INSTALLATION     ((uint32_t)1u << 1)
#define NINLIL_TARGET_HAS_SITE             ((uint32_t)1u << 2)

typedef struct ninlil_concrete_target {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t target_runtime_id;
    ninlil_id128_t target_application_instance_id;
    ninlil_id128_t device_id;
    ninlil_id128_t installation_id;
    ninlil_id128_t site_domain_id;
    uint64_t binding_epoch;
    uint64_t membership_epoch;
    uint32_t flags;
    uint32_t reserved_zero;
} ninlil_concrete_target_t;

typedef struct ninlil_service_identity {
    NINLIL_STRUCT_HEADER;
    ninlil_text_id_t namespace_id;
    ninlil_text_id_t service_id;
    ninlil_text_id_t schema_id;
    uint64_t descriptor_revision;
    ninlil_digest256_t descriptor_digest;
    uint16_t schema_major;
    uint16_t schema_minor;
    ninlil_family_t family;
} ninlil_service_identity_t;

typedef struct ninlil_bearer_message {
    NINLIL_STRUCT_HEADER;
    ninlil_bearer_message_kind_t kind;
    uint32_t flags;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t event_id;
    ninlil_party_t source;
    ninlil_concrete_target_t target;
    ninlil_service_identity_t service;
    ninlil_digest256_t content_digest;
    uint64_t generation;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    ninlil_evidence_stage_t required_evidence;
    ninlil_evidence_stage_t receipt_stage;
    ninlil_disposition_t disposition;
    ninlil_effect_certainty_t effect_certainty;
    ninlil_retry_guidance_t retry_guidance;
    ninlil_cancel_kind_t cancel_kind;
    uint64_t retry_delay_ms;
    ninlil_time_sample_t evidence_time;
    ninlil_bytes_view_t payload;
    ninlil_bytes_view_t evidence;
} ninlil_bearer_message_t;

typedef struct ninlil_bearer_send_result {
    NINLIL_STRUCT_HEADER;
    ninlil_bearer_send_kind_t kind;
    uint32_t reserved_zero;
    uint64_t availability_epoch;
} ninlil_bearer_send_result_t;

typedef struct ninlil_bearer_state {
    NINLIL_STRUCT_HEADER;
    uint64_t availability_epoch;
    uint32_t available;
    uint32_t reserved_zero;
} ninlil_bearer_state_t;

typedef struct ninlil_tx_permit {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t permit_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t clock_epoch_id;
    uint64_t expires_at_ms;
} ninlil_tx_permit_t;

typedef struct ninlil_bearer_ops {
    NINLIL_STRUCT_HEADER;
    void *user;

    ninlil_bearer_status_t (*open)(
        void *user,
        const ninlil_id128_t *runtime_id,
        ninlil_role_t role,
        ninlil_bearer_handle_t *out_handle);

    void (*close)(void *user, ninlil_bearer_handle_t handle);

    ninlil_bearer_status_t (*send)(
        void *user,
        ninlil_bearer_handle_t handle,
        const ninlil_tx_permit_t *permit,
        const ninlil_bearer_message_t *message,
        ninlil_bearer_send_result_t *out_result);

    ninlil_bearer_status_t (*receive_next)(
        void *user,
        ninlil_bearer_handle_t handle,
        ninlil_bearer_message_t *out_message);

    void (*release_received)(
        void *user,
        ninlil_bearer_handle_t handle,
        ninlil_bearer_message_t *message);

    ninlil_bearer_status_t (*state)(
        void *user,
        ninlil_bearer_handle_t handle,
        ninlil_bearer_state_t *out_state);
} ninlil_bearer_ops_t;

#define NINLIL_TX_GATE_OK                  ((ninlil_tx_gate_status_t)0u)
#define NINLIL_TX_GATE_DENIED              ((ninlil_tx_gate_status_t)1u)
#define NINLIL_TX_GATE_TEMPORARY           ((ninlil_tx_gate_status_t)2u)

typedef struct ninlil_tx_request {
    NINLIL_STRUCT_HEADER;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_bearer_message_kind_t message_kind;
    uint32_t logical_bytes;
    ninlil_digest256_t content_digest;
} ninlil_tx_request_t;

typedef struct ninlil_tx_gate_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_tx_gate_status_t (*acquire)(
        void *user,
        const ninlil_tx_request_t *request,
        const ninlil_time_sample_t *now,
        ninlil_tx_permit_t *out_permit);
    void (*release_unused)(void *user, const ninlil_tx_permit_t *permit);
} ninlil_tx_gate_ops_t;

#define NINLIL_ORIGIN_AUTH_OK                ((ninlil_origin_auth_status_t)0u)
#define NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE ((ninlil_origin_auth_status_t)1u)
#define NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE ((ninlil_origin_auth_status_t)2u)

typedef struct ninlil_origin_authorization_request {
    NINLIL_STRUCT_HEADER;
    ninlil_environment_t environment;
    uint32_t reserved_zero;
    ninlil_party_t source;
    ninlil_concrete_target_t target;
    ninlil_service_identity_t service;
    ninlil_id128_t event_id;
    ninlil_digest256_t content_digest;
    ninlil_evidence_stage_t required_evidence;
    uint32_t payload_length;
    uint32_t active_spool_count;
    uint32_t admissions_in_current_window;
    uint64_t active_spool_bytes;
    uint64_t current_window_started_at_ms;
    ninlil_time_sample_t now;
} ninlil_origin_authorization_request_t;

typedef struct ninlil_origin_authorization_decision {
    NINLIL_STRUCT_HEADER;
    uint32_t allowed;
    ninlil_reason_t reason;
    ninlil_retry_guidance_t retry_guidance;
    uint32_t reserved_zero_head;
    ninlil_id128_t provider_id;
    uint64_t provider_revision;
    ninlil_digest256_t decision_digest;
    ninlil_id128_t grant_id;
    uint64_t grant_revision;
    ninlil_id128_t clock_epoch_id;
    uint64_t evaluated_at_ms;
    uint64_t valid_from_ms;
    uint64_t expires_at_ms;
    uint64_t retry_delay_ms;
    uint32_t max_payload_bytes;
    uint32_t max_active_spool_count;
    uint64_t max_active_spool_bytes;
    uint32_t rate_window_ms;
    uint32_t max_admissions_per_window;
    uint32_t max_attempts_per_retry_cycle;
    uint32_t reserved_zero_tail;
} ninlil_origin_authorization_decision_t;

typedef struct ninlil_origin_authorization_ops {
    NINLIL_STRUCT_HEADER;
    void *user;
    ninlil_origin_auth_status_t (*evaluate)(
        void *user,
        const ninlil_origin_authorization_request_t *request,
        ninlil_origin_authorization_decision_t *out_decision);
} ninlil_origin_authorization_ops_t;

typedef struct ninlil_platform_ops {
    NINLIL_STRUCT_HEADER;
    const ninlil_allocator_ops_t *allocator;
    const ninlil_execution_ops_t *execution;
    const ninlil_clock_ops_t *clock;
    const ninlil_entropy_ops_t *entropy;
    const ninlil_storage_ops_t *storage;
    const ninlil_bearer_ops_t *bearer;
    const ninlil_tx_gate_ops_t *tx_gate;
    const ninlil_origin_authorization_ops_t *origin_authorization;
} ninlil_platform_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_PLATFORM_H */
