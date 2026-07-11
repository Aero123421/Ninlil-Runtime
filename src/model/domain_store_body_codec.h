#ifndef NINLIL_MODEL_DOMAIN_STORE_BODY_CODEC_H
#define NINLIL_MODEL_DOMAIN_STORE_BODY_CODEC_H

#include "domain_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Domain Store v1 pure body codec — D1-B1 + D1-B2 + D1-B3a..d.
 * Production-private; not installed. Complements domain_store_codec (D1-A)
 * with exact body encode/decode and same-record typed validation.
 * Does not implement D2 scan, D3 cross-row, or D4 convergence.
 *
 * Scope:
 *   D1-B1: family 5 01; family 6 60/62/64/7d
 *   D1-B2: family 6 10/11/20/21/22/23/24/25
 *          (SERVICE, SERVICE_QUOTA, TRANSACTION_*, RESERVATION, maps)
 *   D1-B3a: family 6 26 SCHEDULER_OWNER only
 *   D1-B3b: family 6 27 ORDERED_INGRESS + pure message_semantic_digest helper
 *   D1-B3c: family 6 30 BLOB manifest (flags=1) + chunk (flags=2) pure body
 *   D1-B3d: family 6 31 ATTEMPT pure body + same-record matrix validation
 *          (not ATTEMPT_ID_INDEX 0x34, not CANCEL_STATE 0x33)
 *
 * Output / alias contract (identical to D1-A domain_store_codec.h):
 * - All participating input and output ranges must be pairwise disjoint.
 * - Alias / address overflow: return NINLIL_E_INVALID_ARGUMENT without
 *   modifying any participating range.
 * - After alias is ruled out and an output pointer is valid, non-alias
 *   failures zero all output objects and set *out_length = 0
 *   (except NINLIL_E_BUFFER_TOO_SMALL, which sets only the documented
 *   required length).
 * - NULL output pointers cannot be zeroed (trivial exception).
 *
 * No Port/Storage calls, heap, VLA, or recursion. Caller owns all buffers.
 * Decode views borrow encoded body bytes only while the encoded buffer lives.
 */

/* Exact fixed body lengths (docs17 section 6 / 8.x). */
#define NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES ((uint32_t)96u)
#define NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES ((uint32_t)36u)
#define NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES ((uint32_t)40u)
#define NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES ((uint32_t)16u)
/* HEAD_INDEX with family 3/4 exact-10 member key (docs17 section 8.6). */
#define NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES ((uint32_t)10u)
#define NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES ((uint32_t)114u)
#define NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_SEQUENCE_INDEX_BYTES ((uint32_t)56u)
#define NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_STATE_BYTES ((uint32_t)224u)
#define NINLIL_MODEL_DOMAIN_RESOURCE_VECTOR_BYTES ((uint32_t)176u)
#define NINLIL_MODEL_DOMAIN_PARTY_BYTES ((uint32_t)100u)
#define NINLIL_MODEL_DOMAIN_TARGET_BYTES ((uint32_t)100u)
#define NINLIL_MODEL_DOMAIN_LOCAL_IDENTITY_BYTES ((uint32_t)68u)
#define NINLIL_MODEL_DOMAIN_TEXT_ID_MAX ((uint32_t)63u)
#define NINLIL_MODEL_DOMAIN_RAW16_SERVICE_KEY_MAX ((uint32_t)255u)
#define NINLIL_MODEL_DOMAIN_RAW16_SCOPE_MAX ((uint32_t)255u)
#define NINLIL_MODEL_DOMAIN_RAW16_OWNER_KEY_MAX ((uint32_t)255u)
#define NINLIL_MODEL_DOMAIN_RAW16_IDEMPOTENCY_KEY_MAX ((uint32_t)64u)
#define NINLIL_MODEL_DOMAIN_BODY_SERVICE_MAX ((uint32_t)768u)
#define NINLIL_MODEL_DOMAIN_BODY_SERVICE_QUOTA_MAX ((uint32_t)512u)
#define NINLIL_MODEL_DOMAIN_BODY_TRANSACTION_ANCHOR_MAX ((uint32_t)1536u)
#define NINLIL_MODEL_DOMAIN_BODY_RESERVATION_MAX ((uint32_t)512u)
#define NINLIL_MODEL_DOMAIN_BODY_IDEMPOTENCY_MAP_MAX ((uint32_t)512u)
#define NINLIL_MODEL_DOMAIN_BODY_EVENT_ID_MAP_MAX ((uint32_t)512u)
#define NINLIL_MODEL_DOMAIN_BODY_SCHEDULER_OWNER_MAX ((uint32_t)512u)
#define NINLIL_MODEL_DOMAIN_BODY_ORDERED_INGRESS_MAX ((uint32_t)1536u)
#define NINLIL_MODEL_DOMAIN_BODY_BLOB_MAX ((uint32_t)3264u)
#define NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_MAX ((uint32_t)512u)
#define NINLIL_MODEL_DOMAIN_RAW16_SUBJECT_KEY_MAX ((uint32_t)255u)
/* ATTEMPT owner_key_raw content max (docs17 §8.3); TX=16 / DELIVERY=80. */
#define NINLIL_MODEL_DOMAIN_RAW16_ATTEMPT_OWNER_KEY_MAX ((uint32_t)128u)
#define NINLIL_MODEL_DOMAIN_EVIDENCE_BYTES_MAX ((uint32_t)128u)

/* BLOB owner_key_raw exact content lengths (docs17 §8.3). */
#define NINLIL_MODEL_DOMAIN_BLOB_OWNER_KEY_TX_BYTES ((uint16_t)16u)
#define NINLIL_MODEL_DOMAIN_BLOB_OWNER_KEY_INGRESS_BYTES ((uint16_t)8u)
#define NINLIL_MODEL_DOMAIN_BLOB_OWNER_KEY_DELIVERY_BYTES ((uint16_t)80u)

/* ATTEMPT owner_key_raw exact content lengths (docs17 §8.3). */
#define NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_KEY_TX_BYTES ((uint16_t)16u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_KEY_DELIVERY_BYTES ((uint16_t)80u)

/* Closed body enums (docs17 section 7.1). */
#define NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_INDEX_STATE_WITNESSED ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED ((uint32_t)1u)
#define NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED ((uint32_t)2u)

#define NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_SERVICE ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_TRANSACTION ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS ((uint16_t)3u)
#define NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_DELIVERY ((uint16_t)4u)
#define NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK ((uint16_t)5u)
#define NINLIL_MODEL_DOMAIN_RESERVATION_RELEASED_MASK_KNOWN ((uint32_t)0x000007ffu)
#define NINLIL_MODEL_DOMAIN_RESOURCE_KIND_COUNT ((uint32_t)11u)
#define NINLIL_MODEL_DOMAIN_DELIVERY_KEY_CONTENTS_BYTES ((uint32_t)80u)

/* scheduler owner_kind / work_class (docs17 §7.1) — distinct from reservation. */
#define NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS ((uint16_t)3u)
#define NINLIL_MODEL_DOMAIN_WORK_CLASS_REDUCE ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_WORK_CLASS_DISPATCH ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_WORK_CLASS_TIMER ((uint16_t)3u)
#define NINLIL_MODEL_DOMAIN_WORK_CLASS_CALLBACK ((uint16_t)4u)
#define NINLIL_MODEL_DOMAIN_WORK_CLASS_CLEANUP ((uint16_t)5u)
#define NINLIL_MODEL_DOMAIN_WORK_CLASS_RECOVERY ((uint16_t)6u)

/* ORDERED_INGRESS owner_binding_kind (docs17 §7.1). */
#define NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_TRANSACTION ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_DELIVERY ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_INGRESS_BINDING_NEW_DELIVERY ((uint16_t)3u)

/* ORDERED_INGRESS ingress_state (docs17 §8.3): PENDING only in v1 body. */
#define NINLIL_MODEL_DOMAIN_INGRESS_STATE_PENDING ((uint32_t)1u)

/*
 * BLOB blob_owner_kind (docs17 §8.3) — private BLOB enums only.
 * Distinct from reservation owner (SERVICE=1..) and scheduler owner
 * (TRANSACTION=1, DELIVERY=2, INGRESS=3).
 */
#define NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY ((uint16_t)3u)

/* BLOB blob_kind (docs17 §7.1 / §8.3). */
#define NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_BLOB_KIND_EVENT_PAYLOAD ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD ((uint16_t)3u)
#define NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE ((uint16_t)4u)
#define NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY ((uint16_t)5u)

/*
 * ATTEMPT private enums (docs17 §7.1 / §8.3) — distinct from reservation /
 * scheduler / BLOB / reverse-reply send_state enums.
 */
#define NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_TRANSACTION ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_OWNER_DELIVERY ((uint16_t)2u)

#define NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_COMMAND ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_EVENT ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_KIND_CANCEL ((uint16_t)3u)

#define NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_PREPARED ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_OBSERVED_SENT ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RESOLVED ((uint16_t)3u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_STATE_RECOVERY_REQUIRED ((uint16_t)4u)

#define NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_PREPARED ((uint32_t)1u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RETRYABLE_NO_SEND ((uint32_t)2u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_SENT_POSSIBLE ((uint32_t)3u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_CLOSED_DENIED ((uint32_t)4u)
#define NINLIL_MODEL_DOMAIN_ATTEMPT_SEND_RECOVERY_REQUIRED ((uint32_t)5u)

/* subject_kind / record role for INTERNAL_INVARIANT (docs17 section 6). */
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE ((uint16_t)0u)
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY3 ((uint16_t)0x0300u)
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY4 ((uint16_t)0x0400u)
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY6_BASE ((uint16_t)0x0600u)

/* --- reusable private wire types (no public ABI headers) --- */

typedef struct ninlil_model_domain_text_id {
    uint8_t length; /* 1..63 */
    uint8_t bytes[63];
} ninlil_model_domain_text_id_t;

typedef struct ninlil_model_domain_local_identity {
    uint32_t flags;
    uint8_t device[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t installation[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t site[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t binding_epoch;
    uint64_t membership_epoch;
} ninlil_model_domain_local_identity_t;

typedef struct ninlil_model_domain_party {
    uint8_t runtime_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t application_instance_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    ninlil_model_domain_local_identity_t local_identity;
} ninlil_model_domain_party_t;

typedef struct ninlil_model_domain_target {
    uint32_t flags;
    uint8_t target_runtime[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t target_application[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t device[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t installation[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t site[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t binding_epoch;
    uint64_t membership_epoch;
} ninlil_model_domain_target_t;

typedef struct ninlil_model_domain_service_identity {
    ninlil_model_domain_text_id_t namespace_id;
    ninlil_model_domain_text_id_t service_id;
    ninlil_model_domain_text_id_t schema_id;
    uint64_t descriptor_revision;
    uint8_t descriptor_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t family;
} ninlil_model_domain_service_identity_t;

/* kinds 1..11 stored as used/reserved pairs in declaration order. */
typedef struct ninlil_model_domain_resource_vector {
    uint64_t used[NINLIL_MODEL_DOMAIN_RESOURCE_KIND_COUNT];
    uint64_t reserved[NINLIL_MODEL_DOMAIN_RESOURCE_KIND_COUNT];
} ninlil_model_domain_resource_vector_t;

/* --- D1-B1 bodies --- */

typedef struct ninlil_model_domain_body_internal_invariant {
    uint32_t reason;
    uint16_t subject_kind;
    uint16_t reserved;
    uint8_t subject_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t first_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t first_at_ms;
    uint8_t detail_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_internal_invariant_t;

typedef struct ninlil_model_domain_body_bearer_state {
    uint64_t availability_epoch;
    uint32_t available; /* exact 0/1 boolean */
    uint8_t observation_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t observed_at_ms;
} ninlil_model_domain_body_bearer_state_t;

typedef struct ninlil_model_domain_body_clock_baseline {
    uint32_t baseline_state;
    uint32_t reserved;
    uint8_t trusted_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t last_trusted_now_ms;
    uint64_t publish_generation;
} ninlil_model_domain_body_clock_baseline_t;

typedef struct ninlil_model_domain_body_attempt_reuse_fence {
    uint32_t active_plan_count;
    uint32_t reserved;
    uint64_t fence_generation;
} ninlil_model_domain_body_attempt_reuse_fence_t;

/*
 * WITNESS_HEAD_INDEX body. On decode, member_key_bytes borrows encoded body
 * and remains valid only while the encoded buffer is alive.
 * Encode requires member_key_bytes to point at caller-owned key bytes of
 * member_key_length (exact 10 for v1 family 3/4 members).
 */
typedef struct ninlil_model_domain_body_witness_head_index {
    uint16_t index_state;
    uint16_t reserved0;
    uint8_t member_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t member_key_length;
    uint16_t reserved1;
    const uint8_t *member_key_bytes;
    uint8_t member_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t member_head_witness_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_witness_head_index_t;

/* --- D1-B2 bodies (variable RAW16 fields borrow on decode) --- */

typedef struct ninlil_model_domain_body_service {
    uint16_t service_key_raw_length;
    const uint8_t *service_key_raw;
    uint64_t descriptor_revision;
    uint8_t descriptor_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t local_application_instance_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    ninlil_model_domain_text_id_t namespace_id;
    ninlil_model_domain_text_id_t service_id;
    ninlil_model_domain_text_id_t schema_id;
    uint16_t schema_major;
    uint16_t minor_min;
    uint16_t minor_max;
    uint32_t family;
    uint32_t direction;
    uint32_t admission_authority;
    uint32_t apply_contract;
    uint32_t custody_policy;
    uint32_t supported_evidence_mask;
    uint32_t logical_payload_limit;
    uint32_t target_limit;
    uint32_t inflight_limit;
    uint32_t attempts_per_cycle;
    uint32_t admission_window_ms;
    uint32_t max_admissions_window;
    uint32_t max_payload_window;
    uint64_t minimum_deadline_ms;
    uint64_t maximum_deadline_ms;
    uint64_t maximum_evidence_grace_ms;
    uint64_t attempt_receipt_timeout_ms;
    uint64_t retry_backoff_ms;
    uint64_t application_completion_timeout_ms;
    uint64_t required_dedup_window_ms;
    uint8_t quota_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t reservation_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_service_t;

typedef struct ninlil_model_domain_body_service_quota {
    uint16_t service_key_raw_length;
    const uint8_t *service_key_raw;
    uint8_t service_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t window_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t window_start_ms;
    uint32_t admissions_in_window;
    uint64_t payload_bytes_in_window;
    uint32_t active_transaction_count;
    uint32_t active_spool_count;
    uint64_t active_spool_bytes;
} ninlil_model_domain_body_service_quota_t;

typedef struct ninlil_model_domain_body_transaction_anchor {
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t transaction_sequence;
    uint64_t scheduler_owner_sequence;
    uint32_t family;
    ninlil_model_domain_party_t source;
    ninlil_model_domain_service_identity_t service;
    uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t canonical_submission_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t event_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t generation;
    uint8_t admission_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t admitted_at_ms;
    uint8_t deadline_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    uint32_t required_evidence;
    uint32_t target_count;
    ninlil_model_domain_target_t target;
    uint16_t idempotency_scope_raw_length;
    const uint8_t *idempotency_scope_raw;
    uint16_t idempotency_key_length;
    const uint8_t *idempotency_key;
    uint8_t sequence_index_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t idempotency_map_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t event_map_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t reservation_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint64_t scheduler_owner_key_sequence;
    uint8_t payload_blob_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_transaction_anchor_t;

typedef struct ninlil_model_domain_body_transaction_sequence_index {
    uint64_t transaction_sequence;
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t anchor_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_transaction_sequence_index_t;

typedef struct ninlil_model_domain_body_transaction_state {
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t anchor_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint32_t state;
    uint32_t outcome;
    uint32_t deadline_verdict;
    uint32_t latest_evidence;
    uint32_t reason;
    uint32_t event_park_cause;
    uint64_t retry_cycle_id;
    uint32_t attempt_in_cycle;
    uint64_t cumulative_attempts;
    uint64_t event_spool_revision;
    uint32_t has_late_evidence;
    uint32_t explicitly_discarded;
    ninlil_model_domain_target_t target;
    uint32_t target_state;
    uint32_t target_outcome;
    uint32_t target_reason;
    uint32_t target_latest_evidence;
} ninlil_model_domain_body_transaction_state_t;

typedef struct ninlil_model_domain_body_reservation {
    uint16_t owner_kind;
    uint16_t reserved;
    uint16_t owner_key_raw_length;
    const uint8_t *owner_key_raw;
    uint8_t primary_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    ninlil_model_domain_resource_vector_t resources;
    uint32_t service_inflight;
    uint32_t grant_active_count;
    uint64_t grant_active_bytes;
    uint32_t released_mask;
} ninlil_model_domain_body_reservation_t;

typedef struct ninlil_model_domain_body_idempotency_map {
    uint16_t scope_raw_length;
    const uint8_t *scope_raw;
    uint16_t idempotency_key_length;
    const uint8_t *idempotency_key;
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t canonical_submission_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t anchor_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_idempotency_map_t;

typedef struct ninlil_model_domain_body_event_id_map {
    uint16_t scope_raw_length;
    const uint8_t *scope_raw;
    uint8_t event_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t canonical_submission_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t idempotency_key_length;
    const uint8_t *idempotency_key;
    uint8_t anchor_value_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_event_id_map_t;

/*
 * SCHEDULER_OWNER (0x26). subject_key_raw borrows encoded body on decode.
 * state_revision is independent of common record_revision (docs17 §8.3).
 */
typedef struct ninlil_model_domain_body_scheduler_owner {
    uint64_t owner_sequence;
    uint16_t owner_kind;
    uint16_t work_class;
    uint16_t subject_key_raw_length;
    const uint8_t *subject_key_raw;
    uint8_t primary_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint64_t state_revision;
    uint8_t logical_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t logical_at_ms;
    uint8_t next_wake_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t next_wake_at_ms;
    uint32_t ready; /* exact 0/1 */
} ninlil_model_domain_body_scheduler_owner_t;

/*
 * ORDERED_INGRESS (0x27). All nested identity fields are value-owned (no
 * RAW16 body borrow). message_semantic_digest is recomputed same-record only
 * when both BLOB key digests are zero (empty payload/evidence streams).
 * Non-zero BLOB digests: D1 proves digest non-zero + kind presence only;
 * BLOB key material and stream recompute are D3 (do not guess keys here).
 */
typedef struct ninlil_model_domain_body_ordered_ingress {
    uint64_t ordered_sequence;
    uint64_t owner_sequence;
    uint16_t owner_binding_kind;
    uint16_t reserved0;
    uint32_t message_kind;
    uint32_t message_flags;
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t attempt_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t event_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    ninlil_model_domain_party_t source;
    ninlil_model_domain_target_t target;
    ninlil_model_domain_service_identity_t service;
    uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint64_t generation;
    uint8_t deadline_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    uint32_t required_evidence;
    uint32_t receipt_stage;
    uint32_t disposition;
    uint32_t effect_certainty;
    uint32_t retry_guidance;
    uint32_t cancel_kind;
    uint64_t retry_delay_ms;
    uint8_t evidence_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t evidence_now_ms;
    uint32_t evidence_trust;
    uint32_t reserved1;
    uint8_t message_semantic_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t payload_blob_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t evidence_blob_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint32_t ingress_state;
    uint8_t reservation_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_ordered_ingress_t;

/*
 * BLOB manifest (0x30, flags=1). owner_key_raw borrows encoded body on decode.
 * blob_id / owner_primary_key_digest / length-count rules are same-record
 * validated; live owner get and multi-chunk stream are D3.
 */
typedef struct ninlil_model_domain_body_blob_manifest {
    uint8_t blob_id_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t blob_owner_kind;
    uint16_t blob_kind;
    uint16_t owner_key_raw_length;
    const uint8_t *owner_key_raw;
    uint8_t owner_primary_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint64_t total_length;
    uint32_t chunk_count;
    uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
} ninlil_model_domain_body_blob_manifest_t;

/*
 * BLOB chunk (0x30, flags=2). chunk_bytes borrows encoded body on decode.
 * Zero chunk_length is always corrupt. Single-chunk content_digest is
 * recomputed same-record; multi-chunk stream digest is D3.
 */
typedef struct ninlil_model_domain_body_blob_chunk {
    uint8_t blob_id_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t manifest_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint32_t chunk_index;
    uint32_t chunk_count;
    uint64_t total_length;
    uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint32_t chunk_length;
    const uint8_t *chunk_bytes;
} ninlil_model_domain_body_blob_chunk_t;

/*
 * ATTEMPT (0x31). owner_key_raw borrows encoded body on decode.
 * Same-record closed matrix + identity (docs17 §8.3). Live owner /
 * ATTEMPT_ID_INDEX / CANCEL_STATE gate / semantic recompute are D3.
 */
typedef struct ninlil_model_domain_body_attempt {
    uint8_t attempt_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint16_t attempt_owner_kind;
    uint16_t reserved0;
    uint16_t owner_key_raw_length;
    const uint8_t *owner_key_raw;
    uint8_t primary_key_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t target_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint16_t attempt_kind;
    uint16_t attempt_state;
    uint64_t retry_cycle_id;
    uint32_t attempt_in_cycle;
    uint64_t cumulative_attempts;
    uint64_t send_operation_generation;
    uint64_t send_invocation_count;
    uint32_t send_counter_exhausted; /* exact 0/1 */
    uint32_t reserved1;
    uint8_t message_semantic_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t prepared_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t prepared_at_ms; /* 0 allowed when epoch non-zero */
    uint32_t send_state;
    uint64_t availability_epoch;
    uint8_t receipt_timeout_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t receipt_timeout_at_ms;
} ninlil_model_domain_body_attempt_t;

/*
 * Prefix fields for message_semantic_digest (docs17 §5.1). Domain PARTY /
 * TARGET / SERVICE_IDENTITY encodings only — no public ABI headers, pointers,
 * reserved, or padding. payload_length is the declared length (hashed as u32
 * before any payload data bytes).
 */
typedef struct ninlil_model_domain_message_semantic_prefix {
    uint32_t kind;
    uint32_t flags;
    uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t attempt_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint8_t event_id[NINLIL_MODEL_DOMAIN_ID_BYTES];
    ninlil_model_domain_party_t source;
    ninlil_model_domain_target_t target;
    ninlil_model_domain_service_identity_t service;
    uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint64_t generation;
    uint8_t deadline_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    uint32_t required_evidence;
    uint32_t receipt_stage;
    uint32_t disposition;
    uint32_t effect_certainty;
    uint32_t retry_guidance;
    uint32_t cancel_kind;
    uint64_t retry_delay_ms;
    uint8_t evidence_clock_epoch[NINLIL_MODEL_DOMAIN_ID_BYTES];
    uint64_t evidence_now_ms;
    uint32_t evidence_trust;
    uint32_t payload_length;
} ninlil_model_domain_message_semantic_prefix_t;

/*
 * Streaming semantic digest state machine (no heap, no VLA, no concatenation
 * buffer). Phases: prefix (init) → payload stream → evidence_length →
 * evidence stream → final. Declared lengths must match bytes absorbed.
 * Hashes data bytes only — never BLOB framing or ABI memory.
 *
 * Alias / address / failure contract (module-wide rules apply):
 * - Full object/byte ranges of every participating argument are address-
 *   validated and pairwise-disjoint before any write. Alias/address failure
 *   returns INVALID_ARGUMENT with every participating range untouched
 *   (including no FAILED transition).
 * - After those gates, non-alias failures that involve a writable ctx set
 *   phase=FAILED. Wrong-phase misuse is a non-alias failure and transitions
 *   FAILED. init also zeros the full ctx on non-alias prefix/nested failure.
 * - final zeros out_digest on non-alias failure after range gates pass;
 *   alias/address failure leaves out_digest and ctx both untouched.
 * - received > declared is rejected before any remaining-length subtraction;
 *   declared evidence > max and incoherent counters are rejected before
 *   underflow/bypass. Underlying SHA context validation still applies.
 */
typedef struct ninlil_model_domain_message_semantic_digest_ctx {
    ninlil_model_domain_sha256_ctx_t sha;
    uint32_t phase;
    uint32_t declared_payload_length;
    uint32_t declared_evidence_length;
    uint32_t received_payload_length;
    uint32_t received_evidence_length;
} ninlil_model_domain_message_semantic_digest_ctx_t;

/* Opaque phase tags for the semantic digest state machine. */
#define NINLIL_MODEL_DOMAIN_MSD_PHASE_PAYLOAD ((uint32_t)1u)
#define NINLIL_MODEL_DOMAIN_MSD_PHASE_EVIDENCE_LEN ((uint32_t)2u)
#define NINLIL_MODEL_DOMAIN_MSD_PHASE_EVIDENCE ((uint32_t)3u)
#define NINLIL_MODEL_DOMAIN_MSD_PHASE_DONE ((uint32_t)4u)
#define NINLIL_MODEL_DOMAIN_MSD_PHASE_FAILED ((uint32_t)5u)

/*
 * Same-record typed view produced by validate_typed_record.
 * body is an anonymous union (stack-bounded); only the matching subtype
 * field is populated. envelope.body and RAW16/member_key borrows remain
 * valid only while encoded_value lives.
 */
typedef struct ninlil_model_domain_typed_record {
    ninlil_model_domain_key_view_t key;
    ninlil_model_domain_envelope_t envelope;
    uint8_t family;
    uint8_t subtype;
    union {
        ninlil_model_domain_body_internal_invariant_t internal_invariant;
        ninlil_model_domain_body_bearer_state_t bearer_state;
        ninlil_model_domain_body_clock_baseline_t clock_baseline;
        ninlil_model_domain_body_attempt_reuse_fence_t attempt_reuse_fence;
        ninlil_model_domain_body_witness_head_index_t witness_head_index;
        ninlil_model_domain_body_service_t service;
        ninlil_model_domain_body_service_quota_t service_quota;
        ninlil_model_domain_body_transaction_anchor_t transaction_anchor;
        ninlil_model_domain_body_transaction_sequence_index_t
            transaction_sequence_index;
        ninlil_model_domain_body_transaction_state_t transaction_state;
        ninlil_model_domain_body_reservation_t reservation;
        ninlil_model_domain_body_idempotency_map_t idempotency_map;
        ninlil_model_domain_body_event_id_map_t event_id_map;
        ninlil_model_domain_body_scheduler_owner_t scheduler_owner;
        ninlil_model_domain_body_ordered_ingress_t ordered_ingress;
        ninlil_model_domain_body_blob_manifest_t blob_manifest;
        ninlil_model_domain_body_blob_chunk_t blob_chunk;
        ninlil_model_domain_body_attempt_t attempt;
    };
} ninlil_model_domain_typed_record_t;

/* --- reusable field length / validation helpers --- */

uint32_t ninlil_model_domain_text_id_encoded_length(
    const ninlil_model_domain_text_id_t *text);
uint32_t ninlil_model_domain_party_encoded_length(void);
uint32_t ninlil_model_domain_target_encoded_length(void);
uint32_t ninlil_model_domain_service_identity_encoded_length(
    const ninlil_model_domain_service_identity_t *identity);
uint32_t ninlil_model_domain_resource_vector_encoded_length(void);

int ninlil_model_domain_text_id_is_valid(
    const ninlil_model_domain_text_id_t *text,
    int namespace_grammar);
int ninlil_model_domain_party_is_valid(const ninlil_model_domain_party_t *party);
int ninlil_model_domain_target_is_valid(
    const ninlil_model_domain_target_t *target);
int ninlil_model_domain_service_identity_is_valid(
    const ninlil_model_domain_service_identity_t *identity);
int ninlil_model_domain_resource_vector_is_valid(
    const ninlil_model_domain_resource_vector_t *vector,
    uint32_t released_mask);

/* --- INTERNAL_INVARIANT --- */
uint32_t ninlil_model_domain_body_internal_invariant_encoded_length(void);

/*
 * Marker identity (key ID128) =
 * SHA-256("NINLIL-DOMAIN-INVARIANT-V1" || reason || subject_kind ||
 *         subject_digest)[0..15]
 */
ninlil_status_t ninlil_model_domain_invariant_marker_id(
    uint32_t reason,
    uint16_t subject_kind,
    const uint8_t subject_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint8_t out_marker_id[NINLIL_MODEL_DOMAIN_ID_BYTES]);

ninlil_status_t ninlil_model_domain_encode_body_internal_invariant(
    const ninlil_model_domain_body_internal_invariant_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_internal_invariant(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_internal_invariant_t *out_body);

/* --- BEARER_STATE --- */
uint32_t ninlil_model_domain_body_bearer_state_encoded_length(void);

ninlil_status_t ninlil_model_domain_encode_body_bearer_state(
    const ninlil_model_domain_body_bearer_state_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_bearer_state(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_bearer_state_t *out_body);

/* --- CLOCK_BASELINE --- */
uint32_t ninlil_model_domain_body_clock_baseline_encoded_length(void);

ninlil_status_t ninlil_model_domain_encode_body_clock_baseline(
    const ninlil_model_domain_body_clock_baseline_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_clock_baseline(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_clock_baseline_t *out_body);

/* --- ATTEMPT_REUSE_FENCE --- */
uint32_t ninlil_model_domain_body_attempt_reuse_fence_encoded_length(void);

ninlil_status_t ninlil_model_domain_encode_body_attempt_reuse_fence(
    const ninlil_model_domain_body_attempt_reuse_fence_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_attempt_reuse_fence(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_attempt_reuse_fence_t *out_body);

/* --- WITNESS_HEAD_INDEX --- */
/*
 * v1 only accepts family 3/4 exact member_key_length=10.
 * Returns 114 for length 10; returns 0 for any other length (including 0).
 */
uint32_t ninlil_model_domain_body_witness_head_index_encoded_length(
    uint16_t member_key_length);

/* Public known ninlil_reason_t values (docs12 / version.h closed registry). */
int ninlil_model_domain_reason_is_known_public(uint32_t reason);

ninlil_status_t ninlil_model_domain_encode_body_witness_head_index(
    const ninlil_model_domain_body_witness_head_index_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * Decode borrows member_key_bytes from encoded. Valid only while encoded
 * remains alive.
 */
ninlil_status_t ninlil_model_domain_decode_body_witness_head_index(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_witness_head_index_t *out_body);

/* --- SERVICE (0x10) --- */
/* Returns required length, or 0 if body shape is not encodable. */
uint32_t ninlil_model_domain_body_service_encoded_length(
    const ninlil_model_domain_body_service_t *body);

ninlil_status_t ninlil_model_domain_encode_body_service(
    const ninlil_model_domain_body_service_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_service(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_service_t *out_body);

/* --- SERVICE_QUOTA (0x11) --- */
uint32_t ninlil_model_domain_body_service_quota_encoded_length(
    const ninlil_model_domain_body_service_quota_t *body);

ninlil_status_t ninlil_model_domain_encode_body_service_quota(
    const ninlil_model_domain_body_service_quota_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_service_quota(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_service_quota_t *out_body);

/* --- TRANSACTION_ANCHOR (0x20) --- */
uint32_t ninlil_model_domain_body_transaction_anchor_encoded_length(
    const ninlil_model_domain_body_transaction_anchor_t *body);

ninlil_status_t ninlil_model_domain_encode_body_transaction_anchor(
    const ninlil_model_domain_body_transaction_anchor_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_transaction_anchor(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_transaction_anchor_t *out_body);

/* --- TRANSACTION_SEQUENCE_INDEX (0x21) --- */
uint32_t ninlil_model_domain_body_transaction_sequence_index_encoded_length(
    void);

ninlil_status_t ninlil_model_domain_encode_body_transaction_sequence_index(
    const ninlil_model_domain_body_transaction_sequence_index_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_transaction_sequence_index(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_transaction_sequence_index_t *out_body);

/* --- TRANSACTION_STATE (0x22) --- */
uint32_t ninlil_model_domain_body_transaction_state_encoded_length(void);

ninlil_status_t ninlil_model_domain_encode_body_transaction_state(
    const ninlil_model_domain_body_transaction_state_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_transaction_state(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_transaction_state_t *out_body);

/* --- RESERVATION (0x23) --- */
uint32_t ninlil_model_domain_body_reservation_encoded_length(
    const ninlil_model_domain_body_reservation_t *body);

ninlil_status_t ninlil_model_domain_encode_body_reservation(
    const ninlil_model_domain_body_reservation_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_reservation(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_reservation_t *out_body);

/* --- IDEMPOTENCY_MAP (0x24) --- */
uint32_t ninlil_model_domain_body_idempotency_map_encoded_length(
    const ninlil_model_domain_body_idempotency_map_t *body);

ninlil_status_t ninlil_model_domain_encode_body_idempotency_map(
    const ninlil_model_domain_body_idempotency_map_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_idempotency_map(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_idempotency_map_t *out_body);

/* --- EVENT_ID_MAP (0x25) --- */
uint32_t ninlil_model_domain_body_event_id_map_encoded_length(
    const ninlil_model_domain_body_event_id_map_t *body);

ninlil_status_t ninlil_model_domain_encode_body_event_id_map(
    const ninlil_model_domain_body_event_id_map_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_event_id_map(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_event_id_map_t *out_body);

/* --- SCHEDULER_OWNER (0x26) --- */
/* Returns required length, or 0 if body shape is not encodable. */
uint32_t ninlil_model_domain_body_scheduler_owner_encoded_length(
    const ninlil_model_domain_body_scheduler_owner_t *body);

ninlil_status_t ninlil_model_domain_encode_body_scheduler_owner(
    const ninlil_model_domain_body_scheduler_owner_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * Decode borrows subject_key_raw from encoded. Valid only while encoded
 * remains alive.
 */
ninlil_status_t ninlil_model_domain_decode_body_scheduler_owner(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_scheduler_owner_t *out_body);

/* --- ORDERED_INGRESS (0x27) --- */
/* Returns required length, or 0 if body shape is not encodable. */
uint32_t ninlil_model_domain_body_ordered_ingress_encoded_length(
    const ninlil_model_domain_body_ordered_ingress_t *body);

ninlil_status_t ninlil_model_domain_encode_body_ordered_ingress(
    const ninlil_model_domain_body_ordered_ingress_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_domain_decode_body_ordered_ingress(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_ordered_ingress_t *out_body);

/* --- BLOB (0x30) manifest + chunk --- */

/*
 * blob_id_digest = SHA-256("NINLIL-DOMAIN-BLOB-ID-V1" ||
 *   blob_owner_kind:u16 || owner_key_raw:RAW16 || blob_kind:u16 ||
 *   content_digest[32] || total_length:u64)
 * owner_key_raw is contents only (RAW16 length prefix is applied here).
 * content_digest must be non-zero. Alias / address failures leave every
 * participating range unchanged; other INVALID zeros *out_digest.
 */
ninlil_status_t ninlil_model_domain_blob_id_digest(
    uint16_t blob_owner_kind,
    uint16_t owner_key_raw_length,
    const uint8_t *owner_key_raw,
    uint16_t blob_kind,
    const uint8_t content_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint64_t total_length,
    ninlil_model_domain_digest_t *out_digest);

/*
 * Checked ceil(total_length / 3072) as u32. total_length=0 → chunk_count=0.
 * Address-validates *out_chunk_count before any write. Overflow of the ceil
 * result past u32 is INVALID_ARGUMENT with *out=0 (when the out range is
 * address-valid). UINT32_MAX*3072 → OK/UINT32_MAX; that total + 1 → INVALID.
 */
ninlil_status_t ninlil_model_domain_blob_chunk_count_for_total(
    uint64_t total_length,
    uint32_t *out_chunk_count);

/* Returns required length, or 0 if body shape is not encodable. */
uint32_t ninlil_model_domain_body_blob_manifest_encoded_length(
    const ninlil_model_domain_body_blob_manifest_t *body);

ninlil_status_t ninlil_model_domain_encode_body_blob_manifest(
    const ninlil_model_domain_body_blob_manifest_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * Decode borrows owner_key_raw from encoded. Valid only while encoded lives.
 */
ninlil_status_t ninlil_model_domain_decode_body_blob_manifest(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_blob_manifest_t *out_body);

/* Returns required length, or 0 if body shape is not encodable. */
uint32_t ninlil_model_domain_body_blob_chunk_encoded_length(
    const ninlil_model_domain_body_blob_chunk_t *body);

ninlil_status_t ninlil_model_domain_encode_body_blob_chunk(
    const ninlil_model_domain_body_blob_chunk_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * Decode borrows chunk_bytes from encoded. Valid only while encoded lives.
 * Zero-length chunk field is always CORRUPT (generic D1-A 0..3072 bound is
 * not sufficient validity for a stored chunk row).
 */
ninlil_status_t ninlil_model_domain_decode_body_blob_chunk(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_blob_chunk_t *out_body);

/* --- ATTEMPT (0x31) --- */
/* Returns required length, or 0 if body shape is not encodable. */
uint32_t ninlil_model_domain_body_attempt_encoded_length(
    const ninlil_model_domain_body_attempt_t *body);

ninlil_status_t ninlil_model_domain_encode_body_attempt(
    const ninlil_model_domain_body_attempt_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * Decode borrows owner_key_raw from encoded. Valid only while encoded lives.
 */
ninlil_status_t ninlil_model_domain_decode_body_attempt(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_attempt_t *out_body);

/*
 * Streaming message_semantic_digest (docs17 §5.1). Pure Core helper:
 * no heap, no VLA, no payload||evidence concatenation buffer.
 * init hashes ASCII prefix + fixed fields through payload_length:u32.
 * update_payload absorbs payload data only (zero-length: no data update).
 * begin_evidence commits evidence_length:u32 after payload complete.
 * update_evidence absorbs evidence data only.
 * final requires both declared lengths exact; zeros out_digest on non-alias
 * failure. Alias/address failures never write ctx/prefix/data/out.
 */
ninlil_status_t ninlil_model_domain_message_semantic_digest_init(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const ninlil_model_domain_message_semantic_prefix_t *prefix);

ninlil_status_t ninlil_model_domain_message_semantic_digest_update_payload(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const uint8_t *data,
    uint32_t length);

ninlil_status_t ninlil_model_domain_message_semantic_digest_begin_evidence(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    uint32_t evidence_length);

ninlil_status_t ninlil_model_domain_message_semantic_digest_update_evidence(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    const uint8_t *data,
    uint32_t length);

ninlil_status_t ninlil_model_domain_message_semantic_digest_final(
    ninlil_model_domain_message_semantic_digest_ctx_t *ctx,
    ninlil_model_domain_digest_t *out_digest);

/*
 * One-shot wrapper over the same streaming state machine. Does not allocate
 * or concatenate payload and evidence into a temporary buffer. Address/alias
 * gates across prefix/payload/evidence/out run before any out write; alias
 * leaves out_digest untouched; non-alias failures zero out_digest.
 */
ninlil_status_t ninlil_model_domain_message_semantic_digest(
    const ninlil_model_domain_message_semantic_prefix_t *prefix,
    ninlil_bytes_view_t payload,
    ninlil_bytes_view_t evidence,
    ninlil_model_domain_digest_t *out_digest);

/*
 * Same-record typed validation for D1-B1 + D1-B2 + D1-B3a..d.
 * Decodes key + envelope (D1-A) and body (this module), then checks
 * header/body/key invariants decidable from one record alone.
 *
 * Not implemented here (deferred with boundary comments in .c):
 * - D2: domain scan / multi-row presence
 * - D3: cross-row primary/index/backlink, fence plan counts, head chains,
 *       live quota recompute from reservations, primary value digest get,
 *       SCHEDULER 1:1 cardinality / counter upper bound / ready semantics /
 *       ingress→delivery owner transfer; ORDERED_INGRESS live owner /
 *       SCHEDULER / RESERVATION / BLOB 0/1 cardinality and BLOB stream
 *       semantic recompute when digests non-zero; SERVICE supported-mask
 *       vs receipt_stage; BLOB live owner/manifest get, primary value digest
 *       equality, chunk 0..count-1 enumeration, multi-chunk stream digest,
 *       owner semantic content match, same-owner/kind/content manifest alias,
 *       lifecycle erase / capacity accounting; ATTEMPT live owner /
 *       ATTEMPT_ID_INDEX 0 / CANCEL_STATE gate / family COMMAND/EVENT kind /
 *       current/stale attempt / primary value digest / target/semantic digest
 *       recompute / SEND_COUNTER health/cardinality (B3d proves same-record
 *       body/key/matrix only; does not implement ATTEMPT_ID_INDEX or
 *       CANCEL_STATE)
 * - D4: COMMIT_UNKNOWN old/new convergence
 *
 * On success, out_record (when non-NULL) is filled; envelope.body and
 * borrowed body pointers reference encoded_value.
 * On non-alias failure with valid out_record, *out_record is zeroed.
 */
ninlil_status_t ninlil_model_domain_validate_typed_record(
    ninlil_bytes_view_t encoded_key,
    ninlil_bytes_view_t encoded_value,
    ninlil_model_domain_typed_record_t *out_record);

/* Family 3/4 complete key shape: root[8]||family||kind, length exact 10. */
int ninlil_model_domain_family34_member_key_is_valid(
    ninlil_bytes_view_t member_key);

/* INTERNAL_INVARIANT subject_kind closed role (docs17 section 6). */
int ninlil_model_domain_invariant_subject_kind_is_valid(uint16_t subject_kind);

#ifdef __cplusplus
}
#endif

#endif
