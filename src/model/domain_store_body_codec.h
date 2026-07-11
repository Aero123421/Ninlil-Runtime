#ifndef NINLIL_MODEL_DOMAIN_STORE_BODY_CODEC_H
#define NINLIL_MODEL_DOMAIN_STORE_BODY_CODEC_H

#include "domain_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Domain Store v1 pure body codec — D1-B1 slice only.
 * Production-private; not installed. Complements domain_store_codec (D1-A)
 * with exact body encode/decode for five subtypes and same-record typed
 * validation. Does not implement D2 scan, D3 cross-row, or D4 convergence.
 *
 * Scope (exact five bodies):
 *   family 5 subtype 01 INTERNAL_INVARIANT
 *   family 6 subtype 60 BEARER_STATE
 *   family 6 subtype 62 CLOCK_BASELINE
 *   family 6 subtype 64 ATTEMPT_REUSE_FENCE
 *   family 6 subtype 7d WITNESS_HEAD_INDEX
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

/* Exact fixed body lengths (docs17 section 6 / 8.6). */
#define NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES ((uint32_t)96u)
#define NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES ((uint32_t)36u)
#define NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES ((uint32_t)40u)
#define NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES ((uint32_t)16u)
/* HEAD_INDEX with family 3/4 exact-10 member key (docs17 section 8.6). */
#define NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES ((uint32_t)10u)
#define NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES ((uint32_t)114u)

/* Closed body enums (docs17 section 7.1). */
#define NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE ((uint16_t)1u)
#define NINLIL_MODEL_DOMAIN_INDEX_STATE_WITNESSED ((uint16_t)2u)
#define NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED ((uint32_t)1u)
#define NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED ((uint32_t)2u)

/* subject_kind / record role for INTERNAL_INVARIANT (docs17 section 6). */
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE ((uint16_t)0u)
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY3 ((uint16_t)0x0300u)
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY4 ((uint16_t)0x0400u)
#define NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY6_BASE ((uint16_t)0x0600u)

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

/*
 * Same-record typed view produced by validate_typed_record.
 * body_union_tag is the subtype; only one body is populated.
 * envelope.body / head_index.member_key_bytes borrow encoded_value.
 */
typedef struct ninlil_model_domain_typed_record {
    ninlil_model_domain_key_view_t key;
    ninlil_model_domain_envelope_t envelope;
    uint8_t family;
    uint8_t subtype;
    ninlil_model_domain_body_internal_invariant_t internal_invariant;
    ninlil_model_domain_body_bearer_state_t bearer_state;
    ninlil_model_domain_body_clock_baseline_t clock_baseline;
    ninlil_model_domain_body_attempt_reuse_fence_t attempt_reuse_fence;
    ninlil_model_domain_body_witness_head_index_t witness_head_index;
} ninlil_model_domain_typed_record_t;

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

/*
 * Same-record typed validation for the five D1-B1 subtypes.
 * Decodes key + envelope (D1-A) and body (this module), then checks
 * header/body/key invariants decidable from one record alone.
 *
 * Not implemented here (deferred with boundary comments in .c):
 * - D2: domain scan / multi-row presence
 * - D3: cross-row primary/index/backlink, fence plan counts, head chains
 * - D4: COMMIT_UNKNOWN old/new convergence
 *
 * On success, out_record (when non-NULL) is filled; envelope.body and
 * witness_head_index.member_key_bytes borrow encoded_value.
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
