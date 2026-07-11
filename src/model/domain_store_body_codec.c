#include "domain_store_body_codec.h"
#include "domain_store_codec_internal.h"

#include <string.h>

/*
 * D1-B1 body codec. Boundary notes for later milestones (not implemented):
 * - D2: bounded recovery scan, row budget, workspace state machine.
 * - D3: cross-row primary/index/backlink, ATTEMPT_REUSE_FENCE vs CLEANUP_PLAN
 *   active_plan_count equality, HEAD_INDEX member get/value mutual proof,
 *   family 3/4 capacity/counter mutual recompute.
 * - D4: COMMIT_UNKNOWN old/new complete-value digest convergence.
 */

static const char PREIMAGE_INVARIANT[] = "NINLIL-DOMAIN-INVARIANT-V1";

static const uint8_t KEY_ROOT[8] = {
    0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
};

static int range_address_is_valid(const void *pointer, size_t length)
{
    uintptr_t start;
    if (length == 0u) {
        return 1;
    }
    if (pointer == NULL) {
        return 0;
    }
    start = (uintptr_t)pointer;
    return length <= UINTPTR_MAX - start;
}

static int multi_ranges_ok(const void *const *ptrs, const size_t *lens, size_t n)
{
    size_t i;
    size_t j;
    for (i = 0u; i < n; ++i) {
        if (!range_address_is_valid(ptrs[i], lens[i])) {
            return 0;
        }
        for (j = i + 1u; j < n; ++j) {
            if (!ninlil_model_domain_ranges_are_disjoint(
                    ptrs[i], lens[i], ptrs[j], lens[j])) {
                return 0;
            }
        }
    }
    return 1;
}

static int encode_alias_ok(
    const void *input,
    size_t input_size,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    return ninlil_model_domain_encode_ranges_are_disjoint(
        input, input_size, out_bytes, capacity, out_length);
}

/* --- subject / family34 helpers --- */

int ninlil_model_domain_invariant_subject_kind_is_valid(uint16_t subject_kind)
{
    uint8_t subtype;
    if (subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE
        || subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY3
        || subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY4) {
        return 1;
    }
    if ((subject_kind & 0xff00u) != NINLIL_MODEL_DOMAIN_SUBJECT_KIND_FAMILY6_BASE) {
        return 0;
    }
    subtype = (uint8_t)(subject_kind & 0x00ffu);
    /* Family 5/1/2 and witness metadata subtypes 7d..7f are corrupt. */
    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK
        || subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER) {
        return 0;
    }
    return ninlil_model_domain_subtype_is_known(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN, subtype);
}

int ninlil_model_domain_family34_member_key_is_valid(ninlil_bytes_view_t member_key)
{
    if (!ninlil_model_domain_bytes_view_shape_is_valid(member_key)
        || member_key.length != NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES
        || member_key.data == NULL) {
        return 0;
    }
    if (memcmp(member_key.data, KEY_ROOT, 8u) != 0) {
        return 0;
    }
    if (member_key.data[8] == 0x03u) {
        return member_key.data[9] >= 0x01u && member_key.data[9] <= 0x04u;
    }
    if (member_key.data[8] == 0x04u) {
        return member_key.data[9] >= 0x01u && member_key.data[9] <= 0x0bu;
    }
    return 0;
}

/*
 * docs12 public reason registry (version.h): exact known values only.
 * NONE=0 is a known public value; docs17 does not forbid it on markers.
 * Reserved gaps (e.g. 67) and unknown integers are reject.
 */
int ninlil_model_domain_reason_is_known_public(uint32_t reason)
{
    if (reason == 0u) {
        return 1; /* NINLIL_REASON_NONE */
    }
    if (reason >= 1u && reason <= 24u) {
        return 1;
    }
    if (reason >= 64u && reason <= 66u) {
        return 1;
    }
    if (reason >= 68u && reason <= 86u) {
        return 1;
    }
    if (reason >= 128u && reason <= 132u) {
        return 1;
    }
    if (reason == 4096u || reason == 4097u) {
        return 1;
    }
    return 0;
}

static int internal_invariant_fields_ok(
    const ninlil_model_domain_body_internal_invariant_t *body)
{
    if (body == NULL || body->reserved != 0u) {
        return 0;
    }
    if (!ninlil_model_domain_reason_is_known_public(body->reason)) {
        return 0;
    }
    if (!ninlil_model_domain_invariant_subject_kind_is_valid(body->subject_kind)) {
        return 0;
    }
    /*
     * docs17 §6: namespace-wide subject uses kind and digest both zero.
     * Zero digest is that sentinel; non-namespace subjects store KEY_DIGEST
     * of a complete key, so zero digest with non-zero kind is corrupt.
     * (Live key equality of KEY_DIGEST is still D3.)
     */
    if (body->subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE) {
        if (!ninlil_model_domain_digest_is_zero(body->subject_digest)) {
            return 0;
        }
    } else if (ninlil_model_domain_digest_is_zero(body->subject_digest)) {
        return 0;
    }
    return 1;
}

static int bearer_fields_ok(const ninlil_model_domain_body_bearer_state_t *body)
{
    if (body == NULL) {
        return 0;
    }
    if (body->availability_epoch == 0u) {
        return 0;
    }
    if (body->available > 1u) {
        return 0;
    }
    if (ninlil_model_domain_id_is_zero(body->observation_clock_epoch)) {
        return 0;
    }
    return 1;
}

static int clock_fields_ok(const ninlil_model_domain_body_clock_baseline_t *body)
{
    if (body == NULL || body->reserved != 0u) {
        return 0;
    }
    if (body->baseline_state
        == NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
        return ninlil_model_domain_id_is_zero(body->trusted_clock_epoch)
            && body->last_trusted_now_ms == 0u
            && body->publish_generation == 0u;
    }
    if (body->baseline_state == NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED) {
        /*
         * First accepted Stage 7 sample is generation 1; epoch non-zero.
         * last_trusted_now_ms may be any trusted sample time (new epoch
         * accepts any now). Cross-sample monotonicity is D3/runtime.
         */
        return !ninlil_model_domain_id_is_zero(body->trusted_clock_epoch)
            && body->publish_generation >= 1u;
    }
    return 0;
}

static int fence_fields_ok(
    const ninlil_model_domain_body_attempt_reuse_fence_t *body)
{
    if (body == NULL || body->reserved != 0u) {
        return 0;
    }
    /* Present fence requires active_plan_count >= 1 and generation >= 1. */
    if (body->active_plan_count == 0u || body->fence_generation == 0u) {
        return 0;
    }
    return 1;
}

static int head_index_fields_ok(
    const ninlil_model_domain_body_witness_head_index_t *body)
{
    ninlil_model_domain_digest_t kd;
    ninlil_bytes_view_t key_view;

    if (body == NULL || body->reserved0 != 0u || body->reserved1 != 0u) {
        return 0;
    }
    if (body->index_state != NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE
        && body->index_state != NINLIL_MODEL_DOMAIN_INDEX_STATE_WITNESSED) {
        return 0;
    }
    if (body->member_key_length
            != NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES
        || body->member_key_bytes == NULL) {
        return 0;
    }
    key_view.data = body->member_key_bytes;
    key_view.length = body->member_key_length;
    if (!ninlil_model_domain_family34_member_key_is_valid(key_view)) {
        return 0;
    }
    if (ninlil_model_domain_key_digest(key_view, &kd) != NINLIL_OK
        || memcmp(kd.bytes, body->member_key_digest,
            NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
            != 0) {
        return 0;
    }
    if (body->index_state == NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
        if (!ninlil_model_domain_digest_is_zero(
                body->member_head_witness_digest)) {
            return 0;
        }
    } else if (ninlil_model_domain_digest_is_zero(
                   body->member_head_witness_digest)) {
        return 0;
    }
    return 1;
}

/* --- INTERNAL_INVARIANT --- */

uint32_t ninlil_model_domain_body_internal_invariant_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES;
}

ninlil_status_t ninlil_model_domain_invariant_marker_id(
    uint32_t reason,
    uint16_t subject_kind,
    const uint8_t subject_digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES],
    uint8_t out_marker_id[NINLIL_MODEL_DOMAIN_ID_BYTES])
{
    ninlil_model_domain_sha256_ctx_t ctx;
    ninlil_model_domain_digest_t dig;
    uint8_t scratch[6];
    ninlil_status_t status;

    if (out_marker_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (subject_digest != NULL
        && !ninlil_model_domain_ranges_are_disjoint(
            subject_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES,
            out_marker_id, NINLIL_MODEL_DOMAIN_ID_BYTES)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
    if (subject_digest == NULL
        || !ninlil_model_domain_reason_is_known_public(reason)
        || !ninlil_model_domain_invariant_subject_kind_is_valid(subject_kind)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (subject_kind == NINLIL_MODEL_DOMAIN_SUBJECT_KIND_NAMESPACE) {
        if (!ninlil_model_domain_digest_is_zero(subject_digest)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else if (ninlil_model_domain_digest_is_zero(subject_digest)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&ctx);
    status = ninlil_model_domain_sha256_update(
        &ctx, (const uint8_t *)PREIMAGE_INVARIANT,
        (uint32_t)(sizeof(PREIMAGE_INVARIANT) - 1u));
    if (status != NINLIL_OK) {
        return status;
    }
    ninlil_model_domain_encode_u32_be(&scratch[0], reason);
    status = ninlil_model_domain_sha256_update(&ctx, scratch, 4u);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    ninlil_model_domain_encode_u16_be(&scratch[0], subject_kind);
    status = ninlil_model_domain_sha256_update(&ctx, scratch, 2u);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    status = ninlil_model_domain_sha256_update(
        &ctx, subject_digest, NINLIL_MODEL_DOMAIN_DIGEST_BYTES);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    status = ninlil_model_domain_sha256_final(&ctx, &dig);
    if (status != NINLIL_OK) {
        (void)memset(out_marker_id, 0, NINLIL_MODEL_DOMAIN_ID_BYTES);
        return status;
    }
    (void)memcpy(out_marker_id, dig.bytes, NINLIL_MODEL_DOMAIN_ID_BYTES);
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_encode_body_internal_invariant(
    const ninlil_model_domain_body_internal_invariant_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required = NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !internal_invariant_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u32_be(&out_bytes[0], body->reason);
    ninlil_model_domain_encode_u16_be(&out_bytes[4], body->subject_kind);
    ninlil_model_domain_encode_u16_be(&out_bytes[6], 0u);
    (void)memcpy(&out_bytes[8], body->subject_digest, 32u);
    (void)memcpy(&out_bytes[40], body->first_clock_epoch, 16u);
    ninlil_model_domain_encode_u64_be(&out_bytes[56], body->first_at_ms);
    (void)memcpy(&out_bytes[64], body->detail_digest, 32u);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_internal_invariant(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_internal_invariant_t *out_body)
{
    ninlil_model_domain_body_internal_invariant_t tmp;

    if (out_body == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.data != NULL && encoded.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_INTERNAL_INVARIANT_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.reason = ninlil_model_domain_decode_u32_be(&encoded.data[0]);
    tmp.subject_kind = ninlil_model_domain_decode_u16_be(&encoded.data[4]);
    tmp.reserved = ninlil_model_domain_decode_u16_be(&encoded.data[6]);
    (void)memcpy(tmp.subject_digest, &encoded.data[8], 32u);
    (void)memcpy(tmp.first_clock_epoch, &encoded.data[40], 16u);
    tmp.first_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[56]);
    (void)memcpy(tmp.detail_digest, &encoded.data[64], 32u);
    if (!internal_invariant_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- BEARER_STATE --- */

uint32_t ninlil_model_domain_body_bearer_state_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_bearer_state(
    const ninlil_model_domain_body_bearer_state_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required = NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !bearer_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u64_be(&out_bytes[0], body->availability_epoch);
    ninlil_model_domain_encode_u32_be(&out_bytes[8], body->available);
    (void)memcpy(&out_bytes[12], body->observation_clock_epoch, 16u);
    ninlil_model_domain_encode_u64_be(&out_bytes[28], body->observed_at_ms);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_bearer_state(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_bearer_state_t *out_body)
{
    ninlil_model_domain_body_bearer_state_t tmp;

    if (out_body == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.data != NULL && encoded.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length != NINLIL_MODEL_DOMAIN_BODY_BEARER_STATE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.availability_epoch =
        ninlil_model_domain_decode_u64_be(&encoded.data[0]);
    tmp.available = ninlil_model_domain_decode_u32_be(&encoded.data[8]);
    (void)memcpy(tmp.observation_clock_epoch, &encoded.data[12], 16u);
    tmp.observed_at_ms = ninlil_model_domain_decode_u64_be(&encoded.data[28]);
    if (!bearer_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- CLOCK_BASELINE --- */

uint32_t ninlil_model_domain_body_clock_baseline_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_clock_baseline(
    const ninlil_model_domain_body_clock_baseline_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required = NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !clock_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u32_be(&out_bytes[0], body->baseline_state);
    ninlil_model_domain_encode_u32_be(&out_bytes[4], 0u);
    (void)memcpy(&out_bytes[8], body->trusted_clock_epoch, 16u);
    ninlil_model_domain_encode_u64_be(&out_bytes[24], body->last_trusted_now_ms);
    ninlil_model_domain_encode_u64_be(&out_bytes[32], body->publish_generation);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_clock_baseline(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_clock_baseline_t *out_body)
{
    ninlil_model_domain_body_clock_baseline_t tmp;

    if (out_body == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.data != NULL && encoded.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length != NINLIL_MODEL_DOMAIN_BODY_CLOCK_BASELINE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.baseline_state = ninlil_model_domain_decode_u32_be(&encoded.data[0]);
    tmp.reserved = ninlil_model_domain_decode_u32_be(&encoded.data[4]);
    (void)memcpy(tmp.trusted_clock_epoch, &encoded.data[8], 16u);
    tmp.last_trusted_now_ms =
        ninlil_model_domain_decode_u64_be(&encoded.data[24]);
    tmp.publish_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[32]);
    if (!clock_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- ATTEMPT_REUSE_FENCE --- */

uint32_t ninlil_model_domain_body_attempt_reuse_fence_encoded_length(void)
{
    return NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_attempt_reuse_fence(
    const ninlil_model_domain_body_attempt_reuse_fence_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const uint32_t required =
        NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES;
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_alias_ok(
            body, body == NULL ? 0u : sizeof(*body),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !fence_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u32_be(&out_bytes[0], body->active_plan_count);
    ninlil_model_domain_encode_u32_be(&out_bytes[4], 0u);
    ninlil_model_domain_encode_u64_be(&out_bytes[8], body->fence_generation);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_attempt_reuse_fence(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_attempt_reuse_fence_t *out_body)
{
    ninlil_model_domain_body_attempt_reuse_fence_t tmp;

    if (out_body == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.data != NULL && encoded.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length
            != NINLIL_MODEL_DOMAIN_BODY_ATTEMPT_REUSE_FENCE_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.active_plan_count =
        ninlil_model_domain_decode_u32_be(&encoded.data[0]);
    tmp.reserved = ninlil_model_domain_decode_u32_be(&encoded.data[4]);
    tmp.fence_generation =
        ninlil_model_domain_decode_u64_be(&encoded.data[8]);
    if (!fence_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- WITNESS_HEAD_INDEX --- */

uint32_t ninlil_model_domain_body_witness_head_index_encoded_length(
    uint16_t member_key_length)
{
    /* v1: only exact family 3/4 member keys of length 10 are legal. */
    if (member_key_length
        != NINLIL_MODEL_DOMAIN_HEAD_INDEX_MEMBER_KEY_BYTES) {
        return 0u;
    }
    return NINLIL_MODEL_DOMAIN_BODY_WITNESS_HEAD_INDEX_BYTES;
}

ninlil_status_t ninlil_model_domain_encode_body_witness_head_index(
    const ninlil_model_domain_body_witness_head_index_t *body,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /* Alias among body object, key bytes, out_bytes, out_length. */
    if (body != NULL) {
        ptrs[n] = body;
        lens[n] = sizeof(*body);
        n++;
        if (body->member_key_bytes != NULL && body->member_key_length != 0u) {
            ptrs[n] = body->member_key_bytes;
            lens[n] = body->member_key_length;
            n++;
        }
    }
    if (out_bytes != NULL && capacity != 0u) {
        ptrs[n] = out_bytes;
        lens[n] = capacity;
        n++;
    }
    ptrs[n] = out_length;
    lens[n] = sizeof(*out_length);
    n++;
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !head_index_fields_ok(body)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    required = ninlil_model_domain_body_witness_head_index_encoded_length(
        body->member_key_length);
    if (required > NINLIL_MODEL_DOMAIN_PRIVATE_BODY_MAX_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    ninlil_model_domain_encode_u16_be(&out_bytes[0], body->index_state);
    ninlil_model_domain_encode_u16_be(&out_bytes[2], 0u);
    (void)memcpy(&out_bytes[4], body->member_key_digest, 32u);
    ninlil_model_domain_encode_u16_be(&out_bytes[36], body->member_key_length);
    ninlil_model_domain_encode_u16_be(&out_bytes[38], 0u);
    (void)memcpy(
        &out_bytes[40], body->member_key_bytes, body->member_key_length);
    (void)memcpy(
        &out_bytes[40u + body->member_key_length],
        body->member_value_digest,
        32u);
    (void)memcpy(
        &out_bytes[72u + body->member_key_length],
        body->member_head_witness_digest,
        32u);
    *out_length = required;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_domain_decode_body_witness_head_index(
    ninlil_bytes_view_t encoded,
    ninlil_model_domain_body_witness_head_index_t *out_body)
{
    ninlil_model_domain_body_witness_head_index_t tmp;
    uint16_t key_len;
    uint32_t required;

    if (out_body == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (encoded.data != NULL && encoded.length != 0u
        && !ninlil_model_domain_ranges_are_disjoint(
            encoded.data, encoded.length, out_body, sizeof(*out_body))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_body, 0, sizeof(*out_body));
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded)
        || encoded.length < 104u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memset(&tmp, 0, sizeof(tmp));
    tmp.index_state = ninlil_model_domain_decode_u16_be(&encoded.data[0]);
    tmp.reserved0 = ninlil_model_domain_decode_u16_be(&encoded.data[2]);
    (void)memcpy(tmp.member_key_digest, &encoded.data[4], 32u);
    key_len = ninlil_model_domain_decode_u16_be(&encoded.data[36]);
    tmp.reserved1 = ninlil_model_domain_decode_u16_be(&encoded.data[38]);
    required =
        ninlil_model_domain_body_witness_head_index_encoded_length(key_len);
    if (required == 0u || encoded.length != required) {
        /* unknown key length, short, or trailing rejected */
        return NINLIL_E_STORAGE_CORRUPT;
    }
    tmp.member_key_length = key_len;
    tmp.member_key_bytes = &encoded.data[40];
    (void)memcpy(
        tmp.member_value_digest, &encoded.data[40u + key_len], 32u);
    (void)memcpy(
        tmp.member_head_witness_digest,
        &encoded.data[72u + key_len],
        32u);
    if (!head_index_fields_ok(&tmp)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_body = tmp;
    return NINLIL_OK;
}

/* --- typed record validation --- */

static ninlil_status_t validate_header_body_local(
    uint8_t family,
    uint8_t subtype,
    const ninlil_model_domain_key_view_t *key,
    const ninlil_model_domain_envelope_t *env,
    ninlil_model_domain_typed_record_t *out)
{
    ninlil_status_t status;
    uint8_t expect_primary[NINLIL_MODEL_DOMAIN_ID_BYTES];
    ninlil_bytes_view_t identity;

    if (env->header.subtype != subtype
        || env->header.domain_format != NINLIL_MODEL_DOMAIN_FORMAT_VERSION
        || env->header.flags != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH) {
        if (env->record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_HEALTH) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
    } else if (env->record_type != NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (key->family != family || key->subtype != subtype) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    identity.data = key->identity;
    identity.length = key->identity_length;
    if (ninlil_model_domain_primary_id_from_identity(
            key->identity_kind, identity, expect_primary)
        != NINLIL_OK) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (memcmp(env->header.primary_id, expect_primary,
            NINLIL_MODEL_DOMAIN_ID_BYTES)
        != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
        uint8_t marker[NINLIL_MODEL_DOMAIN_ID_BYTES];
        status = ninlil_model_domain_decode_body_internal_invariant(
            env->body, &out->internal_invariant);
        if (status != NINLIL_OK) {
            return status;
        }
        /* Marker revision always 1; head and primary digest zero (D1-A). */
        if (env->header.record_revision != 1u
            || !ninlil_model_domain_digest_is_zero(
                env->header.head_witness_digest)
            || !ninlil_model_domain_digest_is_zero(
                env->header.primary_value_digest)) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ninlil_model_domain_invariant_marker_id(
                out->internal_invariant.reason,
                out->internal_invariant.subject_kind,
                out->internal_invariant.subject_digest,
                marker)
            != NINLIL_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_ID128
            || key->identity_length != 16u
            || key->identity == NULL
            || memcmp(key->identity, marker, 16u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE) {
        status = ninlil_model_domain_decode_body_bearer_state(
            env->body, &out->bearer_state);
        if (status != NINLIL_OK) {
            return status;
        }
        /* BEARER requires non-zero head; primary digest zero. */
        if (ninlil_model_domain_digest_is_zero(env->header.head_witness_digest)
            || !ninlil_model_domain_digest_is_zero(
                env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE) {
        status = ninlil_model_domain_decode_body_clock_baseline(
            env->body, &out->clock_baseline);
        if (status != NINLIL_OK) {
            return status;
        }
        if (!ninlil_model_domain_digest_is_zero(
                env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /*
         * docs17 §8.6 CLOCK_BASELINE lifecycle:
         *   UNINITIALIZED: revision 1, generation 0
         *   first TRUSTED Stage 7 sample: revision 2, generation 1
         *   each later accepted sample: revision and generation both +1
         * Same-record closed relation: record_revision == publish_generation+1
         * (generation never reaches UINT64_MAX on a stored valid row).
         */
        if (out->clock_baseline.publish_generation == UINT64_MAX
            || env->header.record_revision
                != out->clock_baseline.publish_generation + 1u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (out->clock_baseline.baseline_state
            == NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
            /* Metadata init without witness: head must be zero (§4 allow-list
             * + init path). */
            if (env->header.record_revision != 1u
                || !ninlil_model_domain_digest_is_zero(
                    env->header.head_witness_digest)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            /* TRUSTED: first sample is revision 2 / generation 1. */
            if (env->header.record_revision < 2u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            /*
             * §4: CLOCK_BASELINE is in the zero-head allow-list; non-zero head
             * is not forbidden. Do not require always-zero common head.
             */
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE) {
        status = ninlil_model_domain_decode_body_attempt_reuse_fence(
            env->body, &out->attempt_reuse_fence);
        if (status != NINLIL_OK) {
            return status;
        }
        if (ninlil_model_domain_digest_is_zero(env->header.head_witness_digest)
            || !ninlil_model_domain_digest_is_zero(
                env->header.primary_value_digest)
            || key->identity_kind != NINLIL_MODEL_DOMAIN_ID_KIND_SINGLETON) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /*
         * docs17 §8.6: absent→create generation=1 (revision 1); each present
         * join/leave replacement increments both generation and common
         * revision. Same-record: fence_generation == record_revision.
         */
        if (env->header.record_revision
            != out->attempt_reuse_fence.fence_generation) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    if (subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX) {
        ninlil_model_domain_digest_t composite;
        ninlil_bytes_view_t components;

        status = ninlil_model_domain_decode_body_witness_head_index(
            env->body, &out->witness_head_index);
        if (status != NINLIL_OK) {
            return status;
        }
        if (!ninlil_model_domain_digest_is_zero(
                env->header.primary_value_digest)
            || key->identity_kind
                != NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE
            || key->identity_length != 32u
            || key->identity == NULL) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        /* common head ↔ body head matrix (§8.6) */
        if (out->witness_head_index.index_state
            == NINLIL_MODEL_DOMAIN_INDEX_STATE_BASELINE) {
            if (!ninlil_model_domain_digest_is_zero(
                    env->header.head_witness_digest)
                || !ninlil_model_domain_digest_is_zero(
                    out->witness_head_index.member_head_witness_digest)) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            /*
             * BASELINE indexes are created once at metadata init (rev 1) and
             * never re-created (erase of persistent index is forbidden).
             */
            if (env->header.record_revision != 1u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            if (ninlil_model_domain_digest_is_zero(
                    env->header.head_witness_digest)
                || memcmp(
                       env->header.head_witness_digest,
                       out->witness_head_index.member_head_witness_digest,
                       NINLIL_MODEL_DOMAIN_DIGEST_BYTES)
                    != 0) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
            /*
             * First business mutation BASELINE→WITNESSED is revision 2;
             * subsequent WITNESSED replacements keep revision >= 2.
             */
            if (env->header.record_revision < 2u) {
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
        /*
         * member_value_digest: docs17 does not state a same-record zero/nonzero
         * closed rule independent of the live family 3/4 member value (D3).
         */
        components.data = out->witness_head_index.member_key_digest;
        components.length = NINLIL_MODEL_DOMAIN_DIGEST_BYTES;
        if (ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX,
                components,
                &composite)
            != NINLIL_OK
            || memcmp(key->identity, composite.bytes, 32u) != 0) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }

    return NINLIL_E_INVALID_ARGUMENT;
}

ninlil_status_t ninlil_model_domain_validate_typed_record(
    ninlil_bytes_view_t encoded_key,
    ninlil_bytes_view_t encoded_value,
    ninlil_model_domain_typed_record_t *out_record)
{
    ninlil_model_domain_typed_record_t local;
    ninlil_status_t status;
    size_t n = 0u;
    const void *ptrs[4];
    size_t lens[4];

    /* Alias: real ranges only; leave out_record untouched on alias. */
    if (encoded_key.data != NULL && encoded_key.length != 0u) {
        ptrs[n] = encoded_key.data;
        lens[n] = encoded_key.length;
        n++;
    }
    if (encoded_value.data != NULL && encoded_value.length != 0u) {
        ptrs[n] = encoded_value.data;
        lens[n] = encoded_value.length;
        n++;
    }
    if (out_record != NULL) {
        ptrs[n] = out_record;
        lens[n] = sizeof(*out_record);
        n++;
    }
    if (!multi_ranges_ok(ptrs, lens, n)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&local, 0, sizeof(local));
    if (out_record != NULL) {
        (void)memset(out_record, 0, sizeof(*out_record));
    }
    if (!ninlil_model_domain_bytes_view_shape_is_valid(encoded_key)
        || !ninlil_model_domain_bytes_view_shape_is_valid(encoded_value)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = ninlil_model_domain_parse_key(encoded_key, &local.key);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_decode_envelope(encoded_value, &local.envelope);
    if (status != NINLIL_OK) {
        return status;
    }

    local.family = local.key.family;
    local.subtype = local.key.subtype;

    /* Only the five D1-B1 subtypes are accepted by this API. */
    if (local.family == NINLIL_MODEL_DOMAIN_FAMILY_HEALTH
        && local.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_INTERNAL_INVARIANT) {
        /* ok */
    } else if (local.family == NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
        && (local.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_BEARER_STATE
            || local.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE
            || local.subtype == NINLIL_MODEL_DOMAIN_SUBTYPE_ATTEMPT_REUSE_FENCE
            || local.subtype
                == NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEAD_INDEX)) {
        /* ok */
    } else {
        if (out_record != NULL) {
            (void)memset(out_record, 0, sizeof(*out_record));
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = validate_header_body_local(
        local.family, local.subtype, &local.key, &local.envelope, &local);
    if (status != NINLIL_OK) {
        if (out_record != NULL) {
            (void)memset(out_record, 0, sizeof(*out_record));
        }
        return status;
    }

    if (out_record != NULL) {
        *out_record = local;
    }
    return NINLIL_OK;
}
