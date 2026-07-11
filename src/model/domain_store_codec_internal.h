#ifndef NINLIL_MODEL_DOMAIN_STORE_CODEC_INTERNAL_H
#define NINLIL_MODEL_DOMAIN_STORE_CODEC_INTERNAL_H

#include "domain_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Implementation/test-only helpers for Domain Store codec.
 * Not an L2 model contract. Pairwise disjoint range rules apply.
 */

int ninlil_model_domain_ranges_are_disjoint(
    const void *left,
    size_t left_length,
    const void *right,
    size_t right_length);

int ninlil_model_domain_encode_ranges_are_disjoint(
    const void *input,
    size_t input_length,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

int ninlil_model_domain_bytes_view_shape_is_valid(ninlil_bytes_view_t view);

int ninlil_model_domain_subtype_is_known(uint8_t family, uint8_t subtype);

int ninlil_model_domain_max_body_for_subtype(
    uint8_t family,
    uint8_t subtype,
    uint32_t *out_max);

int ninlil_model_domain_identity_kind_length_is_valid(
    uint8_t identity_kind,
    uint8_t identity_length);

void ninlil_model_domain_encode_u16_be(uint8_t *destination, uint16_t value);
void ninlil_model_domain_encode_u32_be(uint8_t *destination, uint32_t value);
void ninlil_model_domain_encode_u64_be(uint8_t *destination, uint64_t value);
uint16_t ninlil_model_domain_decode_u16_be(const uint8_t *source);
uint32_t ninlil_model_domain_decode_u32_be(const uint8_t *source);
uint64_t ninlil_model_domain_decode_u64_be(const uint8_t *source);

int ninlil_model_domain_digest_is_zero(
    const uint8_t digest[NINLIL_MODEL_DOMAIN_DIGEST_BYTES]);
int ninlil_model_domain_id_is_zero(
    const uint8_t id[NINLIL_MODEL_DOMAIN_ID_BYTES]);

/*
 * Validate action/presence/digest combination for one manifest entry
 * without inspecting surrounding member set uniqueness/order.
 */
int ninlil_model_domain_witness_entry_shape_is_valid(
    const ninlil_model_domain_witness_entry_t *entry);

int ninlil_model_domain_witness_member_key_is_valid(
    uint16_t record_role,
    uint16_t key_length,
    const uint8_t *key_bytes);

int ninlil_model_domain_operation_identity_is_valid(
    uint16_t operation_kind,
    ninlil_bytes_view_t operation_identity);

#ifdef __cplusplus
}
#endif

#endif
