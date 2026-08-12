/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private durable codecs for ADR-0019/0020 records.
 * Default-OFF, not installed.
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_CODEC_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_CODEC_H

#include "rrmp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --- NRM1 management record (256) --- */
typedef struct ninlil_rrmp_nrm1_fields {
    ninlil_rrmp_id16_t authority_id;
    uint64_t controller_term;
    uint64_t route_revision;
    uint64_t lease_epoch;
    ninlil_rrmp_id16_t authority_clock_epoch_id;
    uint64_t lease_expiry_ms;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    ninlil_rrmp_id16_t egress_peer_id;
    uint32_t egress_hop_context_id;
    uint16_t egress_route_handle;
    uint16_t egress_route_generation;
    ninlil_rrmp_id16_t grant_id;
    uint16_t queue_quota_entries;
    uint32_t queue_quota_bytes;
    uint8_t max_hops;
    uint8_t ack_policy;
    uint8_t terminal_flag;
    ninlil_rrmp_id16_t path_policy_id;
    uint64_t path_policy_revision;
} ninlil_rrmp_nrm1_fields_t;

int ninlil_rrmp_encode_nrm1(
    const ninlil_rrmp_nrm1_fields_t *fields, uint8_t out[NINLIL_RRMP_NRM1_BYTES]);
int ninlil_rrmp_decode_nrm1(
    const uint8_t in[NINLIL_RRMP_NRM1_BYTES], ninlil_rrmp_nrm1_fields_t *out);

int ninlil_rrmp_materialize_exact(
    const ninlil_rrmp_nrm1_fields_t *fields,
    uint8_t out[NINLIL_RRMP_EXACT_BODY_BYTES]);

/* --- Route slot (508) / NRP1 page (4096) / NRD1 directory (256) --- */
typedef struct ninlil_rrmp_drain_fence {
    uint64_t drain_fence;
    uint64_t route_revision;
    uint64_t drain_deadline_ms;
    uint64_t lease_deadline_ms;
} ninlil_rrmp_drain_fence_t;

int ninlil_rrmp_encode_slot(
    uint8_t state,
    const ninlil_rrmp_nrm1_fields_t *fields,
    uint64_t next_admission_seq,
    const ninlil_rrmp_drain_fence_t *drain_or_null,
    uint8_t out[NINLIL_RRMP_SLOT_BYTES]);
int ninlil_rrmp_decode_slot_state(
    const uint8_t in[NINLIL_RRMP_SLOT_BYTES],
    uint8_t *state_out,
    ninlil_rrmp_nrm1_fields_t *fields_out,
    uint64_t *next_admission_seq_out);

int ninlil_rrmp_encode_nrp1(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots[NINLIL_RRMP_SLOTS_PER_PAGE],
    uint8_t out[NINLIL_RRMP_NRP1_BYTES]);
int ninlil_rrmp_validate_nrp1(const uint8_t in[NINLIL_RRMP_NRP1_BYTES]);

int ninlil_rrmp_encode_nrd1(
    uint64_t directory_generation,
    const ninlil_rrmp_id16_t *authority_id,
    uint64_t controller_term,
    const uint32_t route_page_gens[NINLIL_RRMP_PAGE_COUNT],
    const uint32_t evidence_page_gens[NINLIL_RRMP_NEP1_PAGE_COUNT],
    uint8_t out[NINLIL_RRMP_DIR_BYTES]);
int ninlil_rrmp_validate_nrd1(const uint8_t in[NINLIL_RRMP_DIR_BYTES]);

/* --- NEV1 evidence (128) / NEP1 page (4096) --- */
typedef struct ninlil_rrmp_nev1_fields {
    uint16_t route_handle;
    uint16_t route_generation;
    uint64_t admission_seq;
    ninlil_rrmp_digest32_t e2e_header_digest;
    uint64_t outer_rx_counter;
    uint64_t outer_tx_counter;
    ninlil_rrmp_id16_t local_runtime_id;
    uint8_t hop_remaining_in;
    uint8_t hop_remaining_out;
    uint8_t lifecycle; /* LIVE/COMPLETED; EMPTY is absent slot */
    uint32_t result_status;
} ninlil_rrmp_nev1_fields_t;

int ninlil_rrmp_encode_nev1(
    const ninlil_rrmp_nev1_fields_t *fields, uint8_t out[NINLIL_RRMP_NEV1_BYTES]);
int ninlil_rrmp_decode_nev1(
    const uint8_t in[NINLIL_RRMP_NEV1_BYTES], ninlil_rrmp_nev1_fields_t *out);
int ninlil_rrmp_validate_nev1(const uint8_t in[NINLIL_RRMP_NEV1_BYTES]);

int ninlil_rrmp_encode_nep1(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots,
    size_t slot_count,
    uint8_t out[NINLIL_RRMP_NEP1_BYTES]);
int ninlil_rrmp_validate_nep1(const uint8_t in[NINLIL_RRMP_NEP1_BYTES]);

/* --- NPS1 / NPP1 / NOA1 / NPH1 --- */
typedef struct ninlil_rrmp_nps1_fields {
    ninlil_rrmp_id16_t owner_scope_id;
    ninlil_rrmp_id16_t parent_set_id;
    uint64_t parent_set_revision;
    uint8_t parent_count;
    ninlil_rrmp_id16_t parent_ids[NINLIL_RRMP_PARENT_MAX];
    ninlil_rrmp_digest32_t parent_set_digest;
} ninlil_rrmp_nps1_fields_t;

int ninlil_rrmp_parent_set_digest(
    const ninlil_rrmp_id16_t *parent_ids,
    uint8_t count,
    ninlil_rrmp_digest32_t *out);

int ninlil_rrmp_encode_nps1(
    const ninlil_rrmp_nps1_fields_t *fields, uint8_t out[NINLIL_RRMP_NPS1_BYTES]);
int ninlil_rrmp_decode_nps1(
    const uint8_t in[NINLIL_RRMP_NPS1_BYTES], ninlil_rrmp_nps1_fields_t *out);
int ninlil_rrmp_validate_nps1(const uint8_t in[NINLIL_RRMP_NPS1_BYTES]);

int ninlil_rrmp_encode_npp1(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots[NINLIL_RRMP_NPP1_SLOTS],
    uint8_t out[NINLIL_RRMP_NPP1_BYTES]);
int ninlil_rrmp_validate_npp1(const uint8_t in[NINLIL_RRMP_NPP1_BYTES]);

typedef struct ninlil_rrmp_noa1_fields {
    ninlil_rrmp_id16_t owner_scope_id;
    ninlil_rrmp_id16_t authority_id;
    uint64_t controller_term;
    uint64_t assignment_epoch;
    uint64_t assignment_revision;
    ninlil_rrmp_id16_t owner_controller_id;
    ninlil_rrmp_id16_t owner_cell_id;
    uint8_t direction;
    uint32_t e2e_context_id;
    uint64_t key_generation;
    ninlil_rrmp_id16_t e2e_security_id;
    uint64_t e2e_security_epoch;
    ninlil_rrmp_digest32_t e2e_binding_digest;
    ninlil_rrmp_id16_t authority_clock_epoch_id;
    uint64_t lease_not_after_authority_ms;
    ninlil_rrmp_digest32_t handoff_token_digest;
    /* parent-set durable reference (after body digest) */
    ninlil_rrmp_digest32_t parent_set_digest;
    uint8_t parent_set_count;
    ninlil_rrmp_id16_t parent_set_id;
} ninlil_rrmp_noa1_fields_t;

int ninlil_rrmp_encode_noa1(
    const ninlil_rrmp_noa1_fields_t *fields, uint8_t out[NINLIL_RRMP_NOA1_BYTES]);
int ninlil_rrmp_decode_noa1(
    const uint8_t in[NINLIL_RRMP_NOA1_BYTES], ninlil_rrmp_noa1_fields_t *out);
int ninlil_rrmp_validate_noa1(const uint8_t in[NINLIL_RRMP_NOA1_BYTES]);

int ninlil_rrmp_authority_commit_digest(
    const uint8_t noa1_body_digest[32],
    const uint8_t nps1_record_digest[32],
    const uint8_t handoff_token_digest[32],
    uint64_t controller_term,
    uint64_t assignment_revision,
    ninlil_rrmp_digest32_t *out);

typedef struct ninlil_rrmp_nph1_fields {
    ninlil_rrmp_id16_t authority_id;
    ninlil_rrmp_id16_t writer_controller_id;
    uint64_t controller_term;
    uint64_t writer_epoch;
    uint64_t lease_not_after_ms;
    ninlil_rrmp_id16_t authority_clock_epoch_id;
    ninlil_rrmp_digest32_t writer_proof_digest;
    uint64_t header_generation;
    uint16_t assignment_page_bitmap;
    uint16_t token_page_bitmap;
    ninlil_rrmp_digest32_t authority_commit_digest;
} ninlil_rrmp_nph1_fields_t;

int ninlil_rrmp_encode_nph1(
    const ninlil_rrmp_nph1_fields_t *fields, uint8_t out[NINLIL_RRMP_NPH1_BYTES]);
int ninlil_rrmp_validate_nph1(const uint8_t in[NINLIL_RRMP_NPH1_BYTES]);

/* NPA1 assignment page (4096) + NPT1 token page (4096) */
int ninlil_rrmp_encode_assignment_slot(
    const uint8_t noa1[NINLIL_RRMP_NOA1_BYTES],
    uint8_t local_state,
    const uint8_t proof_digest[32],
    const uint8_t receipt_digest[32],
    uint8_t out[NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES]);
int ninlil_rrmp_encode_npa1_page(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *const slots[NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE],
    uint8_t out[NINLIL_RRMP_NPA1_BYTES]);
int ninlil_rrmp_validate_npa1(const uint8_t in[NINLIL_RRMP_NPA1_BYTES]);

int ninlil_rrmp_encode_npt1_slot(
    const uint8_t digest32[32],
    uint8_t kind,
    uint64_t created_ms,
    uint8_t out[NINLIL_RRMP_NPT1_SLOT_BYTES]);
int ninlil_rrmp_encode_npt1_page(
    uint16_t page_index,
    uint32_t page_generation,
    const uint8_t *slots_packed, /* kind-occupied prefix of NPT1_SLOT_BYTES each */
    uint32_t slot_count,
    uint8_t out[NINLIL_RRMP_NPT1_BYTES]);
int ninlil_rrmp_validate_npt1(const uint8_t in[NINLIL_RRMP_NPT1_BYTES]);

/*
 * ADR-0020 §4 exact owner_scope_id derivation:
 * SHA-256("NINLIL-OWNER-SCOPE-V1" || endpoint16 || direction_u8 ||
 *   namespace_len_u16_be || namespace || service_len_u16_be || service ||
 *   traffic_class_u16_be || path_policy_id16)[0..15]
 * namespace/service length 1..63. Returns 0 on invalid inputs.
 */
int ninlil_rrmp_derive_owner_scope_id(
    const uint8_t endpoint_runtime_id[16],
    uint8_t direction,
    const uint8_t *namespace_bytes,
    uint16_t namespace_len,
    const uint8_t *service_bytes,
    uint16_t service_len,
    uint16_t traffic_class,
    const uint8_t path_policy_id[16],
    uint8_t owner_scope_id_out[16]);

/* Domain tags for loop / dedup / evidence durable keys */
void ninlil_rrmp_loop_key(
    const uint8_t e2e_header_digest32[32],
    uint16_t route_handle,
    uint16_t route_generation,
    const uint8_t local_runtime_id16[16],
    ninlil_rrmp_digest32_t *out);

void ninlil_rrmp_dedup_key(
    const uint8_t e2e_header_digest32[32],
    uint32_t ingress_hop_context_id,
    uint16_t route_handle,
    uint16_t route_generation,
    ninlil_rrmp_digest32_t *out);

void ninlil_rrmp_evidence_key(
    const uint8_t e2e_header_digest32[32],
    uint16_t route_handle,
    uint16_t route_generation,
    uint64_t admission_seq,
    ninlil_rrmp_digest32_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_CODEC_H */
