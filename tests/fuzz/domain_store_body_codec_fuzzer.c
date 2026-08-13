/* SPDX-License-Identifier: Apache-2.0 */
/* libFuzzer entry: selector byte + D1-B body bytes; output remains local. */
#include "domain_store_body_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef NINLIL_FUZZ_REACHABILITY_MAIN
#include <stdio.h>
#endif

#define NINLIL_DOMAIN_FUZZ_DECODER_COUNT ((uint8_t)29u)

typedef union ninlil_domain_fuzz_output {
    ninlil_model_domain_body_internal_invariant_t internal_invariant;
    ninlil_model_domain_body_bearer_state_t bearer_state;
    ninlil_model_domain_body_clock_baseline_t clock_baseline;
    ninlil_model_domain_body_attempt_reuse_fence_t attempt_reuse_fence;
    ninlil_model_domain_body_witness_head_index_t witness_head_index;
    ninlil_model_domain_body_service_t service;
    ninlil_model_domain_body_service_quota_t service_quota;
    ninlil_model_domain_body_transaction_anchor_t transaction_anchor;
    ninlil_model_domain_body_transaction_sequence_index_t transaction_sequence_index;
    ninlil_model_domain_body_transaction_state_t transaction_state;
    ninlil_model_domain_body_reservation_t reservation;
    ninlil_model_domain_body_idempotency_map_t idempotency_map;
    ninlil_model_domain_body_event_id_map_t event_id_map;
    ninlil_model_domain_body_scheduler_owner_t scheduler_owner;
    ninlil_model_domain_body_ordered_ingress_t ordered_ingress;
    ninlil_model_domain_body_blob_manifest_t blob_manifest;
    ninlil_model_domain_body_blob_chunk_t blob_chunk;
    ninlil_model_domain_body_attempt_t attempt;
    ninlil_model_domain_body_attempt_id_index_t attempt_id_index;
    ninlil_model_domain_body_cancel_state_t cancel_state;
    ninlil_model_domain_body_evidence_cell_t evidence_cell;
    ninlil_model_domain_body_delivery_t delivery;
    ninlil_model_domain_body_result_cache_t result_cache;
    ninlil_model_domain_body_reverse_reply_t reverse_reply;
    ninlil_model_domain_body_event_spool_t event_spool;
    ninlil_model_domain_body_retry_summary_t retry_summary;
    ninlil_model_domain_body_management_ledger_t management_ledger;
    ninlil_model_domain_body_retention_basis_t retention_basis;
    ninlil_model_domain_body_cleanup_plan_t cleanup_plan;
} ninlil_domain_fuzz_output_t;

static ninlil_status_t ninlil_domain_fuzz_decode(
    uint8_t selector,
    const uint8_t *data,
    size_t size)
{
    ninlil_bytes_view_t body;
    ninlil_domain_fuzz_output_t out;

    if (selector >= NINLIL_DOMAIN_FUZZ_DECODER_COUNT || size > UINT32_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    body.data = data;
    body.length = (uint32_t)size;
    memset(&out, 0, sizeof(out));
    switch (selector) {
    case 0u:
        return ninlil_model_domain_decode_body_internal_invariant(
            body, &out.internal_invariant);
    case 1u:
        return ninlil_model_domain_decode_body_bearer_state(
            body, &out.bearer_state);
    case 2u:
        return ninlil_model_domain_decode_body_clock_baseline(
            body, &out.clock_baseline);
    case 3u:
        return ninlil_model_domain_decode_body_attempt_reuse_fence(
            body, &out.attempt_reuse_fence);
    case 4u:
        return ninlil_model_domain_decode_body_witness_head_index(
            body, &out.witness_head_index);
    case 5u:
        return ninlil_model_domain_decode_body_service(body, &out.service);
    case 6u:
        return ninlil_model_domain_decode_body_service_quota(
            body, &out.service_quota);
    case 7u:
        return ninlil_model_domain_decode_body_transaction_anchor(
            body, &out.transaction_anchor);
    case 8u:
        return ninlil_model_domain_decode_body_transaction_sequence_index(
            body, &out.transaction_sequence_index);
    case 9u:
        return ninlil_model_domain_decode_body_transaction_state(
            body, &out.transaction_state);
    case 10u:
        return ninlil_model_domain_decode_body_reservation(
            body, &out.reservation);
    case 11u:
        return ninlil_model_domain_decode_body_idempotency_map(
            body, &out.idempotency_map);
    case 12u:
        return ninlil_model_domain_decode_body_event_id_map(
            body, &out.event_id_map);
    case 13u:
        return ninlil_model_domain_decode_body_scheduler_owner(
            body, &out.scheduler_owner);
    case 14u:
        return ninlil_model_domain_decode_body_ordered_ingress(
            body, &out.ordered_ingress);
    case 15u:
        return ninlil_model_domain_decode_body_blob_manifest(
            body, &out.blob_manifest);
    case 16u:
        return ninlil_model_domain_decode_body_blob_chunk(
            body, &out.blob_chunk);
    case 17u:
        return ninlil_model_domain_decode_body_attempt(body, &out.attempt);
    case 18u:
        return ninlil_model_domain_decode_body_attempt_id_index(
            body, &out.attempt_id_index);
    case 19u:
        return ninlil_model_domain_decode_body_cancel_state(
            body, &out.cancel_state);
    case 20u:
        return ninlil_model_domain_decode_body_evidence_cell(
            body, &out.evidence_cell);
    case 21u:
        return ninlil_model_domain_decode_body_delivery(body, &out.delivery);
    case 22u:
        return ninlil_model_domain_decode_body_result_cache(
            body, &out.result_cache);
    case 23u:
        return ninlil_model_domain_decode_body_reverse_reply(
            body, &out.reverse_reply);
    case 24u:
        return ninlil_model_domain_decode_body_event_spool(
            body, &out.event_spool);
    case 25u:
        return ninlil_model_domain_decode_body_retry_summary(
            body, &out.retry_summary);
    case 26u:
        return ninlil_model_domain_decode_body_management_ledger(
            body, &out.management_ledger);
    case 27u:
        return ninlil_model_domain_decode_body_retention_basis(
            body, &out.retention_basis);
    case 28u:
        return ninlil_model_domain_decode_body_cleanup_plan(
            body, &out.cleanup_plan);
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

#ifdef NINLIL_FUZZ_REACHABILITY_MAIN
int main(void)
{
    uint8_t input[4097];
    size_t size = fread(input, 1u, sizeof(input), stdin);

    if (size < 2u || size == sizeof(input) || ferror(stdin) != 0) {
        return 2;
    }
    return ninlil_domain_fuzz_decode(input[0], input + 1u, size - 1u)
            == NINLIL_OK
        ? 0
        : 1;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1u) {
        return 0;
    }
    (void)ninlil_domain_fuzz_decode(data[0], data + 1u, size - 1u);
    return 0;
}
#endif
