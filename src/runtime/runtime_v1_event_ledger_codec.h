/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_RUNTIME_V1_EVENT_LEDGER_CODEC_H
#define NINLIL_RUNTIME_V1_EVENT_LEDGER_CODEC_H

/*
 * V1-LAB-private Event management ledger codec (NEL1).
 *
 * NEL1 is deterministic but is not a canonical Ninlil durable format, not
 * NLR1, and not a docs/17 domain-store record.  A namespace containing NEL1
 * rows MUST NOT be shared with another runtime/profile or durable schema.
 * Compatibility is limited to the exact V1-LAB profile and schema version.
 */

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_V1_EVENT_LEDGER_RESUME_PREFIX ((uint16_t)0x4552u)
#define NINLIL_RT_V1_EVENT_LEDGER_DISCARD_PREFIX ((uint16_t)0x4544u)
#define NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES ((uint32_t)34u)
#define NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES ((uint32_t)18u)
#define NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES ((uint32_t)128u)
#define NINLIL_RT_V1_EVENT_LEDGER_RECORD_MIN_BYTES ((uint32_t)261u)
#define NINLIL_RT_V1_EVENT_LEDGER_RECORD_MAX_BYTES ((uint32_t)388u)

typedef enum ninlil_rt_v1_event_ledger_kind {
    NINLIL_RT_V1_EVENT_LEDGER_KIND_RESUME = 1,
    NINLIL_RT_V1_EVENT_LEDGER_KIND_DISCARD = 2
} ninlil_rt_v1_event_ledger_kind_t;

typedef struct ninlil_rt_v1_event_ledger_record {
    ninlil_rt_v1_event_ledger_kind_t operation_kind;
    uint64_t record_revision;
    uint64_t ordered_sequence;
    ninlil_id128_t transaction_id;
    ninlil_id128_t event_id;
    ninlil_id128_t operation_id;
    ninlil_id128_t actor_id;
    uint8_t canonical_request_digest[NINLIL_SHA256_BYTES];
    uint64_t expected_spool_revision;
    ninlil_id128_t expected_event_id;
    uint16_t expected_content_digest_algorithm;
    uint8_t expected_content_digest[NINLIL_SHA256_BYTES];
    uint32_t request_reason;
    uint32_t acknowledge_flag;
    uint32_t metadata_length;
    uint8_t metadata[NINLIL_RT_V1_EVENT_LEDGER_METADATA_MAX_BYTES];
    ninlil_id128_t audit_clock_epoch_id;
    uint64_t audit_committed_at_ms;
    uint32_t replay_result_kind;
    ninlil_reason_t replay_result_reason;
    uint64_t replay_retry_cycle_id;
    uint64_t replay_spool_revision;
    uint32_t replay_spool_released;
} ninlil_rt_v1_event_ledger_record_t;

void ninlil_rt_v1_event_ledger_key(
    uint16_t prefix,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *operation_id,
    uint8_t out_key[NINLIL_RT_V1_EVENT_LEDGER_KEY_BYTES]);

void ninlil_rt_v1_event_ledger_transaction_prefix(
    uint16_t prefix,
    const ninlil_id128_t *transaction_id,
    uint8_t out_prefix[NINLIL_RT_V1_EVENT_LEDGER_TXN_PREFIX_BYTES]);

ninlil_status_t ninlil_rt_v1_event_resume_request_digest(
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    uint8_t out_digest[NINLIL_SHA256_BYTES]);

ninlil_status_t ninlil_rt_v1_event_discard_request_digest(
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    uint8_t out_digest[NINLIL_SHA256_BYTES]);

ninlil_status_t ninlil_rt_v1_event_ledger_encode(
    const ninlil_rt_v1_event_ledger_record_t *record,
    uint8_t *out_value,
    uint32_t capacity,
    uint32_t *out_length);

/*
 * On failure, out_record is left byte-for-byte unchanged.
 */
ninlil_status_t ninlil_rt_v1_event_ledger_decode(
    ninlil_bytes_view_t value,
    ninlil_rt_v1_event_ledger_record_t *out_record);

ninlil_status_t ninlil_rt_v1_event_ledger_validate(
    ninlil_rt_v1_event_ledger_kind_t expected_kind,
    ninlil_bytes_view_t value);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_EVENT_LEDGER_CODEC_H */
