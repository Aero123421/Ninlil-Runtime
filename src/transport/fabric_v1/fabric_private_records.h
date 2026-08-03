/*
 * Private Fabric storage schema 1 codecs: FBM1/FBR1/FBP1/FBC1/FBA1/FBT1.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_RECORDS_H
#define NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_RECORDS_H

#include "fabric_private_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t ninlil_fabric_private_record_status_t;

#define NINLIL_FABRIC_PRIVATE_RECORD_OK \
    ((ninlil_fabric_private_record_status_t)0u)
#define NINLIL_FABRIC_PRIVATE_RECORD_INVALID_ARGUMENT \
    ((ninlil_fabric_private_record_status_t)1u)
#define NINLIL_FABRIC_PRIVATE_RECORD_CORRUPT \
    ((ninlil_fabric_private_record_status_t)2u)
#define NINLIL_FABRIC_PRIVATE_RECORD_UNSUPPORTED \
    ((ninlil_fabric_private_record_status_t)3u)

#define NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED 1u
#define NINLIL_FABRIC_PRIVATE_ATTEMPT_LINK_RETAINED 2u
#define NINLIL_FABRIC_PRIVATE_ATTEMPT_RETRYABLE_NO_ACCEPT 3u
#define NINLIL_FABRIC_PRIVATE_ATTEMPT_CLOSED 4u
#define NINLIL_FABRIC_PRIVATE_ATTEMPT_FENCED_UNKNOWN 5u
#define NINLIL_FABRIC_PRIVATE_ATTEMPT_DRAINED 6u

/* FBA1 co-located one-shot TxPermit claim state. */
#define NINLIL_FABRIC_PRIVATE_PERMIT_CLEAR 0u
#define NINLIL_FABRIC_PRIVATE_PERMIT_CLAIMED 1u

#define NINLIL_FABRIC_PRIVATE_LIFECYCLE_ACTIVE 1u
#define NINLIL_FABRIC_PRIVATE_LIFECYCLE_DRAINING 2u

#define NINLIL_FABRIC_PRIVATE_MIGRATION_CLEAN 1u
#define NINLIL_FABRIC_PRIVATE_MIGRATION_MIGRATING 2u

#define NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_OLD 1u
#define NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_NEW 2u
#define NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_ABSENT 3u
#define NINLIL_FABRIC_PRIVATE_COMMIT_CLASS_CORRUPT 4u

typedef struct ninlil_fabric_private_common_envelope {
    uint8_t magic[4];
    uint16_t schema;
    uint16_t header_length;
    uint32_t total_length;
    uint64_t revision;
    uint32_t crc32c;
} ninlil_fabric_private_common_envelope_t;

typedef struct ninlil_fabric_private_fbm1 {
    uint16_t source_schema;
    uint16_t target_schema;
    uint16_t migration_state;
    uint16_t reserved_zero;
    uint64_t migration_generation;
    uint64_t rollback_floor_generation;
    uint64_t outer_availability_epoch;
    uint32_t outer_available;
    uint32_t reserved_zero_u32;
} ninlil_fabric_private_fbm1_t;

typedef struct ninlil_fabric_private_fbr1 {
    uint8_t instance_id[16];
    uint32_t link_kind;
    uint32_t direction_mask;
    uint32_t capability_flags;
    uint64_t descriptor_revision;
    uint8_t descriptor_digest[32];
    uint8_t security_profile_id[16];
    uint32_t security_capability_flags;
    uint8_t security_binding_digest[32];
    uint64_t attestation_epoch;
    uint8_t attestation_clock_epoch_id[16];
    uint64_t attestation_expires_at_ms;
    uint8_t attestation_digest[32];
    uint8_t authenticated_peer_runtime_id[16];
    uint8_t attachment_authority_id[16];
    uint8_t attachment_binding_digest[32];
    uint32_t maximum_packet_bytes;
    uint32_t maximum_transfer_bytes;
    uint16_t latency_class;
    uint16_t cost_class;
    uint16_t reservation_capacity;
    uint16_t reserved_zero_u16;
    uint64_t availability_epoch;
    uint8_t availability_clock_epoch_id[16];
    uint8_t available; /* 0 or 1 */
    uint8_t lifecycle; /* ACTIVE=1 DRAINING=2 */
    uint16_t reserved_avail_u16;
    uint64_t availability_expires_at_ms;
    uint16_t peer_nfl1_version;
    uint16_t reserved_peer_u16;
    uint32_t peer_fabric_capability_flags;
    uint64_t configuration_revision;
    uint8_t configuration_digest[32];
} ninlil_fabric_private_fbr1_t;

typedef struct ninlil_fabric_private_policy_candidate {
    uint8_t instance_id[16];
    uint16_t rank;
    uint16_t flags;
    uint16_t reservation_units;
    uint16_t reserved_zero;
} ninlil_fabric_private_policy_candidate_t;

typedef struct ninlil_fabric_private_fbp1 {
    uint8_t policy_id[16];
    uint64_t revision;
    uint8_t canonical_digest[32];
    uint8_t service_identity_digest[32];
    uint32_t family;
    uint32_t direction;
    uint16_t traffic_class;
    uint16_t scope_selector;
    uint32_t required_capability_flags;
    uint32_t required_security_flags;
    uint16_t maximum_latency_class;
    uint16_t maximum_cost_class;
    uint32_t minimum_packet_bytes;
    uint8_t authority_mode;
    uint8_t reserved_zero_u8[3];
    uint64_t deadline_guard_ms;
    uint16_t candidate_count;
    uint16_t reserved_zero_u16;
    uint32_t reserved_zero_u32;
    ninlil_fabric_private_policy_candidate_t candidates[8];
} ninlil_fabric_private_fbp1_t;

typedef struct ninlil_fabric_private_fbc1 {
    uint8_t binding_id[16];
    uint8_t service_identity_digest[32];
    uint32_t family;
    uint32_t direction;
    uint16_t traffic_class;
    uint16_t scope_selector;
    uint8_t endpoint_runtime_id[16];
    uint8_t target_runtime_id[16];
    uint8_t target_application_id[16];
    uint8_t policy_id[16];
    uint64_t policy_revision;
    uint8_t policy_digest[32];
    uint32_t authority_state;
    uint8_t authority_id[16];
    uint64_t authority_term;
    uint32_t assignment_epoch;
    uint32_t reserved_zero_u32;
    uint8_t owner_scope_id[16];
    uint8_t owner_tuple_digest[32];
    uint8_t owner_tuple_canonical[200];
    uint8_t authority_clock_epoch_id[16];
    uint64_t lease_expires_at_ms;
    uint64_t assignment_revision;
    uint64_t reserved_zero_u64;
} ninlil_fabric_private_fbc1_t;

typedef struct ninlil_fabric_private_fba1 {
    uint8_t transaction_id[16];
    uint8_t attempt_id[16];
    uint32_t message_kind;
    uint32_t response_slot;
    uint32_t state;
    uint8_t foundation_message_digest[32];
    uint8_t policy_id[16];
    uint64_t policy_revision;
    uint8_t policy_digest[32];
    uint8_t selected_path_id[16];
    uint64_t path_selection_epoch;
    uint32_t route_flags;
    uint32_t authority_state;
    uint8_t authority_id[16];
    uint64_t authority_term;
    uint32_t assignment_epoch;
    uint8_t owner_scope_id[16];
    uint8_t owner_tuple_digest[32];
    uint64_t registry_record_revision;
    uint8_t registry_record_digest[32];
    uint8_t descriptor_digest[32];
    uint8_t security_profile_id[16];
    uint64_t attestation_epoch;
    uint8_t attestation_clock_epoch_id[16];
    uint8_t attestation_digest[32];
    uint64_t attestation_expires_at_ms;
    uint8_t peer_runtime_id[16];
    uint8_t attachment_authority_id[16];
    uint8_t attachment_binding_digest[32];
    uint64_t availability_epoch;
    uint8_t availability_clock_epoch_id[16];
    uint8_t availability_state;
    uint8_t reserved_avail[7];
    uint64_t availability_expires_at_ms;
    uint8_t reservation_id[16];
    uint8_t deadline_clock_epoch_id[16];
    uint64_t deadline_ms;
    uint32_t nfl1_length;
    uint8_t nfl1_sha256[32];
    uint8_t retention_clock_epoch_id[16];
    uint64_t retention_until_ms;
    uint8_t retry_lifetime_clock_epoch_id[16];
    uint64_t retry_expires_at_ms;
    uint8_t local_dispatch_id[32];
    uint64_t runtime_terminal_revision;
    /*
     * TxPermit is immutable per attempt. Its clock epoch is the existing
     * retry_lifetime_clock_epoch_id; no second clock field may diverge.
     */
    uint8_t permit_id[16];
    uint64_t permit_expires_at_ms;
    uint32_t permit_claim_state;
} ninlil_fabric_private_fba1_t;

typedef struct ninlil_fabric_private_fbt1 {
    uint8_t transaction_id[16];
    uint8_t triggering_attempt_id[16];
    uint32_t triggering_kind;
    uint32_t authority_state;
    uint8_t endpoint_runtime_id[16];
    uint8_t owner_scope_id[16];
    uint8_t authority_id[16];
    uint64_t authority_term;
    uint32_t assignment_epoch;
    uint32_t reserved_zero_u32;
    uint8_t owner_tuple_digest[32];
    uint8_t policy_id[16];
    uint64_t policy_revision;
    uint8_t policy_digest[32];
    uint8_t retention_clock_epoch_id[16];
    uint64_t retention_until_ms;
    uint64_t runtime_terminal_revision;
} ninlil_fabric_private_fbt1_t;

ninlil_fabric_private_record_status_t
ninlil_fabric_private_record_encode_envelope(
    const uint8_t magic[4],
    uint64_t revision,
    const uint8_t *payload,
    uint32_t payload_len,
    uint8_t *out_value,
    uint32_t out_capacity,
    uint32_t *out_length);

ninlil_fabric_private_record_status_t
ninlil_fabric_private_record_decode_envelope(
    const uint8_t *value,
    uint32_t value_len,
    const uint8_t expected_magic[4],
    uint32_t expected_payload_len,
    ninlil_fabric_private_common_envelope_t *out_header,
    const uint8_t **out_payload);

/* Key builders (caller-owned fixed buffers). */
void ninlil_fabric_private_key_fbm1(uint8_t out_key[4]);
void ninlil_fabric_private_key_fbr1(
    const uint8_t instance_id[16], uint8_t out_key[20]);
void ninlil_fabric_private_key_fbp1(
    const uint8_t policy_id[16],
    uint64_t revision,
    uint8_t out_key[28]);
void ninlil_fabric_private_key_fbc1(
    const uint8_t binding_id[16], uint8_t out_key[20]);
void ninlil_fabric_private_key_fba1(
    const uint8_t transaction_id[16],
    const uint8_t attempt_id[16],
    uint32_t message_kind,
    uint32_t response_slot,
    const uint8_t foundation_message_digest[32],
    uint8_t out_key[76]);
void ninlil_fabric_private_key_fbt1(
    const uint8_t transaction_id[16],
    const uint8_t triggering_attempt_id[16],
    uint32_t triggering_kind,
    uint8_t out_key[40]);

/* Payload encode/decode into exact fixed sizes. */
ninlil_fabric_private_record_status_t ninlil_fabric_private_fbm1_encode(
    const ninlil_fabric_private_fbm1_t *in,
    uint8_t out_payload[40]);
ninlil_fabric_private_record_status_t ninlil_fabric_private_fbm1_decode(
    const uint8_t payload[40],
    ninlil_fabric_private_fbm1_t *out);

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbr1_encode(
    const ninlil_fabric_private_fbr1_t *in,
    uint8_t out_payload[348]);
ninlil_fabric_private_record_status_t ninlil_fabric_private_fbr1_decode(
    const uint8_t payload[348],
    ninlil_fabric_private_fbr1_t *out);

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbp1_encode(
    const ninlil_fabric_private_fbp1_t *in,
    uint8_t out_payload[328]);
ninlil_fabric_private_record_status_t ninlil_fabric_private_fbp1_decode(
    const uint8_t payload[328],
    ninlil_fabric_private_fbp1_t *out);
/* Compute policy digest with digest field zeroed, then fill canonical_digest. */
void ninlil_fabric_private_fbp1_compute_digest(
    ninlil_fabric_private_fbp1_t *inout);

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbc1_encode(
    const ninlil_fabric_private_fbc1_t *in,
    uint8_t out_payload[488]);
ninlil_fabric_private_record_status_t ninlil_fabric_private_fbc1_decode(
    const uint8_t payload[488],
    ninlil_fabric_private_fbc1_t *out);

void ninlil_fabric_private_owner_tuple_digest(
    const uint8_t canonical[200], uint8_t out[32]);

ninlil_fabric_private_record_status_t ninlil_fabric_private_fba1_encode(
    const ninlil_fabric_private_fba1_t *in,
    uint8_t out_payload[688]);
ninlil_fabric_private_record_status_t ninlil_fabric_private_fba1_decode(
    const uint8_t payload[688],
    ninlil_fabric_private_fba1_t *out);

ninlil_fabric_private_record_status_t ninlil_fabric_private_fbt1_encode(
    const ninlil_fabric_private_fbt1_t *in,
    uint8_t out_payload[224]);
ninlil_fabric_private_record_status_t ninlil_fabric_private_fbt1_decode(
    const uint8_t payload[224],
    ninlil_fabric_private_fbt1_t *out);

void ninlil_fabric_private_registry_record_digest(
    const uint8_t key[20],
    const uint8_t value[372],
    uint8_t out[32]);

void ninlil_fabric_private_local_dispatch_id(
    const uint8_t fba1_key[76], uint8_t out[32]);

/*
 * COMMIT_UNKNOWN classification for one key: compare observed to old/new
 * expected exact rows. Returns OLD/NEW/ABSENT/CORRUPT.
 */
uint32_t ninlil_fabric_private_commit_unknown_classify(
    const uint8_t *old_key,
    uint32_t old_key_len,
    const uint8_t *old_value,
    uint32_t old_value_len,
    const uint8_t *new_key,
    uint32_t new_key_len,
    const uint8_t *new_value,
    uint32_t new_value_len,
    const uint8_t *observed_key,
    uint32_t observed_key_len,
    const uint8_t *observed_value,
    uint32_t observed_value_len,
    int observed_present);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_RECORDS_H */
