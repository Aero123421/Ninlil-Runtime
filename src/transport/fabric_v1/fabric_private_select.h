/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Deterministic Fabric path selection (ADR-0017).
 * Pure function over fixed snapshots; no heap/VLA.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_SELECT_H
#define NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_SELECT_H

#include "fabric_private_records.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ADR-0017 profile-1 admission snapshot bounds.
 * Policies: only current (max-revision) matchers — at most a few; 4 is enough
 * (service match must be exact-1). Full RAM still holds 64 retained revisions.
 * Registry 16 / authorities 64 / active attempts 64 match durable profile.
 */
#define NINLIL_FABRIC_PRIVATE_SELECT_MAX_CANDIDATES 8u
#define NINLIL_FABRIC_PRIVATE_SELECT_MAX_POLICIES 4u
#define NINLIL_FABRIC_PRIVATE_SELECT_MAX_REGISTRY 16u
/* Snapshot holds only policy-matching authority rows (exact-1 join). */
#define NINLIL_FABRIC_PRIVATE_SELECT_MAX_AUTHORITIES 16u
#define NINLIL_FABRIC_PRIVATE_SELECT_MAX_ACTIVE_ATTEMPTS 64u

#define NINLIL_FABRIC_PRIVATE_SEL_SELECTED 1u
#define NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE 2u
#define NINLIL_FABRIC_PRIVATE_SEL_NO_POLICY 3u
#define NINLIL_FABRIC_PRIVATE_SEL_CORRUPT 4u

typedef struct ninlil_fabric_private_select_query {
    uint8_t service_identity_digest[32];
    uint32_t family;
    uint32_t direction;
    uint16_t traffic_class;
    uint8_t source_runtime_id[16];
    uint8_t target_runtime_id[16];
    uint8_t target_application_id[16];
    uint32_t packet_bytes;
    uint32_t transfer_bytes;
    uint64_t now_ms;
    uint64_t deadline_ms;
    uint8_t deadline_clock_epoch_id[16];
    uint8_t admission_clock_epoch_id[16];
    uint8_t availability_clock_epoch_id[16];
    uint8_t attestation_clock_epoch_id[16];
    uint8_t authority_clock_epoch_id[16];
    uint32_t required_capability_flags;
    uint32_t required_security_flags;
    uint32_t requires_sleep_compatible;
    uint32_t requires_custody;
    uint32_t requires_evidence;
    uint8_t authenticated_peer_runtime_id[16];
    uint8_t attachment_authority_id[16];
    uint8_t attachment_binding_digest[32];
    uint32_t rf_permit_valid;
    uint32_t rf_mapping_accepted;
} ninlil_fabric_private_select_query_t;

typedef struct ninlil_fabric_private_select_registry_row {
    uint8_t instance_id[16];
    uint32_t link_kind;
    uint32_t direction_mask;
    uint32_t capability_flags;
    uint32_t security_capability_flags;
    uint32_t maximum_packet_bytes;
    uint32_t maximum_transfer_bytes;
    uint16_t latency_class;
    uint16_t cost_class;
    uint16_t reservation_capacity;
    uint8_t lifecycle; /* ACTIVE=1 */
    uint16_t peer_nfl1_version;
    uint32_t peer_fabric_capability_flags;
    uint8_t authenticated_peer_runtime_id[16];
    uint8_t attachment_authority_id[16];
    uint8_t attachment_binding_digest[32];
    uint8_t attestation_clock_epoch_id[16];
    uint64_t attestation_expires_at_ms;
    uint8_t availability_clock_epoch_id[16];
    uint8_t availability_state;
    uint64_t availability_expires_at_ms;
    uint32_t rf_mapping_approved;
} ninlil_fabric_private_select_registry_row_t;

typedef struct ninlil_fabric_private_select_authority_row {
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
    uint32_t authority_state; /* 0 ABSENT 1 BOUND */
    uint8_t authority_clock_epoch_id[16];
    uint64_t lease_expires_at_ms;
} ninlil_fabric_private_select_authority_row_t;

typedef struct ninlil_fabric_private_select_active_attempt {
    uint8_t instance_id[16];
    uint32_t state; /* PREPARED / LINK_RETAINED only count */
    uint16_t reservation_units;
} ninlil_fabric_private_select_active_attempt_t;

typedef struct ninlil_fabric_private_select_policy {
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
    uint8_t authority_mode; /* 0 ABSENT_ALLOWED 1 BOUND_REQUIRED */
    uint64_t deadline_guard_ms;
    uint16_t candidate_count;
    ninlil_fabric_private_policy_candidate_t candidates[8];
    /* revision_chain[0..revision_chain_len) must be contiguous ending at
     * revision. */
    uint64_t revision_chain[8];
    uint32_t revision_chain_len;
} ninlil_fabric_private_select_policy_t;

typedef struct ninlil_fabric_private_select_snapshot {
    uint32_t outer_available;
    ninlil_fabric_private_select_query_t query;
    uint32_t policy_count;
    ninlil_fabric_private_select_policy_t
        policies[NINLIL_FABRIC_PRIVATE_SELECT_MAX_POLICIES];
    uint32_t registry_count;
    ninlil_fabric_private_select_registry_row_t
        registry[NINLIL_FABRIC_PRIVATE_SELECT_MAX_REGISTRY];
    uint32_t authority_count;
    ninlil_fabric_private_select_authority_row_t
        authorities[NINLIL_FABRIC_PRIVATE_SELECT_MAX_AUTHORITIES];
    uint32_t active_attempt_count;
    ninlil_fabric_private_select_active_attempt_t
        active_attempts[NINLIL_FABRIC_PRIVATE_SELECT_MAX_ACTIVE_ATTEMPTS];
} ninlil_fabric_private_select_snapshot_t;

typedef struct ninlil_fabric_private_select_eval {
    uint8_t instance_id[16];
    uint32_t eligible;
    const char *primary_rejection; /* static string or NULL */
    uint16_t sort_rank;
    uint16_t sort_latency;
    uint16_t sort_cost;
} ninlil_fabric_private_select_eval_t;

typedef struct ninlil_fabric_private_select_result {
    uint32_t resolution;
    const char *primary_rejection;
    uint32_t evaluated_count;
    ninlil_fabric_private_select_eval_t evaluated[8];
    uint8_t selected_instance_id[16];
    uint32_t has_selection;
} ninlil_fabric_private_select_result_t;

void ninlil_fabric_private_select(
    const ninlil_fabric_private_select_snapshot_t *snapshot,
    ninlil_fabric_private_select_result_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_SELECT_H */
