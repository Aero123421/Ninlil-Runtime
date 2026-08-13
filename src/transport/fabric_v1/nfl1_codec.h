/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private NFL1 v1 codec — Fabric Logical Envelope only.
 * Authority: docs/34-v2-runtime-fabric-completion.md §5.1–§5.2,
 *            docs/adr/0017-bearer-registry-path-selection.md
 *
 * Not installed. Not public ABI. Default-OFF source candidate.
 * Symbol prefix: ninlil_fabric_private_nfl1_
 *
 * No heap, no VLA, no native-struct wire, no pointer persistence.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_NFL1_CODEC_H
#define NINLIL_TRANSPORT_FABRIC_V1_NFL1_CODEC_H

#include "ninlil/platform.h"
#include "ninlil/version.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_FABRIC_PRIVATE_NFL1_VERSION ((uint16_t)1u)
#define NINLIL_FABRIC_PRIVATE_NFL1_HEADER_BYTES ((uint32_t)584u)
#define NINLIL_FABRIC_PRIVATE_NFL1_CODEC_CEILING ((uint32_t)2048u)
#define NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN ((uint32_t)587u)
#define NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MAX ((uint32_t)1925u)
#define NINLIL_FABRIC_PRIVATE_NFL1_SEMANTIC_MAX ((uint32_t)1797u)
#define NINLIL_FABRIC_PRIVATE_NFL1_PAYLOAD_MAX ((uint32_t)1024u)
#define NINLIL_FABRIC_PRIVATE_NFL1_EVIDENCE_MAX ((uint32_t)128u)
#define NINLIL_FABRIC_PRIVATE_NFL1_TEXT_ID_MAX ((uint32_t)63u)

/* Digest algorithm closed for v1: SHA-256 only. */
#define NINLIL_FABRIC_PRIVATE_NFL1_DIGEST_SHA256 ((uint16_t)1u)

typedef uint32_t ninlil_fabric_private_nfl1_status_t;

#define NINLIL_FABRIC_PRIVATE_NFL1_OK ((ninlil_fabric_private_nfl1_status_t)0u)
#define NINLIL_FABRIC_PRIVATE_NFL1_INVALID_ARGUMENT \
    ((ninlil_fabric_private_nfl1_status_t)1u)
#define NINLIL_FABRIC_PRIVATE_NFL1_BUFFER_TOO_SMALL \
    ((ninlil_fabric_private_nfl1_status_t)2u)
#define NINLIL_FABRIC_PRIVATE_NFL1_CORRUPT \
    ((ninlil_fabric_private_nfl1_status_t)3u)
#define NINLIL_FABRIC_PRIVATE_NFL1_UNSUPPORTED \
    ((ninlil_fabric_private_nfl1_status_t)4u)

/*
 * Encode input views: variable regions are borrowed for the call only.
 * Decode output views: variable regions are copy-owned into workspace;
 * the codec never retains pointers into the input packet after return.
 */
typedef struct ninlil_fabric_private_nfl1_bytes_view {
    const uint8_t *bytes;
    uint32_t length;
} ninlil_fabric_private_nfl1_bytes_view_t;

typedef struct ninlil_fabric_private_nfl1_envelope {
    uint16_t api_version; /* local only; not on wire */
    uint16_t struct_size; /* local only; not on wire */
    uint32_t message_kind;
    uint32_t message_flags; /* v1: must be 0 */
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t event_id;
    ninlil_id128_t source_runtime_id;
    ninlil_id128_t source_application_id;
    ninlil_id128_t source_device_id;
    ninlil_id128_t source_installation_id;
    ninlil_id128_t source_site_id;
    uint64_t source_binding_epoch;
    uint64_t source_membership_epoch;
    uint32_t source_flags;
    ninlil_id128_t target_runtime_id;
    ninlil_id128_t target_application_id;
    ninlil_id128_t target_device_id;
    ninlil_id128_t target_installation_id;
    ninlil_id128_t target_site_id;
    uint64_t target_binding_epoch;
    uint64_t target_membership_epoch;
    uint32_t target_flags;
    ninlil_id128_t authority_id;
    uint64_t authority_term;
    uint32_t assignment_epoch;
    uint64_t descriptor_revision;
    ninlil_digest256_t descriptor_digest;
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t family;
    ninlil_digest256_t content_digest;
    uint64_t generation;
    ninlil_id128_t deadline_clock_epoch_id;
    uint64_t absolute_effect_deadline_ms;
    uint64_t evidence_grace_ms;
    uint32_t required_evidence;
    uint32_t receipt_stage;
    uint32_t disposition;
    uint32_t effect_certainty;
    uint32_t retry_guidance;
    uint32_t cancel_kind;
    uint64_t retry_delay_ms;
    ninlil_id128_t evidence_time_clock_epoch_id;
    uint64_t evidence_time_now_ms;
    uint32_t evidence_time_trust;
    ninlil_id128_t route_policy_id;
    uint64_t route_policy_revision;
    ninlil_digest256_t route_policy_digest;
    ninlil_id128_t selected_path_id;
    uint64_t path_selection_epoch;
    uint32_t route_flags; /* v1: must be 0 */
    ninlil_fabric_private_nfl1_bytes_view_t namespace_id;
    ninlil_fabric_private_nfl1_bytes_view_t service_id;
    ninlil_fabric_private_nfl1_bytes_view_t schema_id;
    ninlil_fabric_private_nfl1_bytes_view_t payload;
    ninlil_fabric_private_nfl1_bytes_view_t evidence;
} ninlil_fabric_private_nfl1_envelope_t;

typedef struct ninlil_fabric_private_nfl1_workspace {
    uint8_t bytes[NINLIL_FABRIC_PRIVATE_NFL1_CODEC_CEILING];
    uint32_t used;
} ninlil_fabric_private_nfl1_workspace_t;

void ninlil_fabric_private_nfl1_clear(
    ninlil_fabric_private_nfl1_envelope_t *envelope);

/*
 * Encode: borrows in views for the call; copies into caller out_packet.
 * BUFFER_TOO_SMALL when out_capacity < exact total length (no write).
 * Semantic/structural failure returns CORRUPT/UNSUPPORTED without writing.
 */
ninlil_fabric_private_nfl1_status_t ninlil_fabric_private_nfl1_encode(
    const ninlil_fabric_private_nfl1_envelope_t *in,
    uint8_t *out_packet,
    uint32_t out_capacity,
    uint32_t *out_length);

/*
 * Decode semantics (docs/34 §5.1):
 * - INVALID_ARGUMENT: no mutation of out, workspace, or required size.
 * - BUFFER_TOO_SMALL: exact required workspace size (variable body bytes);
 *   out all-zero; workspace unchanged.
 * - Other failures after arg validation: out all-zero; workspace unchanged.
 * - Success: variable regions copy-owned into workspace; out views point there.
 */
ninlil_fabric_private_nfl1_status_t ninlil_fabric_private_nfl1_decode(
    const uint8_t *packet,
    uint32_t packet_length,
    ninlil_fabric_private_nfl1_workspace_t *workspace,
    ninlil_fabric_private_nfl1_envelope_t *out,
    uint32_t *out_required_workspace);

/* Optional: CRC32C of packet with CRC field treated as zero (diagnostic). */
uint32_t ninlil_fabric_private_nfl1_crc32c(
    const uint8_t *data, size_t length);

/* FBA1 key / dispatch helpers (ADR-0017 enrichment). */
uint32_t ninlil_fabric_private_nfl1_response_slot(
    uint32_t message_kind,
    uint32_t receipt_stage,
    uint32_t disposition,
    uint32_t cancel_kind);

void ninlil_fabric_private_nfl1_foundation_message_digest(
    const uint8_t *packet,
    uint32_t packet_length,
    uint8_t out_digest[32]);

void ninlil_fabric_private_nfl1_service_identity_digest(
    const uint8_t *namespace_id,
    uint16_t namespace_len,
    const uint8_t *service_id,
    uint16_t service_len,
    const uint8_t *schema_id,
    uint16_t schema_len,
    uint64_t descriptor_revision,
    const uint8_t descriptor_digest[32],
    uint16_t schema_major,
    uint16_t schema_minor,
    uint32_t family,
    uint8_t out_digest[32]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_NFL1_CODEC_H */
