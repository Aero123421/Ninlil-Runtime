/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ADR-0021 exact four-slot Host coordinator.
 *
 * Source-only, private, default-OFF, not installed, and not public ABI.
 */
#ifndef NINLIL_MFDT_V1_HOST_COORDINATOR_H
#define NINLIL_MFDT_V1_HOST_COORDINATOR_H

#include "mfdt_v1.h"
#include "mfdt_v1_pipeline.h"
#include "mfdt_v1_store_port.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MFDT_V1_HOST_SLOT_COUNT       ((size_t)4u)
#define NINLIL_MFDT_V1_HOST_HEADER_BYTES     ((size_t)128u)
#define NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES  ((size_t)96u)
#define NINLIL_MFDT_V1_HOST_METADATA_BYTES   ((size_t)512u)
#define NINLIL_MFDT_V1_HOST_TERMINAL_COUNT_MAX ((size_t)16u)
#define NINLIL_MFDT_V1_HOST_TERMINAL_DESC_BYTES ((size_t)64u)
#define NINLIL_MFDT_V1_HOST_TERMINAL_CATALOG_BYTES ((size_t)1024u)
#define NINLIL_MFDT_V1_HOST_CONTROL_META_BYTES ((size_t)64u)
#define NINLIL_MFDT_V1_HOST_CONTROL_OUTBOX_BYTES ((size_t)1024u)
#define NINLIL_MFDT_V1_HOST_CONTROL_NRC1_BYTES ((size_t)15024u)
#define NINLIL_MFDT_V1_HOST_CONTROL_NM30_BYTES ((size_t)184u)
#define NINLIL_MFDT_V1_HOST_CONTROL_RESERVED_BYTES ((size_t)88u)
#define NINLIL_MFDT_V1_HOST_CONTROL_AREA_BYTES ((size_t)17920u)
#define NINLIL_MFDT_V1_HOST_OWNER_BYTES      ((size_t)280064u)
#define NINLIL_MFDT_V1_HOST_CONTROL_ROUTE    ((uint8_t)0xffu)

#define NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES   ((size_t)35216u)
#define NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES     ((size_t)15024u)
#define NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES ((size_t)2304u)
#define NINLIL_MFDT_V1_HOST_ENGINE_REGION_BYTES   ((size_t)256u)
#define NINLIL_MFDT_V1_HOST_TEMP_REGION_BYTES     ((size_t)12736u)

#define NINLIL_MFDT_V1_HOST_ROLE_SENDER   ((uint8_t)1u)
#define NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ((uint8_t)2u)

typedef union ninlil_mfdt_v1_host_owner {
    uint64_t align8;
    uint8_t opaque[NINLIL_MFDT_V1_HOST_OWNER_BYTES];
} ninlil_mfdt_v1_host_owner_t;

typedef struct ninlil_mfdt_v1_host_bind {
    uint8_t peer_endpoint_id[16];
    uint32_t session_generation;
    uint64_t session_cookie;
    uint8_t role;
} ninlil_mfdt_v1_host_bind_t;

typedef struct ninlil_mfdt_v1_host_header_snapshot {
    uint64_t now_ms;
    uint64_t committed_logical_bytes;
    uint32_t tracked_groups;
    uint32_t committed_keys;
    uint8_t active_count;
    uint8_t next_slot;
    uint8_t full_locked;
    uint8_t started;
    uint8_t recovered;
    uint8_t inventory_uncertain;
    uint8_t terminal_count;
    uint8_t control_outbox_pending;
} ninlil_mfdt_v1_host_header_snapshot_t;

typedef struct ninlil_mfdt_v1_host_slot_snapshot {
    uint8_t transfer_id[16];
    uint8_t peer_endpoint_id[16];
    uint64_t session_cookie;
    uint32_t session_generation;
    uint32_t fulls_this_transfer;
    uint8_t role;
    uint8_t occupied;
    uint8_t bind_valid;
    uint8_t unpaid_chunk_offer;
    uint8_t active_accounted;
    uint8_t engine_active;
    uint8_t pipeline_phase;
    uint8_t outbox_pending;
} ninlil_mfdt_v1_host_slot_snapshot_t;

/*
 * Source-private restart identity. `metadata` points only at caller-owned
 * Foundation projections; the Host compares it with the canonical OPEN
 * embedded in the recovered NM3S row and retains no pointer.
 */
typedef struct ninlil_mfdt_v1_host_sender_expectation {
    uint8_t transfer_id[16];
    uint8_t content_digest[32];
    uint32_t content_length;
    ninlil_mfdt_v1_open_metadata_t metadata;
} ninlil_mfdt_v1_host_sender_expectation_t;

typedef struct ninlil_mfdt_v1_host_recovered_sender_view {
    uint8_t transfer_id[16];
    uint8_t origin_transaction_id[16];
    uint8_t peer_endpoint_id[16];
    uint32_t stored_session_generation;
    uint8_t slot;
    uint8_t state_code;
    uint8_t fresh_open_arm;
    uint8_t reserved_zero;
} ninlil_mfdt_v1_host_recovered_sender_view_t;

/*
 * Source-private, read-only receiver application authority for the READY and
 * HANDED_OFF phases. OPEN and content are borrowed from the canonical packed
 * NM3R row and remain valid only until the next Host mutation. This view
 * deliberately does not require a live carrier bind, so the same authority is
 * available after a cold restart.
 */
typedef struct ninlil_mfdt_v1_host_receiver_ready_view {
    const uint8_t *open_body;
    const uint8_t *content;
    uint16_t open_body_length;
    uint32_t content_length;
    uint8_t transfer_id[16];
    uint8_t peer_endpoint_id[16];
    uint8_t publication_token[16];
    uint64_t acceptance_generation;
    uint32_t stored_session_generation;
    uint8_t slot;
    uint8_t state_code;
    uint8_t publication_state;
    uint8_t handoff_state;
    uint8_t publication_evidence_digest[32];
} ninlil_mfdt_v1_host_receiver_ready_view_t;

/* Source-private, read-only retained-terminal correlation authority. */
typedef struct ninlil_mfdt_v1_host_terminal_view {
    uint8_t transfer_id[16];
    uint8_t peer_endpoint_id[16];
    uint32_t stored_session_generation;
    uint32_t transfer_revision;
    uint8_t manifest_digest[32];
    uint8_t open_request_body_digest[32];
    uint16_t terminal_state;
    uint16_t terminal_reason;
    uint8_t role;
    uint8_t replay_eligible;
    uint8_t reserved_zero[2];
} ninlil_mfdt_v1_host_terminal_view_t;

int ninlil_mfdt_v1_host_owner_init(
    ninlil_mfdt_v1_host_owner_t *owner,
    ninlil_mfdt_v1_store_port_t *store,
    const ninlil_mfdt_v1_config_t *base_config);

int ninlil_mfdt_v1_host_owner_recover(
    ninlil_mfdt_v1_host_owner_t *owner);

int ninlil_mfdt_v1_host_owner_start(
    ninlil_mfdt_v1_host_owner_t *owner);

int ninlil_mfdt_v1_host_rebind_recovered(
    ninlil_mfdt_v1_host_owner_t *owner,
    const uint8_t transfer_id[16],
    const ninlil_mfdt_v1_host_bind_t *bind);

/*
 * Validate and view one unbound recovered sender. When `expected` is non-NULL
 * every immutable OPEN/Application identity and the content length+digest
 * must match exactly. This function performs no durable or wire mutation.
 */
int ninlil_mfdt_v1_host_recovered_sender_view(
    const ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const ninlil_mfdt_v1_host_sender_expectation_t *expected,
    uint8_t *scratch,
    uint32_t scratch_capacity,
    ninlil_mfdt_v1_host_recovered_sender_view_t *out);

int ninlil_mfdt_v1_host_receiver_ready_view(
    const ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    ninlil_mfdt_v1_host_receiver_ready_view_t *out);

int ninlil_mfdt_v1_host_terminal_view(
    ninlil_mfdt_v1_host_owner_t *owner,
    const uint8_t transfer_id[16],
    ninlil_mfdt_v1_host_terminal_view_t *out);

int ninlil_mfdt_v1_host_sender_open_with_metadata(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const uint8_t transfer_id[16],
    const uint8_t *content,
    uint32_t content_len,
    const ninlil_mfdt_v1_open_metadata_t *metadata,
    uint64_t request_id,
    uint8_t *slot_out);

/*
 * Source-private cross-namespace compensation primitive.  It accepts only
 * the exact fresh sender arm produced by sender_open above, before its OPEN
 * outbox ownership has advanced.  A successful call compare-erases NM3S and
 * NRC1 in one FULL and releases the exact Host slot; every shape/bind mismatch
 * is mutation-free. `scratch` is caller-owned, non-aliasing storage used for
 * the same-transaction read-back and must fit ACTIVE_VALUE_MAX bytes.
 */
int ninlil_mfdt_v1_host_disarm_fresh_sender(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t transfer_id[16],
    uint8_t *scratch,
    uint32_t scratch_capacity);

/* Cold-only equivalent: exact unbound recovered fresh arm, no reissue. */
int ninlil_mfdt_v1_host_disarm_recovered_fresh_sender(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t transfer_id[16],
    uint8_t *scratch,
    uint32_t scratch_capacity);

/*
 * Return status describes Host transport processing, while an exact protocol
 * refusal is carried by response/outbox as REJECT or BUSY.  Once such a frame
 * is formed and owned this function returns OK and publishes slot_out; only a
 * malformed request or an unformed/unowned response returns semantic/internal
 * error. Stateless fresh-OPEN refusals and retained-terminal responses use
 * NINLIL_MFDT_V1_HOST_CONTROL_ROUTE and never consume an active slot.
 */
int ninlil_mfdt_v1_host_on_wire(
    ninlil_mfdt_v1_host_owner_t *owner,
    const ninlil_mfdt_v1_host_bind_t *bind,
    const ninlil_mfdt_v1_wire_view_t *wire,
    ninlil_mfdt_v1_response_t *response,
    uint8_t *slot_out);

int ninlil_mfdt_v1_host_pump_control(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot);

int ninlil_mfdt_v1_host_schedule_one_chunk(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t *selected_slot_out);

/* Borrowed until the next Host mutation; ownership remains with Host. */
int ninlil_mfdt_v1_host_peek_outbound_ncl1(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t **out,
    size_t *out_len);

int ninlil_mfdt_v1_host_take_outbound_ncl1(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    uint8_t *out,
    size_t cap,
    size_t *out_len);

int ninlil_mfdt_v1_host_tick(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint64_t now_ms);

int ninlil_mfdt_v1_host_observe_time(
    ninlil_mfdt_v1_host_owner_t *owner,
    const uint8_t local_clock_epoch[16],
    uint64_t now_ms,
    uint8_t *epoch_changed_out);

int ninlil_mfdt_v1_host_gc(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint64_t now_ms);

int ninlil_mfdt_v1_host_receiver_publication_view(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t **content_out,
    uint32_t *content_len_out,
    uint8_t publication_token_out[16],
    uint64_t *acceptance_generation_out);

int ninlil_mfdt_v1_host_receiver_commit_publication(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    const uint8_t publication_token[16],
    const uint8_t publication_evidence_digest[32]);

int ninlil_mfdt_v1_host_finish_terminal(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot);

int ninlil_mfdt_v1_host_snapshot(
    const ninlil_mfdt_v1_host_owner_t *owner,
    ninlil_mfdt_v1_host_header_snapshot_t *header_out,
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots_out[NINLIL_MFDT_V1_HOST_SLOT_COUNT]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_HOST_COORDINATOR_H */
