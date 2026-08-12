/* SPDX-License-Identifier: Apache-2.0 */
/*
 *
 * Instance-local Runtime owner for the private ADR-0021 MFDT candidate.
 *
 * This header is source-only, default-OFF, not installed, and not public ABI.
 * The owner uses the Runtime's copied Storage Port vtable, but opens the
 * deterministic ADR-0021 MFDT sidecar namespace on a distinct handle. The
 * sidecar is bound to the caller's exact Foundation namespace by NMS1 and
 * never falls back to the process-global legacy spine.
 */
#ifndef NINLIL_MFDT_V1_RUNTIME_OWNER_H
#define NINLIL_MFDT_V1_RUNTIME_OWNER_H

#include "mfdt_v1.h"
#include "mfdt_v1_host_coordinator.h"
#include "mfdt_v1_session.h"

#include <ninlil/runtime.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_rt_mfdt_v1_runtime_owner
    ninlil_rt_mfdt_v1_runtime_owner_t;

typedef struct ninlil_rt_mfdt_v1_runtime_config {
    uint32_t struct_size;
    uint32_t enabled;
    uint32_t session_generation;
    uint32_t reserved_zero;
    uint64_t session_cookie;
} ninlil_rt_mfdt_v1_runtime_config_t;

typedef struct ninlil_rt_mfdt_v1_runtime_snapshot {
    uint32_t struct_size;
    uint32_t enabled;
    uint32_t ready;
    uint32_t exact_slot_count;
    uint32_t active_count;
    uint32_t recovered;
    uint32_t inventory_uncertain;
    uint32_t reserved_zero;
} ninlil_rt_mfdt_v1_runtime_snapshot_t;

/*
 * Private opt-in. A normal Runtime remains MFDT-OFF and allocates no MFDT
 * owner. Enabling is owner-thread-only and creates one owner bound to that
 * Runtime instance. This late opt-in remains a test-only integration seam;
 * production composition must open/recover the sidecar before the Bearer.
 */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_configure(
    ninlil_runtime_t *runtime,
    const ninlil_rt_mfdt_v1_runtime_config_t *config);

int ninlil_rt_mfdt_v1_runtime_should_use(
    const ninlil_runtime_t *runtime,
    uint32_t logical_payload_length);

/* Bind one real, already-ADMITTED MFN1 session to this Runtime instance. */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_bind_session(
    ninlil_runtime_t *runtime,
    const ninlil_mfdt_v1_session_t *session);

ninlil_status_t ninlil_rt_mfdt_v1_runtime_snapshot(
    const ninlil_runtime_t *runtime,
    ninlil_rt_mfdt_v1_runtime_snapshot_t *out);

/* Deterministic private correlation shared by Foundation NTS3 and NM3S. */
void ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
    const ninlil_bearer_message_t *application,
    uint32_t target_ordinal,
    uint8_t transfer_id_out[16]);

/* Exact source-private ADR-0021 Application-evidence digest preimage. */
ninlil_status_t ninlil_rt_mfdt_v1_application_evidence_digest(
    const uint8_t publication_token[16],
    const ninlil_id128_t *origin_transaction_id,
    const ninlil_id128_t *original_attempt_id,
    uint32_t target_ordinal,
    ninlil_evidence_stage_t evidence_stage,
    ninlil_bytes_view_t evidence,
    uint8_t digest_out[32]);

/*
 * Internal sender admission primitive used by the future ordinary
 * Runtime scheduler. `application` is the original application envelope;
 * NCL1 is carried separately so application identity is not discarded.
 */
int ninlil_rt_mfdt_v1_runtime_sender_open(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *application,
    const uint8_t *content,
    uint32_t content_length,
    uint32_t target_ordinal,
    const uint8_t transfer_id[16],
    uint8_t *slot_out);

/* Exact post-pre-arm compensation; source-private and owner-thread-only. */
int ninlil_rt_mfdt_v1_runtime_sender_disarm(
    ninlil_runtime_t *runtime,
    uint8_t slot,
    const uint8_t transfer_id[16]);

/*
 * Shared-Bearer ingress demux for ordinary runtime_step. A message addressed
 * to the reserved private MFDT Service is always claimed, including malformed
 * input, so it can never fall through to an Application Service. Fresh OPEN
 * may create a receiver slot; every later frame is routed through its pinned
 * instance-local binding before Host ownership is advanced.
 */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_ingress(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *now,
    uint32_t *claimed_out,
    uint32_t *durable_transition_out);

/* Private upper-handoff inspection seam; it does not commit publication. */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_receiver_publication_view(
    ninlil_runtime_t *runtime,
    const uint8_t transfer_id[16],
    const uint8_t **content_out,
    uint32_t *content_length_out,
    uint8_t publication_token_out[16],
    uint64_t *acceptance_generation_out);

/* Internal runtime_step seam: READY NM3R -> one inbound Foundation FULL. */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_reconcile_ready(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *now,
    uint32_t transition_budget,
    uint32_t *transitions_consumed_out,
    uint32_t *work_remaining_out);

/*
 * Borrow one complete verified receiver object for the existing Foundation
 * callback. The publication token remains private and is never returned.
 */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_borrow_receiver_payload(
    ninlil_runtime_t *runtime,
    const uint8_t transfer_id[16],
    uint32_t target_ordinal,
    const ninlil_id128_t *foundation_transaction_id,
    const uint8_t **content_out,
    uint32_t *content_length_out);

/* Exact source-private gate for the existing Foundation Receipt reducer. */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_receiver_handoff_complete(
    ninlil_runtime_t *runtime,
    const uint8_t transfer_id[16],
    uint32_t target_ordinal,
    const ninlil_id128_t *foundation_transaction_id,
    uint32_t *complete_out);

/*
 * Called only from Runtime teardown. It performs no Storage mutation and is
 * safe after a failed create path has already closed the provider handles.
 */
void ninlil_rt_mfdt_v1_runtime_owner_release(
    ninlil_runtime_t *runtime);

/*
 * Ordinary runtime_step integration seam. It advances owner time and sends
 * at most the supplied budget through the Runtime-owned Bearer handle. It
 * never fabricates the original single-frame Application or a Receipt.
 */
ninlil_status_t ninlil_rt_mfdt_v1_runtime_step_maintenance(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *now,
    uint32_t send_budget,
    uint32_t *bearer_sends_out,
    uint32_t *work_remaining_out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_RUNTIME_OWNER_H */
