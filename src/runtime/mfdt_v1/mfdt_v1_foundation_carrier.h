/* SPDX-License-Identifier: Apache-2.0
 * Instance-bound Foundation bearer carrier for private MFDT v1.
 *
 * This is a private/default-OFF integration surface.  It maps one NCL1 DATA
 * frame to one Foundation TRANSFER_RESERVED Application message and therefore
 * lets the normal Fabric path-selection, authority, TxPermit, custody, and
 * packet-link machinery carry MFN1/MFDT traffic.
 *
 * It owns no global state and never installs a public Service.  A caller that
 * shares a bearer with the Portable Runtime should use build/accept as its
 * demux seam.  open/tx/rx are the exclusive-handle convenience path used by a
 * dedicated owner-plane worker.
 */
#ifndef NINLIL_MFDT_V1_FOUNDATION_CARRIER_H
#define NINLIL_MFDT_V1_FOUNDATION_CARRIER_H

#include "mfdt_v1_session.h"

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_MFDT_V1_CARRIER_DEADLINE_MS_DEFAULT ((uint64_t)60000ull)

typedef struct ninlil_mfdt_v1_foundation_carrier_config {
    const ninlil_bearer_ops_t *bearer;
    const ninlil_clock_ops_t *clock;
    const ninlil_tx_gate_ops_t *tx_gate;
    ninlil_role_t role;
    ninlil_party_t source;
    ninlil_concrete_target_t target;
    ninlil_mfdt_v1_session_t *session;
    uint64_t deadline_window_ms;
} ninlil_mfdt_v1_foundation_carrier_config_t;

typedef struct ninlil_mfdt_v1_foundation_carrier {
    ninlil_mfdt_v1_foundation_carrier_config_t config;
    ninlil_service_identity_t service;
    ninlil_bearer_handle_t bearer_handle;
    uint8_t initialized;
    uint8_t opened;
} ninlil_mfdt_v1_foundation_carrier_t;

/* Canonical private owner-plane service used by policy/authority setup. */
int ninlil_mfdt_v1_foundation_carrier_service_identity(
    ninlil_service_identity_t *out_service);

int ninlil_mfdt_v1_foundation_carrier_init(
    ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const ninlil_mfdt_v1_foundation_carrier_config_t *config);

int ninlil_mfdt_v1_foundation_carrier_open(
    ninlil_mfdt_v1_foundation_carrier_t *carrier);

void ninlil_mfdt_v1_foundation_carrier_close(
    ninlil_mfdt_v1_foundation_carrier_t *carrier);

/*
 * Demux-friendly primitives. build_message borrows frame in out_message.
 * accept_message copies the admitted NCL1 payload into caller storage.
 */
int ninlil_mfdt_v1_foundation_carrier_build_message(
    ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_time_sample_t *now,
    ninlil_bearer_message_t *out_message);

int ninlil_mfdt_v1_foundation_carrier_accept_message(
    const ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const ninlil_bearer_message_t *message,
    uint8_t *frame_out,
    size_t frame_cap,
    size_t *frame_len_out);

/* mfdt_v1_bearer_worker callback-compatible exclusive-handle path. */
int ninlil_mfdt_v1_foundation_carrier_tx(
    void *user, const uint8_t *frame, size_t frame_len);

/*
 * Runtime-owned-handle variant.  It applies the same canonical envelope,
 * clock, TxPermit, and send-result rules as the exclusive-handle callback,
 * but never opens or closes the supplied Bearer handle.
 */
int ninlil_mfdt_v1_foundation_carrier_tx_shared(
    ninlil_mfdt_v1_foundation_carrier_t *carrier,
    ninlil_bearer_handle_t bearer_handle,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_time_sample_t *now,
    uint32_t *send_attempted_out,
    ninlil_bearer_status_t *bearer_status_out);

int ninlil_mfdt_v1_foundation_carrier_rx(
    void *user, uint8_t *frame_out, size_t frame_cap, size_t *frame_len_out);

uint64_t ninlil_mfdt_v1_foundation_carrier_now(void *user);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_FOUNDATION_CARRIER_H */
