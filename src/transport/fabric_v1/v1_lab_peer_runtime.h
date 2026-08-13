/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_PEER_RUNTIME_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_PEER_RUNTIME_H

/*
 * Private fixed V1 LAB endpoint composition.
 *
 * This is deliberately a closed profile, not an installed role/plugin API:
 * one adopted radio pair, at most two flows, and at most three Services.
 */

#include "v1_lab_board_owner.h"

#include "ninlil/composition_v1.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_PEER_RUNTIME_OBJECT_BYTES ((size_t)16384u)

typedef uint32_t ninlil_v1_lab_peer_runtime_status_t;
#define NINLIL_V1_LAB_PEER_RUNTIME_OK \
    ((ninlil_v1_lab_peer_runtime_status_t)0u)
#define NINLIL_V1_LAB_PEER_RUNTIME_WAITING \
    ((ninlil_v1_lab_peer_runtime_status_t)1u)
#define NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT \
    ((ninlil_v1_lab_peer_runtime_status_t)2u)
#define NINLIL_V1_LAB_PEER_RUNTIME_BINDING \
    ((ninlil_v1_lab_peer_runtime_status_t)3u)
#define NINLIL_V1_LAB_PEER_RUNTIME_PLATFORM \
    ((ninlil_v1_lab_peer_runtime_status_t)4u)
#define NINLIL_V1_LAB_PEER_RUNTIME_COMPOSITION \
    ((ninlil_v1_lab_peer_runtime_status_t)5u)
#define NINLIL_V1_LAB_PEER_RUNTIME_SERVICE \
    ((ninlil_v1_lab_peer_runtime_status_t)6u)
#define NINLIL_V1_LAB_PEER_RUNTIME_FABRIC \
    ((ninlil_v1_lab_peer_runtime_status_t)7u)
#define NINLIL_V1_LAB_PEER_RUNTIME_FENCED \
    ((ninlil_v1_lab_peer_runtime_status_t)8u)
#define NINLIL_V1_LAB_PEER_RUNTIME_CLOSING \
    ((ninlil_v1_lab_peer_runtime_status_t)9u)
#define NINLIL_V1_LAB_PEER_RUNTIME_CLOSED \
    ((ninlil_v1_lab_peer_runtime_status_t)10u)

typedef union ninlil_v1_lab_peer_runtime {
    uint64_t alignment;
    uint8_t opaque[NINLIL_V1_LAB_PEER_RUNTIME_OBJECT_BYTES];
} ninlil_v1_lab_peer_runtime_t;

typedef struct ninlil_v1_lab_peer_runtime_config {
    const ninlil_r7_crypto_provider *crypto;
    /* Caller supplies only live allocator/execution/clock/entropy/storage. */
    /* Composition supplies Bearer; this fixed owner supplies TxGate/origin. */
    const ninlil_platform_ops_t *platform_template;
    void *composition_workspace;
    uint32_t composition_workspace_bytes;
    /* One application-neutral dispatcher handles every DesiredState row. */
    const ninlil_service_callbacks_t *desired_callbacks;
} ninlil_v1_lab_peer_runtime_config_t;

/* State and workspace must be zeroed and remain caller-owned through close. */
ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_prepare(
    ninlil_v1_lab_peer_runtime_t *runtime,
    const ninlil_v1_lab_peer_runtime_config_t *config);

/* Exact callback shape for ninlil_v1_lab_board_owner_config_t::pair_ready. */
int ninlil_v1_lab_peer_runtime_pair_ready(
    void *user,
    ninlil_v1_lab_radio_packet_link_t *radio,
    uint8_t pair_slot,
    const uint8_t *encoded_binding,
    size_t encoded_length);

/* Activates once after adoption, then advances one bounded Composition step. */
ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_step(
    ninlil_v1_lab_peer_runtime_t *runtime);

/* Borrow one active Service by its exact binding slot. */
ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_service(
    ninlil_v1_lab_peer_runtime_t *runtime,
    uint8_t service_slot,
    ninlil_service_t **out_service);

/* Borrow the active Runtime for existing public query/list operations. */
ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_handle(
    ninlil_v1_lab_peer_runtime_t *runtime,
    ninlil_runtime_t **out_runtime);

ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_close_begin(
    ninlil_v1_lab_peer_runtime_t *runtime);

/* out_done becomes one only after Composition destroy consumed all borrows. */
ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_close_step(
    ninlil_v1_lab_peer_runtime_t *runtime,
    uint32_t *out_done);

/* Valid only after close completed, or after prepare before pair adoption. */
ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_clear(
    ninlil_v1_lab_peer_runtime_t *runtime);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_PEER_RUNTIME_H */
