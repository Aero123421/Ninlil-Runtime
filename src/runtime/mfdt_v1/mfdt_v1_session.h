/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private MFDT session negotiation + NCL1 DATA carrier demux.
 *
 * MFN1 is deliberately independent from the Accepted HELLO
 * selected_control_version domain.  The base control session remains version
 * 1 or 2; MFDT admission becomes version 1 only after the bound MFN1
 * OFFER/ACCEPT revision-2 transcript succeeds.
 */
#ifndef NINLIL_MFDT_V1_SESSION_H
#define NINLIL_MFDT_V1_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "mfdt_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ninlil_mfdt_v1_spine_ctx;

#define NINLIL_MFDT_V1_NEGOTIATE_OFFER   ((uint8_t)0x34u)
#define NINLIL_MFDT_V1_NEGOTIATE_ACCEPT  ((uint8_t)0x35u)
#define NINLIL_MFDT_V1_NEGOTIATE_OFFER_BODY_BYTES  ((uint16_t)112u)
#define NINLIL_MFDT_V1_NEGOTIATE_ACCEPT_BODY_BYTES ((uint16_t)160u)
#define NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES \
    ((size_t)(26u + NINLIL_MFDT_V1_NEGOTIATE_ACCEPT_BODY_BYTES))

#define NINLIL_MFDT_V1_CAP_TRANSFER  ((uint8_t)0x01u)
#define NINLIL_MFDT_V1_CAP_NCL1_DATA ((uint8_t)0x02u)
#define NINLIL_MFDT_V1_CAP_REQUIRED \
    ((uint8_t)(NINLIL_MFDT_V1_CAP_TRANSFER | NINLIL_MFDT_V1_CAP_NCL1_DATA))
#define NINLIL_MFDT_V1_CARRIER_NCL1_DATA ((uint8_t)0x01u)

#define NINLIL_MFDT_V1_SESSION_COLD     ((uint8_t)0u)
#define NINLIL_MFDT_V1_SESSION_BOUND    ((uint8_t)1u)
#define NINLIL_MFDT_V1_SESSION_ADMITTED ((uint8_t)2u)
#define NINLIL_MFDT_V1_SESSION_FENCED   ((uint8_t)3u)

typedef struct ninlil_mfdt_v1_session {
    uint8_t policy_on;
    uint8_t capability;
    uint8_t host_mode;
    uint8_t state;
    uint16_t base_control_version; /* Accepted HELLO value: exact 1 or 2. */
    uint16_t mfdt_admission_version; /* 0 until MFN1, then exact 2. */
    uint32_t session_generation;
    uint64_t session_cookie;
    uint8_t local_endpoint_id[16];
    uint8_t peer_endpoint_id[16];
    uint8_t local_offer_nonce[16];
    uint8_t peer_offer_nonce[16];
    uint8_t responder_nonce[16];
    uint8_t local_offer_digest[32];
    uint8_t peer_offer_digest[32];
    uint8_t transcript_digest[32];
    uint8_t cached_accept_body[NINLIL_MFDT_V1_NEGOTIATE_ACCEPT_BODY_BYTES];
    uint32_t local_offer_request_id;
    uint32_t peer_offer_request_id;
    uint16_t cached_accept_body_len;
    uint8_t local_offer_sent;
    uint8_t peer_offer_accepted;
    uint8_t negotiated;
    uint8_t ncl1_data_carrier_ok; /* NCG1 DATA mapping admitted */
    uint8_t selected_max_active;
} ninlil_mfdt_v1_session_t;

void ninlil_mfdt_v1_session_init(ninlil_mfdt_v1_session_t *s, uint8_t policy_on,
                                 uint8_t capability);

/*
 * Bind MFDT negotiation to one already-active Accepted control session.
 * base_control_version is exact 1 or 2.  IDs and generation/cookie are
 * non-zero.  Rebinding clears every prior transcript and admission.
 */
int ninlil_mfdt_v1_session_bind(
    ninlil_mfdt_v1_session_t *s, uint16_t base_control_version,
    uint32_t session_generation, uint64_t session_cookie, uint8_t host_mode,
    const uint8_t local_endpoint_id[16], const uint8_t peer_endpoint_id[16]);

/*
 * Build an MFN1 OFFER carried by NCL1 DATA.  request_nonce must be a
 * caller-supplied, non-zero CSPRNG value.  A duplicate call must use the same
 * request_id and nonce; a conflicting second offer fences the session.
 */
int ninlil_mfdt_v1_session_build_offer(
    ninlil_mfdt_v1_session_t *s, uint32_t request_id,
    const uint8_t request_nonce[16], uint8_t *wire_out, size_t wire_cap,
    size_t *wire_len_out);

/*
 * Validate a peer MFN1 OFFER and emit the correlated ACCEPT.  responder_nonce
 * is required only for the first valid OFFER.  An exact duplicate returns the
 * cached ACCEPT; a conflicting OFFER fences the session.
 */
int ninlil_mfdt_v1_session_on_offer(
    ninlil_mfdt_v1_session_t *s, const uint8_t *offer_wire,
    size_t offer_wire_len, const uint8_t responder_nonce[16],
    uint8_t *accept_wire_out, size_t accept_wire_cap,
    size_t *accept_wire_len_out);

/* Validate the ACCEPT for the sole local OFFER and admit MFDT v1. */
int ninlil_mfdt_v1_session_on_accept(
    ninlil_mfdt_v1_session_t *s, const uint8_t *accept_wire,
    size_t accept_wire_len);

/* 1 if MFDT control may ride NCL1 DATA after a bound MFN1 transcript. */
int ninlil_mfdt_v1_session_carrier_ncl1_data_ok(
    const ninlil_mfdt_v1_session_t *s);

/*
 * Demux one NCG1 DATA payload: if MFDT type 0x36..0x43 and session admits,
 * forward to spine receive. Returns 1 if consumed, 0 if not MFDT, <0 error.
 */
int ninlil_mfdt_v1_session_on_ncg1_data(
    const ninlil_mfdt_v1_session_t *s,
    struct ninlil_mfdt_v1_spine_ctx *spine,
    const uint8_t *payload, size_t len);

/* Explicitly sync one caller-owned spine; session mutation has no side effect. */
int ninlil_mfdt_v1_session_apply_to_spine(
    const ninlil_mfdt_v1_session_t *s,
    struct ninlil_mfdt_v1_spine_ctx *spine);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_SESSION_H */
