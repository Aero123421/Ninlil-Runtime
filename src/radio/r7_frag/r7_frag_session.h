/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_R7_FRAG_SESSION_H
#define NINLIL_R7_FRAG_SESSION_H

/*
 * R7 private NRW1 LINK/FRAG integrated session candidate.
 *
 * TX plan -> E2E seal (START/CONT) -> outer DATA seal (hop DATA lane) ->
 * LINK retry + LINK_ACK (hop ACK lane) -> RX open/replay -> reassembly ->
 * SHA-256 content digest via approved provider -> exactly-once publication.
 *
 * Uses r7_crypto_* only. wire_profile_id=0x11. Not installed/HIL/public.
 *
 * Contract boundary (do not conflate with MFDT):
 *   - Reassembly slots, tombstones, and TX LINK/E2E volatile restart are
 *     Link/NRW1 hop+E2E contracts (docs/30). TOMBSTONE_VOLATILE_ON_RESTART:
 *     process restart discards volatile reasm/tombs; no resume claim.
 *   - Multi-frame durable custody (MFDT / U6) is a separate durable transfer
 *     authority. This session does NOT claim durable end-to-end custody,
 *     crash-atomic exactly-once application delivery, or MFDT completeness.
 */

#include "r7_crypto_provider.h"
#include "r7_frag.h"
#include "r7_frag_ack_ledger.h"
#include "r7_frag_state.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "r7_frag_profile.h"

/*
 * Test/crash durable simulator embed (NOT production N6).
 * Host lab/session tests: default ON.
 * ESP ENDPOINT / production-claim builds: set
 *   NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE=0
 * so sizeof(session) excludes ~43KiB durable+cu_ws and no production path
 * can mistake the simulator for real N6 counters.
 */
#ifndef NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
#define NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE 1
#endif

#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
#include "r7_frag_durable.h"
#endif

#define NINLIL_R7_FRAG_SESS_OK ((int32_t)0)
#define NINLIL_R7_FRAG_SESS_INVALID ((int32_t)1)
#define NINLIL_R7_FRAG_SESS_STRUCT ((int32_t)2)
#define NINLIL_R7_FRAG_SESS_RESOURCE ((int32_t)3)
#define NINLIL_R7_FRAG_SESS_REPLAY ((int32_t)4)
#define NINLIL_R7_FRAG_SESS_AUTH ((int32_t)5)
#define NINLIL_R7_FRAG_SESS_FENCED ((int32_t)6)
#define NINLIL_R7_FRAG_SESS_DURABLE ((int32_t)7)
#define NINLIL_R7_FRAG_SESS_NO_PUB ((int32_t)8)
#define NINLIL_R7_FRAG_SESS_DONE ((int32_t)9)
#define NINLIL_R7_FRAG_SESS_RETRY ((int32_t)10)
#define NINLIL_R7_FRAG_SESS_INTERNAL ((int32_t)11)

#define NINLIL_R7_FRAG_SESS_LANES ((size_t)8u)
#define NINLIL_R7_FRAG_SESS_MAX_FRAGS ((size_t)13u)
#define NINLIL_R7_FRAG_SESS_FRAME_MAX ((size_t)255u)

typedef struct ninlil_r7_frag_sess_keys {
    uint8_t e2e_key16[16];
    uint8_t e2e_iv12[12];
    uint8_t hop_data_key16[16];
    uint8_t hop_data_iv12[12];
    uint8_t hop_ack_key16[16];
    uint8_t hop_ack_iv12[12];
    /* Reverse hop for LINK_ACK generation (receiver ACK lane TX). */
    uint8_t rev_hop_ack_key16[16];
    uint8_t rev_hop_ack_iv12[12];
    /* Reverse E2E for FRAG_ACK (optional seal). */
    uint8_t rev_e2e_key16[16];
    uint8_t rev_e2e_iv12[12];
} ninlil_r7_frag_sess_keys;

typedef struct ninlil_r7_frag_sess_lane {
    uint8_t in_use;
    uint8_t kind; /* NINLIL_R7_FRAG_LANE_* */
    uint32_t context_id;
    uint64_t key_generation;
    uint64_t tx_next;
    uint64_t tx_limit;
    uint64_t rx_boot_floor;
    uint64_t rx_highest;
    uint64_t rx_bitmap;
    uint64_t rx_accept_through;
    uint8_t fenced;
} ninlil_r7_frag_sess_lane;

/* Sender fragment transfer (volatile group + durable counter burns). */
typedef struct ninlil_r7_frag_sess_tx_frag {
    uint8_t in_use;
    uint8_t complete;
    uint32_t e2e_context_id;
    uint64_t key_generation;
    uint64_t transfer_handle;
    uint8_t transfer_id[16];
    ninlil_r7_frag_state_plan plan;
    uint8_t content_digest[32];
    uint8_t fingerprint[32];
    /* Sealed E2E blobs per fragment for LINK retry (bit-identical). */
    uint16_t e2e_len[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint8_t e2e_blob[NINLIL_R7_FRAG_SESS_MAX_FRAGS][220];
    uint64_t e2e_counter[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    /* Per-fragment LINK group state */
    uint8_t hop_attempts[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint8_t frag_acked[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint64_t last_hop_counter[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint64_t eligible_at[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint16_t last_outer_len[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint8_t last_outer[NINLIL_R7_FRAG_SESS_MAX_FRAGS][255];
    uint16_t bitmap_from_frag_ack;
    /* Per-fragment E2E prep burns (≤4) and outer attempt accounting (≤16). */
    uint8_t e2e_prep_burns[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint8_t outer_attempts[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint64_t frag_ack_deadline[NINLIL_R7_FRAG_SESS_MAX_FRAGS];
    uint64_t sender_absolute_deadline;
    uint64_t transfer_start_mono;
} ninlil_r7_frag_sess_tx_frag;

typedef struct ninlil_r7_frag_sess {
    const ninlil_r7_crypto_provider *provider;
    ninlil_r7_frag_sess_keys keys;
#if NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE
    /*
     * Test durable simulator only (SEMANTIC: R7_FRAG_TEST_DURABLE_SIMULATOR_NOT_N6).
     * Not production N6. Not MFDT. CU workspace is object storage pointed by
     * durable.cu_ws after init. Omitted on ESP ENDPOINT builds.
     */
    ninlil_r7_frag_dur_store durable;
    ninlil_r7_frag_dur_cu_workspace cu_ws;
#endif
    ninlil_r7_frag_state_engine reasm;
    ninlil_r7_frag_sess_lane lanes[NINLIL_R7_FRAG_SESS_LANES];
    ninlil_r7_frag_sess_tx_frag tx;
    /*
     * Receiver FRAG_ACK reverse-burn ledger (docs/30 §15.3.7).
     * Identity-keyed; not on tx (sender) path. Shared semantics with production.
     */
    ninlil_r7_frag_ack_ledger_t ack_ledger;
    uint64_t now_mono;
    uint32_t hop_data_context_id;
    uint32_t hop_ack_context_id; /* reverse ACK-lane context for LINK_ACK RX */
    uint32_t e2e_context_id;
    uint32_t rev_e2e_context_id;
    uint64_t key_generation;
    uint32_t acked_hop_data_context_id; /* for LINK_ACK body */
    uint8_t ack_requested_default;
    uint32_t publish_count;
} ninlil_r7_frag_sess;

void ninlil_r7_frag_sess_init(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_frag_sess_keys *keys);

void ninlil_r7_frag_sess_zeroize(ninlil_r7_frag_sess *s);
void ninlil_r7_frag_sess_set_now(ninlil_r7_frag_sess *s, uint64_t now);

/* Install hop DATA/ACK and E2E lanes (local TX/RX mirror + durable initial). */
int32_t ninlil_r7_frag_sess_install_lane(
    ninlil_r7_frag_sess *s,
    uint8_t kind,
    uint32_t context_id,
    uint64_t key_generation);

/*
 * Sender: admit payload, plan, SHA-256 content digest + START fingerprint,
 * seal all E2E fragments with fresh counters, seal first outer for frag 0.
 * out_frame is first air candidate for fragment 0.
 */
int32_t ninlil_r7_frag_sess_tx_begin(
    ninlil_r7_frag_sess *s,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t transfer_id[16],
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len,
    uint16_t *out_frag_index);

/* Produce outer for fragment frag_index (0..fc-1), LINK retry or next frag. */
int32_t ninlil_r7_frag_sess_tx_air(
    ninlil_r7_frag_sess *s,
    uint16_t frag_index,
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len);

/*
 * E2E fragment retry (docs/30 FRAG_E2E_RETRY_FRESH_SEAL): same immutable
 * transfer fields, fresh e2e_counter + seal, new LINK group (hop attempts 0).
 * Requires e2e_prep_burns[frag] < 4 and original payload retained by caller.
 */
int32_t ninlil_r7_frag_sess_tx_e2e_retry(
    ninlil_r7_frag_sess *s,
    uint16_t frag_index,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len);

/* Note successful air (consume+edge). Starts ACK timer if ack_requested. */
int32_t ninlil_r7_frag_sess_tx_note_air(
    ninlil_r7_frag_sess *s,
    uint16_t frag_index,
    uint64_t hop_counter);

/* RX outer DATA frame: open hop DATA, replay, open E2E, reasm, maybe finalize. */
int32_t ninlil_r7_frag_sess_rx_data(
    ninlil_r7_frag_sess *s,
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_frag_state_ack_intent *out_frag_intent,
    uint8_t *out_link_ack_frame,
    size_t link_ack_cap,
    size_t *out_link_ack_len);

/* RX LINK_ACK outer: open ACK lane, apply to pending hop counters. */
int32_t ninlil_r7_frag_sess_rx_link_ack(
    ninlil_r7_frag_sess *s,
    const uint8_t *frame,
    size_t frame_len);

/* Seal FRAG_ACK E2E+outer from intent (receiver reverse E2E). */
int32_t ninlil_r7_frag_sess_tx_frag_ack(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_frag_state_ack_intent *intent,
    uint8_t *out_frame,
    size_t out_cap,
    size_t *out_len);

/* Sender applies FRAG_ACK after RX path open (caller may pass intent body). */
int32_t ninlil_r7_frag_sess_tx_apply_frag_ack(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_frag_ack_body *body);

int32_t ninlil_r7_frag_sess_take_publication(
    ninlil_r7_frag_sess *s,
    uint8_t *out_payload,
    size_t out_cap,
    size_t *out_len);

/* Tick timeouts on reassembly. */
int32_t ninlil_r7_frag_sess_tick(ninlil_r7_frag_sess *s, uint64_t now);

/*
 * Crash/restart: durable lanes only; reassembly/tombstones/tx volatile.
 * After decode, no publication may be manufactured from empty reasm.
 */
int32_t ninlil_r7_frag_sess_restart_encode(
    const ninlil_r7_frag_sess *s,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);

int32_t ninlil_r7_frag_sess_restart_decode(
    ninlil_r7_frag_sess *s,
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_frag_sess_keys *keys,
    const uint8_t *in,
    size_t in_len);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_SESSION_H */
