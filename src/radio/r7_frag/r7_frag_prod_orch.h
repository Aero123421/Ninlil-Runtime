#ifndef NINLIL_R7_FRAG_PROD_ORCH_H
#define NINLIL_R7_FRAG_PROD_ORCH_H

/*
 * Production-path private L1 orchestrator for NRW1 0x11:
 *   N6 durable counters + r7_wire AEAD + R2 pcp_issue + R1 transmit_with_permit
 *   + L1 issued-FIFO ledger (max 2 concurrent) + §15.3.8 cleanup classes.
 * Fail-closed on unbound authority / clock uncertain / epoch mismatch.
 * Not public ABI. Not installed. Not HIL/RF/legal.
 *
 * Link-layer FRAG reassembly / tombstones / TX volatile restart are NRW1
 * hop/E2E contracts only. They do NOT claim multi-frame durable custody
 * (MFDT) end-to-end transfer completeness.
 */

#include "n6_context_store.h"
#include "pcp_authority.h"
#include "r7_crypto_provider.h"
#include "r7_frag.h"
#include "r7_frag_ack_ledger.h"
#include "r7_frag_adapters.h"
#include "r7_frag_checked_issue.h"
#include "r7_frag_state.h"
#include "radio_hal.h"
/* Intentionally no r7_frag_session.h: production orch must not pull lab
 * session/test-durable BSS into ESP component archives. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_R7_FRAG_PROD_OK ((int32_t)0)
#define NINLIL_R7_FRAG_PROD_INVALID ((int32_t)1)
#define NINLIL_R7_FRAG_PROD_UNBOUND ((int32_t)2)
#define NINLIL_R7_FRAG_PROD_N6 ((int32_t)3)
#define NINLIL_R7_FRAG_PROD_WIRE ((int32_t)4)
#define NINLIL_R7_FRAG_PROD_R2 ((int32_t)5)
#define NINLIL_R7_FRAG_PROD_R1 ((int32_t)6)
#define NINLIL_R7_FRAG_PROD_CLEANUP ((int32_t)7)
#define NINLIL_R7_FRAG_PROD_CLOCK ((int32_t)8)
#define NINLIL_R7_FRAG_PROD_ADMISSION ((int32_t)9)
#define NINLIL_R7_FRAG_PROD_LEDGER ((int32_t)10)
#define NINLIL_R7_FRAG_PROD_MATRIX ((int32_t)11)
#define NINLIL_R7_FRAG_PROD_RESOURCE ((int32_t)12)

/* §15.3.8 disposition class (host proof). */
#define NINLIL_R7_FRAG_CLN_NONE ((uint8_t)0u)
#define NINLIL_R7_FRAG_CLN_UNISSUED_DROP ((uint8_t)1u)
#define NINLIL_R7_FRAG_CLN_ISSUED_DRAIN ((uint8_t)2u)
#define NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN ((uint8_t)3u)
#define NINLIL_R7_FRAG_CLN_EDGE_STALE ((uint8_t)4u)
#define NINLIL_R7_FRAG_CLN_OK_COMPLETE ((uint8_t)5u)
#define NINLIL_R7_FRAG_CLN_CLOCK_DROP ((uint8_t)6u)
#define NINLIL_R7_FRAG_CLN_EPOCH_DROP ((uint8_t)7u)
/* Issued, coordinator-owned, not yet TX (queued or R1-held same-object). */
#define NINLIL_R7_FRAG_CLN_ISSUED_HELD ((uint8_t)8u)

/* L1 issued FIFO capacity for private matrix (≤ R2 global 8; pin 2). */
#define NINLIL_R7_FRAG_L1_ISSUED_CAP ((size_t)2u)

/* Matrix catalog (closed private host proof). */
#define NINLIL_R7_FRAG_MX_CARRIER_LORA ((uint8_t)1u)
#define NINLIL_R7_FRAG_MX_CLASS_DATA ((uint8_t)1u)
#define NINLIL_R7_FRAG_MX_CLASS_ACK ((uint8_t)2u)
#define NINLIL_R7_FRAG_MX_ACTION_TX ((uint8_t)1u)
#define NINLIL_R7_FRAG_MX_ACTION_RX ((uint8_t)2u)
#define NINLIL_R7_FRAG_MX_PROFILE_0x11 ((uint8_t)0x11u)

typedef struct ninlil_r7_frag_prod_ledger_slot {
    uint8_t live;
    uint8_t cleanup_class;
    uint8_t edge_invoked;
    uint8_t consume_invoked;
    uint64_t permit_sequence;
    uint64_t owner_token;
    uint64_t candidate_token;
    size_t outer_len;
    uint8_t outer[255];
} ninlil_r7_frag_prod_ledger_slot_t;

typedef struct ninlil_r7_frag_prod_tx_result {
    uint8_t cleanup_class;
    uint64_t permit_sequence;
    uint8_t consume_invoked;
    uint8_t edge_invoked;
    uint8_t ledger_admitted;
    ninlil_radio_hal_status_t r1_status;
    ninlil_radio_hal_stage_t r1_stage;
    ninlil_radio_hal_reason_t r1_reason;
    ninlil_pcp_status_t r2_status;
    ninlil_pcp_stage_t r2_stage;
    ninlil_pcp_reason_t r2_reason;
    ninlil_n6_status_t n6_status;
    /* Typed checked-issue axes (docs/30 §15.3.2) when issue was attempted. */
    uint8_t issue_l1_class;
    uint8_t issue_business_mutation;
    uint8_t issue_txn_provenance;
    uint64_t hop_counter;
    uint64_t e2e_counter;
    size_t outer_len;
    uint8_t outer[255];
} ninlil_r7_frag_prod_tx_result_t;

/* Pending reverse LINK_ACK obligation after DATA RX with ack_requested. */
#define NINLIL_R7_FRAG_PROD_LINK_ACK_PENDING_CAP ((size_t)4u)

typedef struct ninlil_r7_frag_prod_link_ack_pending {
    uint8_t live;
    uint8_t prepared; /* sealed outer ready for issue */
    uint8_t issue_calls; /* ≤ NINLIL_R7_ISSUE_RETRY_MAX */
    uint8_t cleanup_class;
    uint32_t hop_ack_context_id;
    uint32_t acked_hop_data_context_id;
    uint64_t ack_base_counter;
    uint16_t ack_bitmap;
    uint64_t owner_token;
    uint64_t candidate_token;
    uint64_t issue_retry_at; /* +100ms issue backoff */
    size_t outer_len;
    uint8_t outer[NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN];
} ninlil_r7_frag_prod_link_ack_pending_t;

typedef struct ninlil_r7_frag_prod_rx_result {
    uint8_t body_applied;
    uint8_t hop_only_retransmit; /* 1 only for typed N6 REPLAY on E2E */
    uint8_t published;
    uint8_t e2e_type; /* SINGLE=1 START=2 CONT=3 ACK=4 */
    uint8_t ack_valid; /* 1 when FRAG_ACK body decoded into ack_body */
    uint8_t intent_valid; /* 1 when START/CONT produced ack_intent */
    uint8_t link_ack_pending_noted; /* 1 if DATA ack_requested enqueued pending */
    uint8_t outer_ack_requested; /* authenticated outer ack_requested bit */
    uint16_t frag_index;
    ninlil_n6_status_t n6_pre_st; /* last hop or e2e precheck status */
    ninlil_n6_reason_t n6_pre_reason; /* last_error.reason when set */
    ninlil_n6_status_t n6_admit_st;
    ninlil_r7_frag_state_status reasm_st;
    ninlil_r7_frag_ack_body ack_body; /* valid iff ack_valid */
    ninlil_r7_frag_state_ack_intent ack_intent; /* valid iff intent_valid */
    size_t app_len;
    uint8_t app[2048];
} ninlil_r7_frag_prod_rx_result_t;

/*
 * Caller-owned production multi-frame TX transfer object (docs/30).
 * Retains sealed E2E blobs for LINK hop retry (same E2E body).
 * Tracks outer/hop attempt caps, retry timers, FRAG_ACK bitmap, deadline.
 * Not test durable simulator. Not MFDT durable end-to-end custody claim.
 */
#define NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS ((size_t)13u)
/* L1W1 FRAME_READY detail0: sealed layer branch (§1.1.1.5). */
#define NINLIL_R7_FRAG_PROD_LAYER_E2E_BLOB ((uint8_t)1u)
#define NINLIL_R7_FRAG_PROD_LAYER_OUTER_FRAME ((uint8_t)2u)

typedef struct ninlil_r7_frag_prod_xfer {
    uint8_t live;
    uint8_t complete; /* terminal COMPLETE/ABORT from FRAG_ACK or all-acked */
    uint8_t aborted;
    uint8_t ack_requested_default; /* 0|1 default; per-air overrides */
    ninlil_r7_frag_state_plan plan;
    uint8_t transfer_id[16];
    uint64_t transfer_handle;
    uint32_t e2e_context_id;
    uint8_t content_digest[32];
    uint8_t fingerprint[32];
    /* Sealed E2E ownership (L1 post FRAME_READY E2E_BLOB). */
    uint16_t e2e_len[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint8_t e2e_blob[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS][220];
    uint64_t e2e_counter[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint8_t e2e_prep_burns[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS]; /* ≤4 */
    /* Per-fragment LINK/outer accounting. */
    uint8_t hop_attempts[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS]; /* ≤4 air */
    uint8_t outer_attempts[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS]; /* ≤16 */
    uint8_t frag_acked[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint64_t last_hop_counter[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint64_t eligible_at[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint16_t last_outer_len[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint8_t last_outer[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS][255];
    /* Immutable prepared LINK candidate (docs/30 §15.3): issue_calls≤8;
     * R1/R2 deny reuses outer without fresh hop burn. */
    uint8_t prepared_live[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint8_t prepared_ack_requested[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint8_t issue_calls[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    /* Immutable per-LINK-group deadline (start+15000) per fragment group. */
    uint64_t link_group_start_ms[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint64_t link_group_deadline_ms[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint8_t link_group_live[NINLIL_R7_FRAG_PROD_XFER_MAX_FRAGS];
    uint16_t bitmap_from_frag_ack;
    uint64_t sender_absolute_deadline;
    uint64_t transfer_start_mono;
    /* Owned copy of app payload (immutable after begin). */
    uint8_t payload_owned[NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX];
    size_t payload_len;
    uint8_t payload_owned_valid;
} ninlil_r7_frag_prod_xfer_t;

/*
 * Caller/instance-owned matrix scratch (not process-global, not stack).
 * Large outer/app buffers live here so run_matrix stays ≤4096 frame.
 * Single-owner non-reentrant per workspace: live=1 for call duration.
 * Storage is owned by the bind's Runtime/Cell agent (or test fixture).
 */
typedef struct ninlil_r7_frag_prod_matrix_ws {
    uint8_t live;
    uint8_t reserved0[7];
    ninlil_r7_frag_prod_tx_result_t tr;
    ninlil_r7_frag_prod_rx_result_t rr;
} ninlil_r7_frag_prod_matrix_ws_t;

/* Stamped by bind_reset / bind_reinit; required before bind_set_matrix_ws. */
#define NINLIL_R7_FRAG_PROD_BIND_MAGIC ((uint32_t)0x5237424Eu) /* R7BN */
#define NINLIL_R7_FRAG_PROD_BIND_VERSION ((uint16_t)1u)

typedef struct ninlil_r7_frag_prod_bind {
    /*
     * Lifecycle stamp. Written only by bind_reset / bind_reinit after a full
     * memset. Uninitialized stack objects must not be read: call reset first.
     */
    uint32_t bind_magic;
    uint16_t bind_version;
    uint16_t bind_reserved0;

    /* Production N6 (TX side OUTBOUND or RX side INBOUND as installed). */
    ninlil_n6_t *n6;
    ninlil_n6_handle_t hop_data_handle;
    ninlil_n6_handle_t hop_ack_handle;
    ninlil_n6_handle_t e2e_handle;
    /* Authority pins for installed handles (must match lease/ticket.context_id). */
    uint32_t hop_data_context_id;
    uint32_t hop_ack_context_id;
    uint32_t e2e_context_id_pin;

    /* Real R2 authority body. */
    ninlil_pcp_t *pcp;
    ninlil_pcp_live_profile_t live; /* L_core source for issue */
    uint8_t live_valid;

    /* Real R1 HAL (permit ops must be ninlil_pcp_permit_ops). */
    ninlil_radio_hal_t *hal;

    /* W1 crypto (OpenSSL3 host or portable). */
    const ninlil_r7_crypto_provider *crypto;

    /* Observation only — not authority. */
    ninlil_r7_frag_spy_t *spy;
    ninlil_r7_frag_l1w1_bus_t *bus;

    /*
     * R2-authoritative time (docs/30 §11.2.2–11.2.3) — CONTRACT v3.
     *
     * PUBLIC FIELDS ARE OBSERVATION ONLY. Authority is bind-embedded private
     * owner state (time_priv_*) with integrity MAC. mint/refresh use only
     * ninlil_r2_private_sample_authority_clock (closed request/result, typed
     * A/B/C/D, 16B epochs, watermark floors, three-axis mutation catalog).
     * No host_seed. No legacy issue_sample_pin for stamps.
     */
    uint64_t trusted_now_ms;
    uint64_t r2_now_ms;
    uint8_t r2_now_valid;
    uint8_t clock_trusted;
    uint8_t clock_uncertain;
    uint8_t clock_future_vs_expiry; /* 1 ⇒ not_before/expiry inverted */
    uint8_t clock_rollback;         /* 1 ⇒ sample < last_trusted */
    uint8_t time_from_r2;           /* 1 = last write from class-D/R2 sample */
    uint32_t time_owner_gen;        /* non-zero after mint; owner handle */
    uint32_t time_seal;             /* opaque observation; not mintable */
    ninlil_pcp_t *time_clock_pcp;   /* observation of bound clock source */
    uint64_t epoch_id_lo;           /* first 8B LE of clock_epoch_id (compat) */
    uint64_t expected_epoch_lo; /* 0 = no pin; else must match epoch_id_lo */
    /* L1 watermark / sample epoch (16B authority domain). */
    uint8_t clock_epoch_id[16];
    uint8_t watermark_epoch_id[16];
    uint8_t watermark_valid;
    uint64_t watermark_now_ms;
    uint8_t last_sample_typed_class; /* NINLIL_R2_SAMPLE_* */
    uint8_t last_sample_meta_mutation;
    uint8_t last_sample_txn_provenance;
    /*
     * Bind-embedded private owner (not process-global). Integrity MAC covers
     * private fields; public writes do not update MAC.
     */
    uint8_t time_priv_live;
    uint32_t time_priv_gen;
    uint32_t time_priv_mac;
    uint8_t time_priv_epoch[16];
    uint8_t time_priv_wm_epoch[16];
    uint8_t time_priv_wm_valid;
    uint64_t time_priv_wm_now_ms;
    uint64_t time_priv_now_ms;
    uint8_t time_priv_trusted;
    uint8_t time_priv_uncertain;
    uint8_t time_priv_rollback;
    uint8_t time_priv_future;
    uint8_t time_priv_from_r2;
    ninlil_pcp_t *time_priv_pcp;

    /* L1 issued FIFO / custody ledger. */
    ninlil_r7_frag_prod_ledger_slot_t ledger[NINLIL_R7_FRAG_L1_ISSUED_CAP];
    size_t ledger_count;
    uint64_t last_completed_seq;

    /*
     * Instance-owned matrix workspace pointer (caller storage).
     * Required non-NULL for run_matrix. Each Runtime/Cell agent binds its
     * own object so concurrent instances never share mutable scratch.
     */
    ninlil_r7_frag_prod_matrix_ws_t *matrix_ws;

    /*
     * Optional reassembly engine for production FRAG START/CONT RX.
     * Caller/instance-owned (not BSS-multiplied). NULL ⇒ RX admits SINGLE only.
     */
    ninlil_r7_frag_state_engine *reasm;
    uint64_t reasm_key_generation; /* binding pin; 0 reject on FRAG admit */

    /*
     * FRAG_ACK reverse-burn ledger (docs/30 §15.3.7). Caller/instance-owned.
     * Required non-NULL for prod_tx_frag_ack. Same module as session lab path.
     */
    ninlil_r7_frag_ack_ledger_t *ack_ledger;

    /*
     * Optional R5 issue registry (docs/30 §15.3.1). NULL ⇒ process-static.
     * Caller/instance-owned for isolation tests.
     */
    ninlil_r7_r5_issue_registry_t *issue_registry;

    /*
     * Reverse LINK_ACK closed-loop (docs/30 §11 / §15.3):
     * pending rows created only from RX DATA with ack_requested.
     * prepare seals hop-ACK outer; tx_link_ack issues only prepared rows
     * with issue_calls ≤ 8 and L1 FIFO cleanup.
     */
    ninlil_r7_frag_prod_link_ack_pending_t
        link_ack_pending[NINLIL_R7_FRAG_PROD_LINK_ACK_PENDING_CAP];

    /*
     * Same-object issued hold (docs/30 §15.3): coordinator-owned Permit +
     * sealed outer for R1 NOT_BEFORE/EXPIRED retry and non-head QUEUED wait.
     * Resume uses exact permit_sequence + outer_digest; never re-issues.
     */
    uint8_t held_tx_live;
    uint8_t held_tx_queued; /* 1 = admitted non-head; 0 = R1 time-hold */
    size_t held_tx_slot;
    uint64_t held_authority_token;
    uint64_t held_permit_sequence;
    uint32_t held_outer_len;
    uint8_t held_outer_digest[32];
    uint8_t held_outer[255];
    ninlil_radio_hal_permit_snapshot_t held_permit;

    /*
     * TERMINAL_PENDING (docs/30 §15.3.8): terminal FRAG_ACK ready while issued
     * work still live. Freeze commit until drain converges.
     */
    uint8_t terminal_pending;
    uint8_t terminal_status; /* COMPLETE/ABORT from FRAG_ACK */
    uint64_t terminal_transfer_handle;
    uint16_t terminal_frag_count;
    uint16_t terminal_bitmap;

    /*
     * FRAG_ACK CU seal identity (docs/30 §15.3.7): preserve counter/key/IV
     * across INTENT_BURN_CU → ALL_PROPOSED resume; immutable owner deadline.
     */
    uint8_t frag_ack_cu_live;
    uint8_t frag_ack_cu_key16[16];
    uint8_t frag_ack_cu_iv12[12];
    uint64_t frag_ack_cu_counter;
    uint32_t frag_ack_cu_e2e_context_id;
    uint32_t frag_ack_cu_hop_context_id;
    uint64_t frag_ack_owner_deadline_ms; /* immutable; never extended on retry */
    ninlil_r7_frag_ack_body frag_ack_cu_body;
    uint8_t frag_ack_sealed_live;
    size_t frag_ack_sealed_len;
    uint8_t frag_ack_sealed[64];
} ninlil_r7_frag_prod_bind_t;

typedef struct ninlil_r7_frag_prod_matrix_cell {
    uint8_t carrier;
    uint32_t channel_id;
    uint8_t owner_class; /* 1 DATA / 2 ACK */
    uint8_t action;      /* 1 TX / 2 RX */
    uint8_t profile;
    uint16_t route_handle;
    uint16_t frag_index; /* 0 = SINGLE; else fragment slot pin */
    uint8_t ok;
    int32_t status;
} ninlil_r7_frag_prod_matrix_cell_t;

/*
 * Safe on uninitialized stack objects: NULL-check then unconditional memset.
 * Never reads bind fields before wipe (C indeterminate-pointer UB forbidden).
 * After reset: magic/version stamped, matrix_ws=NULL. Caller must explicitly
 * ninlil_r7_frag_prod_bind_set_matrix_ws for run_matrix.
 */
void ninlil_r7_frag_prod_bind_reset(ninlil_r7_frag_prod_bind_t *bind);

/*
 * Attach/detach caller-owned matrix workspace. Requires prior reset/reinit
 * (magic/version). ws may be NULL to unbind.
 */
int32_t ninlil_r7_frag_prod_bind_set_matrix_ws(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_matrix_ws_t *ws);

/*
 * Re-clear an *already initialized* bind (magic/version match). Preserves
 * matrix_ws pointer only. Refuses uninitialized garbage (no field reads that
 * would trap). Use when soft-restarting a live Runtime/Cell agent object.
 */
int32_t ninlil_r7_frag_prod_bind_reinit(ninlil_r7_frag_prod_bind_t *bind);

/* 1 if magic/version match current contract. */
int ninlil_r7_frag_prod_bind_is_inited(const ninlil_r7_frag_prod_bind_t *bind);

/* Zeroize instance matrix workspace (clear live + tr/rr). */
void ninlil_r7_frag_prod_matrix_ws_zeroize(ninlil_r7_frag_prod_matrix_ws_t *ws);

/* Copy live L_core into bind (required before issue). */
int32_t ninlil_r7_frag_prod_set_live(
    ninlil_r7_frag_prod_bind_t *bind,
    const ninlil_pcp_live_profile_t *live);

/*
 * Owner-held time authority (docs/30 §11.2.3) — CONTRACT v3 (stable).
 *
 * Contract pin (header/source/fixtures must agree; mixed snapshots are RED):
 *   NINLIL_R7_FRAG_TIME_AUTHORITY_CONTRACT == 3
 *   - sample sole owner: ninlil_r2_private_sample_authority_clock only
 *   - bind-embedded private owner (no process-global pointer secret table)
 *   - typed A/B/C/D + watermark/baseline floors + three-axis catalog
 *   - 16B sample epoch copy; no host_seed / no issue_sample_pin for stamps
 *   - fixtures: advance bound PCP then mint/refresh
 */
/* Integer-only for #if pin (no cast — C preprocessor). */
#define NINLIL_R7_FRAG_TIME_AUTHORITY_CONTRACT 3
int32_t ninlil_r7_frag_prod_time_authority_mint(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t *out_owner_gen);
int32_t ninlil_r7_frag_prod_time_authority_refresh(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen);
int32_t ninlil_r7_frag_prod_time_apply_class_d(
    ninlil_r7_frag_prod_bind_t *bind,
    const ninlil_r7_class_d_sample_t *sample);
int32_t ninlil_r7_frag_prod_time_set_uncertain(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen,
    uint8_t uncertain);
int32_t ninlil_r7_frag_prod_time_set_epoch_pin(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen,
    uint64_t epoch_id_lo,
    uint64_t expected_epoch_lo);
int32_t ninlil_r7_frag_prod_time_set_fault_flags(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen,
    uint8_t clock_rollback,
    uint8_t clock_future_vs_expiry);
uint64_t ninlil_r7_frag_prod_time_now_ms(
    const ninlil_r7_frag_prod_bind_t *bind);
int ninlil_r7_frag_prod_time_is_trusted(
    const ninlil_r7_frag_prod_bind_t *bind);
/* 1 iff bind-embedded private owner live + MAC valid. */
int ninlil_r7_frag_prod_time_authority_valid(
    const ninlil_r7_frag_prod_bind_t *bind);
/* Last sample typed_class (NINLIL_R2_SAMPLE_*) after mint/refresh. */
uint8_t ninlil_r7_frag_prod_time_last_typed_class(
    const ninlil_r7_frag_prod_bind_t *bind);

/* L1 admission: free ledger slot? */
int32_t ninlil_r7_frag_prod_ledger_free_slots(
    const ninlil_r7_frag_prod_bind_t *bind,
    size_t *out_free);

/*
 * Seal SINGLE via N6 e2e + hop DATA burns, real AEAD, L1 admit (≤2),
 * R2 issue, R1 transmit. cleanup_class set for all outcomes.
 */
int32_t ninlil_r7_frag_prod_tx_single(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    const uint8_t *app,
    size_t app_len,
    uint32_t e2e_context_id,
    uint32_t hop_context_id,
    uint8_t ack_requested,
    ninlil_r7_frag_prod_tx_result_t *out);

/*
 * TX a pre-sealed E2E blob as OUTER (LINK/FRAG hop path): N6 hop DATA burn +
 * outer seal + L1/R2/R1. Used for same-E2E-body / fresh-hop retry after session
 * retains bit-identical E2E.
 */
int32_t ninlil_r7_frag_prod_tx_outer_from_e2e(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    const uint8_t *e2e_blob,
    size_t e2e_len,
    uint32_t hop_context_id,
    uint8_t ack_requested,
    uint16_t route_handle,
    uint8_t route_generation,
    ninlil_r7_frag_prod_tx_result_t *out);

/*
 * RX outer: structural + N6 hop precheck + hop AEAD + N6 hop admit +
 * E2E precheck/open/admit + body.
 *   - SINGLE always (no reasm required)
 *   - START/CONT when bind->reasm bound (production fragmented path)
 *   - FRAG_ACK open when present (body_applied=0; e2e_type=ACK)
 * hop-only if typed N6 REPLAY on E2E only (no body reapply / no publish).
 * Live-ticket collision (TICKET) and all other N6 errors ⇒ PROD_N6 fail-closed.
 * Decoded outer hop_context_id must exact-match hop_context_id (WIRE else).
 */
int32_t ninlil_r7_frag_prod_rx_outer(
    ninlil_r7_frag_prod_bind_t *bind,
    const uint8_t *outer,
    size_t outer_len,
    uint32_t hop_context_id,
    uint32_t e2e_context_id,
    ninlil_r7_frag_prod_rx_result_t *out);

/*
 * Production FRAG_ACK INTENT_BURN_CU classify (docs/30 §15.3.7):
 * calls ninlil_n6_recover_cu and maps ALL_PROPOSED/ALL_OLD/THIRD/RETRY.
 * Reserve retained until classification; not lab-only.
 */
int32_t ninlil_r7_frag_prod_frag_ack_classify_cu(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_n6_cu_class_t *out_class);

/*
 * Production multi-frame TX begin (docs/30 §1.1.1 ownership):
 * per fragment: STAMP_FIELDS → N6 E2E burn → seal → FRAME_READY(E2E_BLOB).
 * No hop burn / Permit / R1. Sets sender deadline + e2e_prep_burns=1.
 * Duplicate begin on live xfer ⇒ ADMISSION.
 */
int32_t ninlil_r7_frag_prod_tx_frag_begin(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t transfer_id[16],
    uint32_t e2e_context_id);

/*
 * Air fragment frag_index with production LINK lifecycle:
 * hop_attempts≤4, outer_attempts≤16, eligible_at retry, deadline, frag_acked.
 * STAMP(HOP E2E_BLOB) → hop burn → outer seal → FRAME_READY(OUTER) → R2/R1.
 * Same E2E blob on hop retry. Does not burn a new E2E counter.
 */
int32_t ninlil_r7_frag_prod_tx_frag_air(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint16_t frag_index,
    uint64_t owner_token,
    uint64_t candidate_token,
    uint32_t hop_context_id,
    uint8_t ack_requested,
    ninlil_r7_frag_prod_tx_result_t *out);

/*
 * After successful air (edge): count hop attempt; schedule retry eligibility
 * when ack_requested; mark frag_acked if unacked success path.
 */
int32_t ninlil_r7_frag_prod_tx_frag_note_air(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint16_t frag_index,
    uint64_t hop_counter);

/*
 * Apply FRAG_ACK to sender xfer (PARTIAL/COMPLETE/ABORT). Wrong handle⇒WIRE.
 * COMPLETE/ABORT with live issued work ⇒ TERMINAL_PENDING (no local erase).
 */
int32_t ninlil_r7_frag_prod_tx_frag_apply_frag_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    const ninlil_r7_frag_ack_body *body);

/*
 * Fresh E2E prep for one fragment (≤4 burns): STAMP→burn→seal→FRAME_READY E2E.
 * Resets hop/outer attempts for that fragment. Retains transfer_handle.
 */
int32_t ninlil_r7_frag_prod_tx_frag_e2e_retry(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint16_t frag_index,
    uint64_t owner_token,
    uint64_t candidate_token);

/* Advance trusted time on bind and fail-closed past sender deadline. */
int32_t ninlil_r7_frag_prod_tx_frag_tick(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint64_t now_ms);

/* Terminal cleanup: OWNER_TERMINAL + zeroize xfer. */
int32_t ninlil_r7_frag_prod_tx_frag_complete(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint64_t owner_token,
    uint64_t candidate_token);

/*
 * Production FRAG_ACK TX: N6 E2E burn + seal ACK + hop outer + R2/R1.
 * Reverse E2E context via e2e_context_id (caller selects reverse lane handle).
 * Not MFDT custody claim.
 */
int32_t ninlil_r7_frag_prod_tx_frag_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    uint32_t e2e_context_id,
    uint32_t hop_context_id,
    const ninlil_r7_frag_ack_body *ack,
    uint8_t outer_ack_requested,
    ninlil_r7_frag_prod_tx_result_t *out);

/*
 * Public note: refuses invent (requires e2e_admitted via after_e2e).
 * Returns ADMISSION without E2E admission proof.
 */
int32_t ninlil_r7_frag_prod_link_ack_note_rx_data(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t hop_ack_context_id,
    uint32_t acked_hop_data_context_id,
    uint64_t acked_hop_counter);

/*
 * Enqueue reverse LINK_ACK only after successful E2E admit.
 * e2e_admitted must be 1; all contexts nonzero; hop_ack_context matches bind.
 */
int32_t ninlil_r7_frag_prod_link_ack_note_after_e2e(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t hop_ack_context_id,
    uint32_t acked_hop_data_context_id,
    uint64_t acked_hop_counter,
    uint8_t e2e_admitted);

/* Seal hop-ACK outer into pending slot (prepare candidate). */
int32_t ninlil_r7_frag_prod_link_ack_prepare(
    ninlil_r7_frag_prod_bind_t *bind,
    size_t pending_index,
    uint64_t owner_token,
    uint64_t candidate_token);

/*
 * Issue+TX prepared LINK_ACK only. issue_calls ≤ 8; FIFO ledger + cleanup.
 * Unprepared / exhausted / wrong order ⇒ ADMISSION/RESOURCE.
 */
int32_t ninlil_r7_frag_prod_tx_link_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    size_t pending_index,
    ninlil_r7_frag_prod_tx_result_t *out);

/*
 * Production LINK_ACK RX: open outer, exact hop_ack_context bind to ticket,
 * reverse-pair body check, N6 admit. out_body filled on OK.
 * Optionally apply to sender xfer pending hop counters when xfer!=NULL.
 */
int32_t ninlil_r7_frag_prod_rx_link_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    const uint8_t *frame,
    size_t frame_len,
    uint32_t hop_ack_context_id,
    uint32_t expected_acked_hop_data_context_id,
    ninlil_r7_frag_prod_xfer_t *xfer,
    ninlil_r7_frag_link_ack_body *out_body);

/* Count live pending LINK_ACK obligations. */
size_t ninlil_r7_frag_prod_link_ack_pending_count(
    const ninlil_r7_frag_prod_bind_t *bind);

void ninlil_r7_frag_prod_xfer_zeroize(ninlil_r7_frag_prod_xfer_t *xfer);

/* Explicit §15.3.8 cleanup matrix entry. */
int32_t ninlil_r7_frag_prod_cleanup(
    ninlil_r7_frag_prod_bind_t *bind,
    uint8_t cleanup_class,
    uint64_t permit_sequence);

/*
 * Closed matrix: 2 permits × carriers/channels/classes/actions/profile/route/
 * fragment DATA/ACK via real N6/R2/R1 calls (host proof). Fills cells[] up to
 * cells_cap; *out_n = count executed.
 *
 * Requires tx_bind->matrix_ws non-NULL (caller/instance-owned storage).
 * Nested run_matrix on the same workspace ⇒ ADMISSION (non-reentrant).
 * Distinct binds with distinct workspaces do not cross-contaminate.
 */
int32_t ninlil_r7_frag_prod_run_matrix(
    ninlil_r7_frag_prod_bind_t *tx_bind,
    ninlil_r7_frag_prod_bind_t *rx_bind,
    const uint8_t *app,
    size_t app_len,
    uint32_t e2e_context_id,
    uint32_t hop_context_id,
    ninlil_r7_frag_prod_matrix_cell_t *cells,
    size_t cells_cap,
    size_t *out_n);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_PROD_ORCH_H */
