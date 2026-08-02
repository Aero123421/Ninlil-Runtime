#ifndef NINLIL_R7_FRAG_ACK_LEDGER_H
#define NINLIL_R7_FRAG_ACK_LEDGER_H

/*
 * FRAG_ACK reverse E2E burn ledger (docs/30 §15.3.7).
 *
 * Semantic identity = full FRAG_ACK plaintext:
 *   (transfer_handle, frag_count, received_bitmap, status, reason)
 *
 * Budgets:
 *   - per identity: burns_used ≤ 2 (ACK_SEMANTIC_MAX2)
 *   - per transfer aggregate: Σ burns ≤ min(2*frag_count, 32)
 *   - control ACK reserve pool: ≤ CONTROL_ACK_RESERVE (8) concurrent holds
 *
 * Retain identity rows until owner_expiry_mono (receiver absolute deadline or
 * tombstone expiry). INTENT_ACKED / DROP clear pending reserve only — never
 * reset burns_used for that identity. New identity → new row burns_used=0.
 * Process restart / discard_all wipes volatile ledger with owner.
 *
 * Production and session share this module. Heap-free fixed cap.
 */

#include "r7_frag_profile.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_R7_FRAG_ACK_LEDGER_OK ((int32_t)0)
#define NINLIL_R7_FRAG_ACK_LEDGER_INVALID ((int32_t)1)
#define NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE ((int32_t)2)
#define NINLIL_R7_FRAG_ACK_LEDGER_EXPIRED ((int32_t)3)

/* Fixed-cap identity rows (heap-free). Covers sequential PARTIAL supersedes. */
#define NINLIL_R7_FRAG_ACK_LEDGER_ROWS ((size_t)16u)

/* Aggregate absolute ceiling (docs/30). */
#define NINLIL_R7_FRAG_ACK_AGGREGATE_ABS_MAX ((uint16_t)32u)

typedef struct ninlil_r7_frag_ack_identity {
    uint64_t transfer_handle;
    uint16_t frag_count;
    uint16_t received_bitmap;
    uint8_t status;
    uint8_t reason;
} ninlil_r7_frag_ack_identity_t;

typedef struct ninlil_r7_frag_ack_ledger_row {
    uint8_t in_use;
    ninlil_r7_frag_ack_identity_t id;
    uint8_t burns_used; /* ≤ NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2 */
    uint64_t last_burn_mono;
    uint64_t owner_expiry_mono; /* retain until; 0 = pin to ledger default */
} ninlil_r7_frag_ack_ledger_row_t;

/* Intent lifecycle states (docs/30 §15.3.7.1) — process-local. */
#define NINLIL_R7_FRAG_INTENT_IDLE ((uint8_t)0u)
#define NINLIL_R7_FRAG_INTENT_PENDING ((uint8_t)1u)
#define NINLIL_R7_FRAG_INTENT_DUE ((uint8_t)2u)
#define NINLIL_R7_FRAG_INTENT_RESERVE ((uint8_t)3u)
#define NINLIL_R7_FRAG_INTENT_BURN ((uint8_t)4u)
#define NINLIL_R7_FRAG_INTENT_BURN_CU ((uint8_t)5u)
#define NINLIL_R7_FRAG_INTENT_SEAL ((uint8_t)6u)
#define NINLIL_R7_FRAG_INTENT_LINK ((uint8_t)7u)
#define NINLIL_R7_FRAG_INTENT_RETRY ((uint8_t)8u)
#define NINLIL_R7_FRAG_INTENT_ACKED ((uint8_t)9u)
#define NINLIL_R7_FRAG_INTENT_DROP ((uint8_t)10u)

typedef struct ninlil_r7_frag_ack_ledger {
    ninlil_r7_frag_ack_ledger_row_t rows[NINLIL_R7_FRAG_ACK_LEDGER_ROWS];
    /*
     * Active transfer aggregate scope (receiver/tombstone owner).
     * transfer_handle=0 ⇒ no aggregate pin (charge still uses id.th).
     */
    uint64_t owner_transfer_handle;
    uint16_t owner_frag_count;
    uint64_t owner_expiry_mono;
    /* Concurrent control-reserve holds (≤ CONTROL_ACK_RESERVE). */
    uint8_t control_reserve_held;
    /* Pending intent work (cleared on ACKED/DROP; ledger rows retained). */
    uint8_t intent_state;
    ninlil_r7_frag_ack_identity_t intent_id;
    uint64_t partial_ack_due;
    uint64_t ack_intent_retry_at;
} ninlil_r7_frag_ack_ledger_t;

void ninlil_r7_frag_ack_ledger_init(ninlil_r7_frag_ack_ledger_t *led);
void ninlil_r7_frag_ack_ledger_zeroize(ninlil_r7_frag_ack_ledger_t *led);

/*
 * Bind aggregate owner (receiver transfer or tombstone). Does not reset
 * existing identity rows for other handles. Sets default owner_expiry for
 * new rows. If transfer_handle changes, aggregate for the new handle starts
 * fresh (prior handles' rows remain until their own expiry).
 */
void ninlil_r7_frag_ack_ledger_bind_owner(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t transfer_handle,
    uint16_t frag_count,
    uint64_t owner_expiry_mono);

/* Expire rows past owner_expiry; release nothing about control_reserve_held. */
void ninlil_r7_frag_ack_ledger_tick(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono);

/* Discard all rows + reserve holds (restart / owner gone). */
void ninlil_r7_frag_ack_ledger_discard_all(ninlil_r7_frag_ack_ledger_t *led);

/* Control reserve pool acquire/release (docs/30 control ACK reserve 8). */
int32_t ninlil_r7_frag_ack_ledger_reserve_acquire(
    ninlil_r7_frag_ack_ledger_t *led);
void ninlil_r7_frag_ack_ledger_reserve_release(
    ninlil_r7_frag_ack_ledger_t *led);

/*
 * Pre-check whether a successful reverse E2E burn may be charged for id
 * (identity max2 + transfer aggregate). Does not mutate.
 */
int32_t ninlil_r7_frag_ack_ledger_may_burn(
    const ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id,
    uint64_t now_mono);

/*
 * After durable reverse E2E burn FULL_OK (or ALL_PROPOSED CU resolve): charge
 * burns_used += 1 for identity. Creates row if needed. Requires reserve held
 * is caller's responsibility. Returns RESOURCE if budgets forbid.
 */
int32_t ninlil_r7_frag_ack_ledger_charge_burn(
    ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id,
    uint64_t now_mono);

/* burns_used for identity (0 if no row). */
uint8_t ninlil_r7_frag_ack_ledger_burns_used(
    const ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id);

/* Aggregate burns for transfer_handle across live rows. */
uint16_t ninlil_r7_frag_ack_ledger_aggregate_burns(
    const ninlil_r7_frag_ack_ledger_t *led,
    uint64_t transfer_handle);

uint16_t ninlil_r7_frag_ack_ledger_aggregate_limit(uint16_t frag_count);

/* Fill identity from FRAG_ACK body fields. */
void ninlil_r7_frag_ack_identity_from_body(
    ninlil_r7_frag_ack_identity_t *id,
    uint64_t transfer_handle,
    uint16_t frag_count,
    uint16_t received_bitmap,
    uint8_t status,
    uint8_t reason);

/*
 * Intent SM (docs/30 §15.3.7): pending work only.
 * INTENT_ACKED/DROP clear pending; burns ledger retained until owner expiry.
 */
int32_t ninlil_r7_frag_ack_intent_arm_pending(
    ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id,
    uint64_t now_mono,
    uint64_t owner_deadline_mono);
/* Advance PENDING→DUE when due; DROP on deadline/overflow. */
int32_t ninlil_r7_frag_ack_intent_tick(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono);
/* DUE→RESERVE on acquire OK; DUE→DROP on capacity. */
int32_t ninlil_r7_frag_ack_intent_enter_reserve(
    ninlil_r7_frag_ack_ledger_t *led);
/* RESERVE→SEAL after charge_burn OK; RESERVE→DROP on budget fail. */
int32_t ninlil_r7_frag_ack_intent_after_burn_ok(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono);
int32_t ninlil_r7_frag_ack_intent_enter_link(
    ninlil_r7_frag_ack_ledger_t *led);
int32_t ninlil_r7_frag_ack_intent_mark_acked(
    ninlil_r7_frag_ack_ledger_t *led);
int32_t ninlil_r7_frag_ack_intent_mark_drop(
    ninlil_r7_frag_ack_ledger_t *led);
/* SEAL/LINK fail → RETRY if budget remains else DROP. */
int32_t ninlil_r7_frag_ack_intent_retry_or_drop(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono);
uint8_t ninlil_r7_frag_ack_intent_state(
    const ninlil_r7_frag_ack_ledger_t *led);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_ACK_LEDGER_H */
