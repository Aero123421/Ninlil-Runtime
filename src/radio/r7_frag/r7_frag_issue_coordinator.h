#ifndef NINLIL_R7_FRAG_ISSUE_COORDINATOR_H
#define NINLIL_R7_FRAG_ISSUE_COORDINATOR_H

/*
 * Production L1 issued-Permit global coordinator (docs/30 §15.3).
 *
 * Authority-scoped: one process-local queue per authority_token (pcp identity).
 * Max 8 issued permits globally per authority. Admission registers pre-TX with
 * full identity (permit_sequence + outer digest + bind). Non-head work stays
 * queued (QUEUED) until head; TX only at head. Complete cleanup releases
 * coordinator + R5 registry rows together.
 *
 * Sole production API: admit / begin_tx / hold_retry / resume_tx / complete.
 * No register/release bypass. Not public ABI. Not installed.
 * Single-threaded host model uses reentry guard as concurrency fence.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP ((size_t)8u)

#define NINLIL_R7_COORD_OK ((int32_t)0)
#define NINLIL_R7_COORD_INVALID ((int32_t)1)
#define NINLIL_R7_COORD_CAPACITY ((int32_t)2)
#define NINLIL_R7_COORD_OUT_OF_ORDER ((int32_t)3)
#define NINLIL_R7_COORD_NOT_FOUND ((int32_t)4)
#define NINLIL_R7_COORD_QUEUED ((int32_t)5)
#define NINLIL_R7_COORD_BUSY ((int32_t)6)
#define NINLIL_R7_COORD_DUPLICATE ((int32_t)7)

/* Slot state in coordinator queue. */
#define NINLIL_R7_COORD_ST_EMPTY ((uint8_t)0u)
#define NINLIL_R7_COORD_ST_QUEUED ((uint8_t)1u) /* issued, waiting head */
#define NINLIL_R7_COORD_ST_HEAD ((uint8_t)2u)   /* may enter R1 TX */
#define NINLIL_R7_COORD_ST_IN_TX ((uint8_t)3u)  /* transmit in progress */
#define NINLIL_R7_COORD_ST_HELD ((uint8_t)4u)   /* issued, R1 retry held */

typedef struct ninlil_r7_coord_admit {
    uint64_t authority_token; /* pcp object identity */
    uint64_t permit_sequence;
    uintptr_t bind_token;
    uint8_t outer_digest[32];
    uint32_t outer_len;
    uint64_t issue_now_ms;
} ninlil_r7_coord_admit_t;

void ninlil_r7_frag_issue_coordinator_reset(void);

/*
 * Admit issued permit into global queue. Returns:
 *   OK     — admitted and is head (may TX now)
 *   QUEUED — admitted but not head (must not TX)
 *   CAPACITY / DUPLICATE / INVALID / BUSY
 */
int32_t ninlil_r7_frag_issue_coordinator_admit(
    const ninlil_r7_coord_admit_t *in);

/* Mark head as IN_TX. Only HEAD (or resume of HELD) may call. */
int32_t ninlil_r7_frag_issue_coordinator_begin_tx(
    uint64_t authority_token,
    uint64_t permit_sequence);

/*
 * Complete release after OK/EDGE_STALE/drain. Drops row and promotes next head.
 * *out_promoted_seq = new head sequence or 0.
 */
int32_t ninlil_r7_frag_issue_coordinator_complete(
    uint64_t authority_token,
    uint64_t permit_sequence,
    uint64_t *out_promoted_seq);

/* Hold issued permit for same-object R1 retry (NOT_BEFORE / EXPIRED). */
int32_t ninlil_r7_frag_issue_coordinator_hold_retry(
    uint64_t authority_token,
    uint64_t permit_sequence);

/* Re-enter TX for HELD head only (same permit_sequence + outer). */
int32_t ninlil_r7_frag_issue_coordinator_resume_tx(
    uint64_t authority_token,
    uint64_t permit_sequence);

/* Exact outer digest match for admitted identity (1 = match). */
int ninlil_r7_frag_issue_coordinator_outer_matches(
    uint64_t authority_token,
    uint64_t permit_sequence,
    const uint8_t outer_digest[32],
    uint32_t outer_len);

/* Slot state query (EMPTY if not found). */
uint8_t ninlil_r7_frag_issue_coordinator_slot_state(
    uint64_t authority_token,
    uint64_t permit_sequence);

size_t ninlil_r7_frag_issue_coordinator_count(void);
uint64_t ninlil_r7_frag_issue_coordinator_head(uint64_t authority_token);
int ninlil_r7_frag_issue_coordinator_is_head(
    uint64_t authority_token,
    uint64_t permit_sequence);

/* Complete all live rows for one authority (cleanup / reinit drain). */
void ninlil_r7_frag_issue_coordinator_complete_all_authority(
    uint64_t authority_token);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_ISSUE_COORDINATOR_H */
