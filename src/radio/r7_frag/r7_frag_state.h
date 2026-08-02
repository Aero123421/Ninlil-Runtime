#ifndef NINLIL_R7_FRAG_STATE_H
#define NINLIL_R7_FRAG_STATE_H

/*
 * R7 private pure FRAG planner + reassembly state (docs/30 §12–13 tranche).
 *
 * SEMANTIC: R7_FRAG_STATE_PRIVATE_PURE_ONLY
 * SEMANTIC: FRAG_COUNT_EFFECTIVE_MAX_13
 * SEMANTIC: CONTENT_DIGEST_SHA256_REASSEMBLED
 * SEMANTIC: FRAG_DUAL_UNIQUE_INDEX_HANDLE_AND_TRANSFER_ID
 * SEMANTIC: FRAG_CONFLICT_NO_REPLACE_EXISTING
 * SEMANTIC: FRAG_START_EXACT_RETRY_NO_MUTATION
 * SEMANTIC: CONT_CONFLICT_ABORT_TOMBSTONE
 * SEMANTIC: FRAG_TOMBSTONE_RESERVE_ON_START
 * SEMANTIC: TOMBSTONE_VOLATILE_ON_RESTART
 * SEMANTIC: FRAG_COMPLETE_COMMIT_ORDER_EXACT
 * SEMANTIC: NO_PARTIAL_PUBLICATION
 * SEMANTIC: COMMIT_UNKNOWN_RECOVERY_EXACT
 *
 * No AEAD/wire/crypto. No heap/VLA. Not public ABI. Not installed. Not HIL.
 * wire_profile_id 0x11 maxima only; does not change Accepted wire offsets.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Exact maxima / timers (docs/30 §12 / §13.1)                                 */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_FRAG_STATE_CONT_UNIT ((uint16_t)180u)
#define NINLIL_R7_FRAG_STATE_S_MIN ((uint16_t)1u)
#define NINLIL_R7_FRAG_STATE_S_MAX ((uint16_t)126u)
#define NINLIL_R7_FRAG_STATE_C_MIN ((uint16_t)1u)
#define NINLIL_R7_FRAG_STATE_C_MAX ((uint16_t)180u)
#define NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX ((uint32_t)2048u)
#define NINLIL_R7_FRAG_STATE_FRAG_COUNT_MIN ((uint16_t)2u)
#define NINLIL_R7_FRAG_STATE_FRAG_COUNT_MAX ((uint16_t)13u)

#define NINLIL_R7_FRAG_STATE_TRANSFER_ID_LEN ((size_t)16u)
#define NINLIL_R7_FRAG_STATE_DIGEST_LEN ((size_t)32u)
#define NINLIL_R7_FRAG_STATE_FINGERPRINT_LEN ((size_t)32u)
#define NINLIL_R7_FRAG_STATE_TOMBSTONE_CANON_LEN ((size_t)72u)

/* CELL_64_V1 capacity from r7_frag_profile.h (controller default). */
#include "r7_frag_profile.h"

#define NINLIL_R7_FRAG_STATE_REASM_SLOTS NINLIL_R7_FRAG_REASM_SLOTS
#define NINLIL_R7_FRAG_STATE_PAYLOAD_BUDGET NINLIL_R7_FRAG_PAYLOAD_BUDGET
#define NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS NINLIL_R7_FRAG_TOMBSTONE_SLOTS
#define NINLIL_R7_FRAG_STATE_UPPER_SLOTS ((size_t)1u)
#define NINLIL_R7_FRAG_STATE_MAX_PER_PEER NINLIL_R7_FRAG_MAX_PER_PEER

#define NINLIL_R7_FRAG_STATE_RECEIVER_TTL_MS NINLIL_R7_FRAG_RECEIVER_TTL_MS
#define NINLIL_R7_FRAG_STATE_IDLE_TIMEOUT_MS NINLIL_R7_FRAG_IDLE_MS
#define NINLIL_R7_FRAG_STATE_TOMBSTONE_TTL_MS NINLIL_R7_FRAG_TOMBSTONE_TTL_MS
#define NINLIL_R7_FRAG_STATE_PARTIAL_ACK_IDLE_MS NINLIL_R7_FRAG_PARTIAL_ACK_IDLE_MS

/* Status / reason catalogs (docs/30 §12.3). */
#define NINLIL_R7_FRAG_STATE_STATUS_PARTIAL ((uint8_t)0u)
#define NINLIL_R7_FRAG_STATE_STATUS_COMPLETE ((uint8_t)1u)
#define NINLIL_R7_FRAG_STATE_STATUS_ABORT ((uint8_t)2u)

#define NINLIL_R7_FRAG_STATE_REASON_NONE ((uint8_t)0u)
#define NINLIL_R7_FRAG_STATE_REASON_CONFLICT ((uint8_t)1u)
#define NINLIL_R7_FRAG_STATE_REASON_DIGEST ((uint8_t)2u)
#define NINLIL_R7_FRAG_STATE_REASON_RESOURCE ((uint8_t)3u)
#define NINLIL_R7_FRAG_STATE_REASON_TIMEOUT ((uint8_t)4u)
#define NINLIL_R7_FRAG_STATE_REASON_FENCED ((uint8_t)5u)

/* COMMIT_UNKNOWN classifier classes (docs/30 §9.3). */
#define NINLIL_R7_FRAG_STATE_CU_RETRY_LATER ((uint8_t)1u)
#define NINLIL_R7_FRAG_STATE_CU_ALL_OLD ((uint8_t)2u)
#define NINLIL_R7_FRAG_STATE_CU_ALL_PROPOSED ((uint8_t)3u)
#define NINLIL_R7_FRAG_STATE_CU_THIRD ((uint8_t)4u)
#define NINLIL_R7_FRAG_STATE_CU_CORRUPT ((uint8_t)5u)

#define NINLIL_R7_FRAG_STATE_CU_ENTRY_OLD ((uint8_t)1u)
#define NINLIL_R7_FRAG_STATE_CU_ENTRY_PROPOSED ((uint8_t)2u)
#define NINLIL_R7_FRAG_STATE_CU_ENTRY_THIRD ((uint8_t)3u)

#define NINLIL_R7_FRAG_STATE_CU_MAX_ENTRIES ((size_t)32u)
#define NINLIL_R7_FRAG_STATE_CU_KEY_MAX ((size_t)255u)
#define NINLIL_R7_FRAG_STATE_CU_VALUE_MAX ((size_t)256u)

/* Restart snapshot */
#define NINLIL_R7_FRAG_STATE_SNAP_MAGIC ((uint32_t)0x52374650u) /* "R7FP" pure */
#define NINLIL_R7_FRAG_STATE_SNAP_VERSION ((uint16_t)1u)

/* Closed status */
#define NINLIL_R7_FRAG_STATE_OK ((int32_t)0)
#define NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT ((int32_t)1)
#define NINLIL_R7_FRAG_STATE_STRUCTURAL ((int32_t)2)
#define NINLIL_R7_FRAG_STATE_LENGTH ((int32_t)3)
#define NINLIL_R7_FRAG_STATE_CAPACITY ((int32_t)4)
#define NINLIL_R7_FRAG_STATE_RESOURCE ((int32_t)5)
#define NINLIL_R7_FRAG_STATE_CONFLICT ((int32_t)6)
#define NINLIL_R7_FRAG_STATE_DUPLICATE ((int32_t)7)
#define NINLIL_R7_FRAG_STATE_EXACT_RETRY ((int32_t)8)
#define NINLIL_R7_FRAG_STATE_NO_TRANSFER ((int32_t)9)
#define NINLIL_R7_FRAG_STATE_TIMEOUT ((int32_t)10)
#define NINLIL_R7_FRAG_STATE_FENCED ((int32_t)11)
#define NINLIL_R7_FRAG_STATE_PUBLISHED ((int32_t)12)
#define NINLIL_R7_FRAG_STATE_DIGEST ((int32_t)13)
#define NINLIL_R7_FRAG_STATE_INTERNAL ((int32_t)14)
#define NINLIL_R7_FRAG_STATE_NEED_DIGEST ((int32_t)15)

typedef int32_t ninlil_r7_frag_state_status;

/* -------------------------------------------------------------------------- */
/* Plan                                                                       */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_frag_state_chunk {
    uint16_t frag_index; /* 0 = START, 1.. = CONT */
    uint16_t offset;
    uint16_t length;
} ninlil_r7_frag_state_chunk;

typedef struct ninlil_r7_frag_state_plan {
    uint32_t total_len;
    uint16_t frag_count;
    uint16_t first_chunk_len; /* S */
    uint16_t cont_unit;       /* 180 */
    ninlil_r7_frag_state_chunk chunks[NINLIL_R7_FRAG_STATE_FRAG_COUNT_MAX];
} ninlil_r7_frag_state_plan;

/*
 * Build canonical plan with maximal S = min(126, total_len-1).
 * total_len domain for FRAG: 2..2048. 0 and 1 reject.
 */
ninlil_r7_frag_state_status ninlil_r7_frag_state_plan_build(
    uint32_t total_len,
    ninlil_r7_frag_state_plan *out_plan);

/* Validate START-derived (total_len, S, frag_count, unit). */
ninlil_r7_frag_state_status ninlil_r7_frag_state_plan_validate(
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint16_t frag_count,
    uint16_t continuation_unit);

/* CONT length/offset for index in 1..frag_count-1 given S and total_len. */
ninlil_r7_frag_state_status ninlil_r7_frag_state_cont_geometry(
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint16_t frag_count,
    uint16_t frag_index,
    uint16_t *out_offset,
    uint16_t *out_length);

/* -------------------------------------------------------------------------- */
/* ACK intent (local structured; no wire)                                     */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_frag_state_ack_intent {
    uint8_t valid;
    uint64_t transfer_handle;
    uint16_t frag_count;
    uint16_t received_bitmap;
    uint8_t status;
    uint8_t reason;
} ninlil_r7_frag_state_ack_intent;

/* -------------------------------------------------------------------------- */
/* Engine                                                                     */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_frag_state_tombstone {
    uint8_t in_use;
    uint8_t is_reservation; /* START reserve before terminal */
    uint32_t e2e_context_id;
    uint64_t key_generation;
    uint8_t transfer_id[NINLIL_R7_FRAG_STATE_TRANSFER_ID_LEN];
    uint64_t transfer_handle;
    uint16_t frag_count;
    uint8_t status;
    uint8_t reason;
    uint8_t fingerprint[NINLIL_R7_FRAG_STATE_FINGERPRINT_LEN];
    uint64_t expiry_mono;
} ninlil_r7_frag_state_tombstone;

typedef struct ninlil_r7_frag_state_slot {
    uint8_t in_use;
    uint32_t e2e_context_id;
    uint64_t key_generation;
    uint8_t transfer_id[NINLIL_R7_FRAG_STATE_TRANSFER_ID_LEN];
    uint64_t transfer_handle;
    uint32_t total_len;
    uint16_t frag_count;
    uint16_t first_chunk_len;
    uint8_t content_digest[NINLIL_R7_FRAG_STATE_DIGEST_LEN];
    uint8_t fingerprint[NINLIL_R7_FRAG_STATE_FINGERPRINT_LEN];
    uint16_t bitmap;
    uint64_t receiver_start_mono;
    uint64_t receiver_absolute_deadline;
    uint64_t idle_deadline;
    uint64_t partial_ack_due;
    uint8_t payload[NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX];
    uint8_t chunk_seen[NINLIL_R7_FRAG_STATE_FRAG_COUNT_MAX];
    uint16_t chunk_len[NINLIL_R7_FRAG_STATE_FRAG_COUNT_MAX];
    size_t tomb_reserve_slot; /* index of reserved tombstone */
    uint8_t need_digest; /* 1: full bitmap committed; await digest finalize */
} ninlil_r7_frag_state_slot;

typedef struct ninlil_r7_frag_state_publication {
    uint8_t valid;
    uint32_t e2e_context_id;
    uint64_t key_generation;
    uint64_t transfer_handle;
    uint32_t total_len;
    uint8_t payload[NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX];
} ninlil_r7_frag_state_publication;

typedef struct ninlil_r7_frag_state_engine {
    ninlil_r7_frag_state_slot reasm[NINLIL_R7_FRAG_STATE_REASM_SLOTS];
    ninlil_r7_frag_state_tombstone tombs[NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS];
    ninlil_r7_frag_state_publication pub;
    size_t payload_bytes_in_use;
    uint64_t now_mono;
    uint8_t fenced;
    uint32_t publish_count; /* exact-once counter */
} ninlil_r7_frag_state_engine;

typedef struct ninlil_r7_frag_state_start_in {
    uint32_t e2e_context_id;
    uint64_t key_generation; /* binding; 0 reject */
    uint8_t transfer_id[NINLIL_R7_FRAG_STATE_TRANSFER_ID_LEN];
    uint64_t transfer_handle; /* nonzero, not UINT64_MAX */
    uint32_t total_len;
    uint16_t frag_count;
    uint16_t continuation_unit;
    uint8_t content_digest[NINLIL_R7_FRAG_STATE_DIGEST_LEN];
    /* Caller-bound start_manifest_fingerprint32 (docs/30 §12.1). */
    uint8_t fingerprint[NINLIL_R7_FRAG_STATE_FINGERPRINT_LEN];
    const uint8_t *first_chunk;
    uint16_t first_chunk_len;
} ninlil_r7_frag_state_start_in;

typedef struct ninlil_r7_frag_state_cont_in {
    uint32_t e2e_context_id;
    uint64_t key_generation;
    uint64_t transfer_handle;
    uint16_t frag_index; /* 1..frag_count-1 */
    const uint8_t *chunk;
    uint16_t chunk_len;
    /*
     * When the last missing fragment is admitted, caller supplies
     * SHA-256(reassembled) for digest binding (no crypto in this TU).
     * Ignored when bitmap remains incomplete.
     */
    const uint8_t *reassembled_digest32; /* may be NULL if incomplete path */
} ninlil_r7_frag_state_cont_in;

void ninlil_r7_frag_state_init(ninlil_r7_frag_state_engine *eng);
void ninlil_r7_frag_state_zeroize(ninlil_r7_frag_state_engine *eng);
void ninlil_r7_frag_state_set_now(
    ninlil_r7_frag_state_engine *eng, uint64_t now_mono);

/*
 * Admit START. Reserves tombstone before reassembly. Dual-index rules.
 * EXACT_RETRY: same fingerprint on active/tombstone (no mutation).
 * CONFLICT: non-exact collision (no replace).
 * RESOURCE: slot/budget/tombstone full (ACK0; no owner).
 */
ninlil_r7_frag_state_status ninlil_r7_frag_state_admit_start(
    ninlil_r7_frag_state_engine *eng,
    const ninlil_r7_frag_state_start_in *in,
    ninlil_r7_frag_state_ack_intent *out_intent);

/*
 * Admit CONT. CONT-before-START => NO_TRANSFER.
 * Identical duplicate => DUPLICATE (idempotent).
 * Conflicting bytes => CONFLICT + ABORT tombstone.
 * Full bitmap + digest provided => complete path.
 * Full bitmap + digest NULL => NEED_DIGEST (payload retained; call finalize).
 */
ninlil_r7_frag_state_status ninlil_r7_frag_state_admit_cont(
    ninlil_r7_frag_state_engine *eng,
    const ninlil_r7_frag_state_cont_in *in,
    ninlil_r7_frag_state_ack_intent *out_intent);

/*
 * After NEED_DIGEST: bind SHA-256(reassembled) bytes (caller must compute via
 * approved crypto provider over exact payload). Not a match-boolean API.
 */
ninlil_r7_frag_state_status ninlil_r7_frag_state_finalize(
    ninlil_r7_frag_state_engine *eng,
    uint32_t e2e_context_id,
    uint64_t transfer_handle,
    const uint8_t reassembled_digest32[32],
    ninlil_r7_frag_state_ack_intent *out_intent);

/* RO borrow of reassembled payload for digest computation only (not publish). */
ninlil_r7_frag_state_status ninlil_r7_frag_state_peek_reassembled(
    const ninlil_r7_frag_state_engine *eng,
    uint32_t e2e_context_id,
    uint64_t transfer_handle,
    const uint8_t **out_payload,
    size_t *out_len);

/* Idle/absolute timeout → ABORT TIMEOUT tombstone; expire tombstones. */
ninlil_r7_frag_state_status ninlil_r7_frag_state_tick(
    ninlil_r7_frag_state_engine *eng,
    uint64_t now_mono);

/*
 * Take completed publication exactly once. No partial bytes.
 * Returns PUBLISHED or NO_TRANSFER.
 */
ninlil_r7_frag_state_status ninlil_r7_frag_state_take_publication(
    ninlil_r7_frag_state_engine *eng,
    uint32_t *out_e2e_context_id,
    uint64_t *out_key_generation,
    uint64_t *out_transfer_handle,
    uint8_t *out_payload,
    size_t out_capacity,
    size_t *out_len);

/* -------------------------------------------------------------------------- */
/* Restart snapshot (volatile: no reassembly/tombstone/publication restore)   */
/* -------------------------------------------------------------------------- */

/*
 * Snapshot carries only mono + fence (pure state engine has no durable lanes).
 * Decode rejects OLD magic, NEW version, PARTIAL length, EXTRA tail, THIRD
 * (nonzero reasm/tomb claims). Reassembly always starts empty after restart.
 */
ninlil_r7_frag_state_status ninlil_r7_frag_state_restart_encode(
    const ninlil_r7_frag_state_engine *eng,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_frag_state_status ninlil_r7_frag_state_restart_decode(
    ninlil_r7_frag_state_engine *eng,
    const uint8_t *in,
    size_t in_len);

/* -------------------------------------------------------------------------- */
/* COMMIT_UNKNOWN classifier (pure; docs/30 §9.3)                             */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_frag_state_cu_entry {
    uint8_t old_present;
    uint8_t proposed_present;
    uint16_t key_len;
    uint16_t old_len;
    uint16_t proposed_len;
    uint8_t key[NINLIL_R7_FRAG_STATE_CU_KEY_MAX];
    uint8_t old_bytes[NINLIL_R7_FRAG_STATE_CU_VALUE_MAX];
    uint8_t proposed_bytes[NINLIL_R7_FRAG_STATE_CU_VALUE_MAX];
    /* 0=OK found, 1=NOT_FOUND, 2=BUSY, 3=IO, 4=OTHER/third */
    uint8_t observed_status;
    uint16_t observed_len;
    uint8_t observed_bytes[NINLIL_R7_FRAG_STATE_CU_VALUE_MAX];
} ninlil_r7_frag_state_cu_entry;

typedef struct ninlil_r7_frag_state_cu_result {
    uint8_t class_code;
    uint8_t entry_count;
    uint8_t entry_class[NINLIL_R7_FRAG_STATE_CU_MAX_ENTRIES];
} ninlil_r7_frag_state_cu_result;

ninlil_r7_frag_state_status ninlil_r7_frag_state_cu_classify(
    const ninlil_r7_frag_state_cu_entry *entries,
    size_t entry_count,
    ninlil_r7_frag_state_cu_result *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_STATE_H */
