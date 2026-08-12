/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_R7_FRAG_H
#define NINLIL_R7_FRAG_H

/*
 * R7 private NRW1 LINK / FRAG / reassembly candidate (docs/30, ADR-0010).
 *
 * SEMANTIC: R7_FRAG_PRIVATE_CANDIDATE_ONLY
 * SEMANTIC: WIRE_PROFILE_ID_0x11
 * SEMANTIC: KIND_DATA_AND_LINK_ACK_ONLY
 * SEMANTIC: HOP_DATA_ACK_SEPARATE_CRYPTO_LANES
 * SEMANTIC: FRAG_START_CONT_ACK_TYPES
 * SEMANTIC: FRAG_COUNT_EFFECTIVE_MAX_13
 * SEMANTIC: FRAG_DUAL_UNIQUE_INDEX_HANDLE_AND_TRANSFER_ID
 * SEMANTIC: FRAG_CONFLICT_NO_REPLACE_EXISTING
 * SEMANTIC: CONTENT_DIGEST_SHA256_REASSEMBLED
 * SEMANTIC: FRAG_TOMBSTONE_FINGERPRINT
 * SEMANTIC: TOMBSTONE_VOLATILE_ON_RESTART
 * SEMANTIC: COMMIT_UNKNOWN_RECOVERY_EXACT
 * SEMANTIC: NO_PARTIAL_PUBLICATION
 * SEMANTIC: R7_FRAG_PUBLIC_ABI_UNCHANGED
 *
 * Production-private under src/radio/r7_frag/. Not public ABI. Not installed.
 * Not HIL. Not full W1/L1/N6/R2/R5. Uses approved r7_crypto_* only for AEAD.
 * wire_profile_id remains 0x11; Accepted offsets are immutable.
 *
 * Heap-free, no VLA, C11. Failure: caller mutation zero / no partial publish.
 */

#include "r7_crypto_provider.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Fixed wire domains (docs/30 §§6–7, §11–12) — immutable Accepted pins        */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_FRAG_PROFILE_ID ((uint8_t)0x11u)

#define NINLIL_R7_FRAG_OUTER_KIND_DATA ((uint8_t)1u)
#define NINLIL_R7_FRAG_OUTER_KIND_LINK_ACK ((uint8_t)2u)

#define NINLIL_R7_FRAG_E2E_TYPE_SINGLE ((uint8_t)1u)
#define NINLIL_R7_FRAG_E2E_TYPE_START ((uint8_t)2u)
#define NINLIL_R7_FRAG_E2E_TYPE_CONT ((uint8_t)3u)
#define NINLIL_R7_FRAG_E2E_TYPE_ACK ((uint8_t)4u)

#define NINLIL_R7_FRAG_OUTER_AAD_LEN ((size_t)19u)
#define NINLIL_R7_FRAG_E2E_AAD_LEN ((size_t)14u)
#define NINLIL_R7_FRAG_TAG_LEN ((size_t)16u)

#define NINLIL_R7_FRAG_LINK_ACK_PT_LEN ((size_t)16u)
#define NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN ((size_t)51u)

#define NINLIL_R7_FRAG_START_HDR_LEN ((size_t)64u)
#define NINLIL_R7_FRAG_CONT_HDR_LEN ((size_t)10u)
#define NINLIL_R7_FRAG_ACK_PT_LEN ((size_t)14u)

#include "r7_frag_profile.h"

#define NINLIL_R7_FRAG_S_MIN ((size_t)1u)
#define NINLIL_R7_FRAG_C_MIN ((size_t)1u)
#define NINLIL_R7_FRAG_C_MAX ((size_t)180u)
#define NINLIL_R7_FRAG_TOTAL_LEN_MAX NINLIL_R7_FRAG_TOTAL_MAX
#define NINLIL_R7_FRAG_COUNT_MIN ((uint16_t)2u)
/* CONT_UNIT / S_MAX / COUNT_MAX / capacity / timers from r7_frag_profile.h */

#define NINLIL_R7_FRAG_ACK_CODE_ACCEPTED_BATCH ((uint8_t)0u)

#define NINLIL_R7_FRAG_STATUS_PARTIAL ((uint8_t)0u)
#define NINLIL_R7_FRAG_STATUS_COMPLETE ((uint8_t)1u)
#define NINLIL_R7_FRAG_STATUS_ABORT ((uint8_t)2u)

#define NINLIL_R7_FRAG_REASON_NONE ((uint8_t)0u)
#define NINLIL_R7_FRAG_REASON_CONFLICT ((uint8_t)1u)
#define NINLIL_R7_FRAG_REASON_DIGEST ((uint8_t)2u)
#define NINLIL_R7_FRAG_REASON_RESOURCE ((uint8_t)3u)
#define NINLIL_R7_FRAG_REASON_TIMEOUT ((uint8_t)4u)
#define NINLIL_R7_FRAG_REASON_FENCED ((uint8_t)5u)

#define NINLIL_R7_FRAG_REASM_PAYLOAD_BUDGET NINLIL_R7_FRAG_PAYLOAD_BUDGET
#define NINLIL_R7_FRAG_LANE_SLOTS ((size_t)8u)
#define NINLIL_R7_FRAG_LINK_GROUP_SLOTS ((size_t)64u)
#define NINLIL_R7_FRAG_TX_BLOCK ((uint64_t)64u)

#define NINLIL_R7_FRAG_TOMBSTONE_CANON_LEN NINLIL_R7_FRAG_TOMBSTONE_CANON
#define NINLIL_R7_FRAG_FINGERPRINT_LEN ((size_t)32u)
#define NINLIL_R7_FRAG_TRANSFER_ID_LEN ((size_t)16u)

#define NINLIL_R7_FRAG_IDLE_TIMEOUT_MS NINLIL_R7_FRAG_IDLE_MS
#define NINLIL_R7_FRAG_MAX_HOP_ATTEMPTS NINLIL_R7_FRAG_HOP_ATTEMPT_MAX

/* Lane kinds for private TX/RX state. */
#define NINLIL_R7_FRAG_LANE_HOP_DATA ((uint8_t)1u)
#define NINLIL_R7_FRAG_LANE_HOP_ACK ((uint8_t)2u)
#define NINLIL_R7_FRAG_LANE_E2E ((uint8_t)3u)

/* COMMIT_UNKNOWN classifier outcomes (docs/30 §9.3). */
#define NINLIL_R7_FRAG_CU_RETRY_LATER ((uint8_t)1u)
#define NINLIL_R7_FRAG_CU_ALL_OLD ((uint8_t)2u)
#define NINLIL_R7_FRAG_CU_ALL_PROPOSED ((uint8_t)3u)
#define NINLIL_R7_FRAG_CU_THIRD ((uint8_t)4u)
#define NINLIL_R7_FRAG_CU_CORRUPT ((uint8_t)5u)

#define NINLIL_R7_FRAG_CU_ENTRY_OLD ((uint8_t)1u)
#define NINLIL_R7_FRAG_CU_ENTRY_PROPOSED ((uint8_t)2u)
#define NINLIL_R7_FRAG_CU_ENTRY_THIRD ((uint8_t)3u)

#define NINLIL_R7_FRAG_CU_MAX_ENTRIES ((size_t)32u)
#define NINLIL_R7_FRAG_CU_VALUE_MAX ((size_t)256u)
#define NINLIL_R7_FRAG_CU_KEY_MAX ((size_t)255u)

/* Restart snapshot magic / version (private volatile only). */
#define NINLIL_R7_FRAG_SNAP_MAGIC ((uint32_t)0x52374653u) /* "R7FS" */
#define NINLIL_R7_FRAG_SNAP_VERSION ((uint16_t)1u)

/* -------------------------------------------------------------------------- */
/* Closed status catalog                                                      */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_FRAG_OK ((int32_t)0)
#define NINLIL_R7_FRAG_INVALID_ARGUMENT ((int32_t)1)
#define NINLIL_R7_FRAG_STRUCTURAL ((int32_t)2)
#define NINLIL_R7_FRAG_LENGTH_CLASS ((int32_t)3)
#define NINLIL_R7_FRAG_CAPACITY ((int32_t)4)
#define NINLIL_R7_FRAG_ALIAS ((int32_t)5)
#define NINLIL_R7_FRAG_AUTH_FAILED ((int32_t)6)
#define NINLIL_R7_FRAG_BACKEND_FAILED ((int32_t)7)
#define NINLIL_R7_FRAG_INTERNAL_CONTRACT ((int32_t)8)
#define NINLIL_R7_FRAG_REPLAY ((int32_t)9)
#define NINLIL_R7_FRAG_DUPLICATE ((int32_t)10)
#define NINLIL_R7_FRAG_CONFLICT ((int32_t)11)
#define NINLIL_R7_FRAG_RESOURCE ((int32_t)12)
#define NINLIL_R7_FRAG_TIMEOUT ((int32_t)13)
#define NINLIL_R7_FRAG_FENCED ((int32_t)14)
#define NINLIL_R7_FRAG_COMMIT_UNKNOWN ((int32_t)15)
#define NINLIL_R7_FRAG_NO_TRANSFER ((int32_t)16)
#define NINLIL_R7_FRAG_EXACT_RETRY ((int32_t)17)
#define NINLIL_R7_FRAG_PUBLISHED ((int32_t)18)

typedef int32_t ninlil_r7_frag_status;

/* -------------------------------------------------------------------------- */
/* Wire field types                                                           */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_frag_outer_data_fields {
    uint8_t ack_requested; /* 0|1 */
    uint8_t hop_remaining;
    uint32_t hop_context_id;
    uint64_t hop_counter;
    uint16_t route_handle;
    uint16_t route_generation;
} ninlil_r7_frag_outer_data_fields;

typedef struct ninlil_r7_frag_outer_link_ack_fields {
    uint32_t hop_context_id; /* reverse ACK-lane context */
    uint64_t hop_counter;    /* ACK-lane counter */
} ninlil_r7_frag_outer_link_ack_fields;

typedef struct ninlil_r7_frag_link_ack_body {
    uint32_t acked_hop_context_id;
    uint64_t ack_base_counter;
    uint16_t ack_bitmap;
    uint8_t ack_code; /* ACCEPTED_BATCH=0 only */
} ninlil_r7_frag_link_ack_body;

typedef struct ninlil_r7_frag_e2e_fields {
    uint8_t e2e_type; /* START/CONT/ACK high nibble value 2/3/4 */
    uint32_t e2e_context_id;
    uint64_t e2e_counter;
} ninlil_r7_frag_e2e_fields;

typedef struct ninlil_r7_frag_start_body {
    uint8_t transfer_id[NINLIL_R7_FRAG_TRANSFER_ID_LEN];
    uint64_t transfer_handle;
    uint32_t total_len;
    uint16_t frag_count;
    uint16_t continuation_unit; /* exact 180 */
    uint8_t content_digest[32];
} ninlil_r7_frag_start_body;

typedef struct ninlil_r7_frag_cont_body {
    uint64_t transfer_handle;
    uint16_t frag_index; /* 1..frag_count-1 */
} ninlil_r7_frag_cont_body;

typedef struct ninlil_r7_frag_ack_body {
    uint64_t transfer_handle;
    uint16_t frag_count;
    uint16_t received_bitmap;
    uint8_t status;
    uint8_t reason;
} ninlil_r7_frag_ack_body;

/* -------------------------------------------------------------------------- */
/* Fragmentation plan                                                         */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_frag_chunk_plan {
    uint16_t frag_index; /* 0=START, 1..=CONT */
    uint16_t offset;
    uint16_t length;
} ninlil_r7_frag_chunk_plan;

typedef struct ninlil_r7_frag_plan {
    uint32_t total_len;
    uint16_t frag_count;
    uint16_t first_chunk_len; /* S */
    uint16_t cont_unit;       /* 180 */
    ninlil_r7_frag_chunk_plan chunks[NINLIL_R7_FRAG_COUNT_MAX];
} ninlil_r7_frag_plan;

/* -------------------------------------------------------------------------- */
/* Private lane / reassembly / link / restart state                           */
/* -------------------------------------------------------------------------- */

typedef struct ninlil_r7_frag_lane {
    uint8_t in_use;
    uint8_t lane_kind; /* HOP_DATA / HOP_ACK / E2E */
    uint32_t context_id;
    uint64_t key_generation;
    /* TX exclusive reservation (docs/30 §9). */
    uint64_t tx_reserved_exclusive;
    uint64_t tx_ram_next;
    uint64_t tx_ram_limit;
    uint8_t tx_fenced;
    /* RX sliding-64 (docs/30 §10). */
    uint64_t rx_accept_reserved_through;
    uint64_t rx_boot_floor;
    uint64_t rx_ram_highest;
    uint64_t rx_bitmap;
    uint8_t rx_fenced;
} ninlil_r7_frag_lane;

typedef struct ninlil_r7_frag_tombstone {
    uint8_t in_use;
    uint32_t e2e_context_id;
    uint8_t transfer_id[NINLIL_R7_FRAG_TRANSFER_ID_LEN];
    uint64_t transfer_handle;
    uint16_t frag_count;
    uint8_t status;
    uint8_t reason;
    uint8_t fingerprint[NINLIL_R7_FRAG_FINGERPRINT_LEN];
    uint64_t expiry_mono;
} ninlil_r7_frag_tombstone;

typedef struct ninlil_r7_frag_reasm_slot {
    uint8_t in_use;
    uint8_t published; /* 1 after COMPLETE upper handoff once */
    uint32_t e2e_context_id;
    uint8_t transfer_id[NINLIL_R7_FRAG_TRANSFER_ID_LEN];
    uint64_t transfer_handle;
    uint32_t total_len;
    uint16_t frag_count;
    uint16_t first_chunk_len;
    uint8_t content_digest[32];
    uint8_t fingerprint[NINLIL_R7_FRAG_FINGERPRINT_LEN];
    uint16_t bitmap; /* bit0=START */
    uint64_t receiver_start_mono;
    uint64_t receiver_absolute_deadline;
    uint64_t idle_deadline;
    uint64_t partial_ack_due;
    uint8_t payload[NINLIL_R7_FRAG_TOTAL_LEN_MAX];
    uint8_t chunk_seen[NINLIL_R7_FRAG_COUNT_MAX];
    uint16_t chunk_len[NINLIL_R7_FRAG_COUNT_MAX];
} ninlil_r7_frag_reasm_slot;

typedef struct ninlil_r7_frag_link_group {
    uint8_t in_use;
    uint8_t ack_requested;
    uint8_t hop_attempts;
    uint8_t completed; /* 1 after covering LINK_ACK or UNACKED success */
    uint32_t hop_data_context_id;
    uint64_t e2e_counter_fixed;
    uint16_t e2e_blob_len;
    uint8_t e2e_blob[220];
    uint64_t group_start_mono;
    uint64_t group_absolute_deadline;
    uint64_t enclosing_owner_deadline;
    uint64_t last_tx_mono;
    uint64_t eligible_at;
    uint64_t pending_hop_counters[NINLIL_R7_FRAG_MAX_HOP_ATTEMPTS];
    uint8_t pending_count;
} ninlil_r7_frag_link_group;

typedef struct ninlil_r7_frag_engine {
    ninlil_r7_frag_lane lanes[NINLIL_R7_FRAG_LANE_SLOTS];
    ninlil_r7_frag_reasm_slot reasm[NINLIL_R7_FRAG_REASM_SLOTS];
    ninlil_r7_frag_tombstone tombs[NINLIL_R7_FRAG_TOMBSTONE_SLOTS];
    ninlil_r7_frag_link_group links[NINLIL_R7_FRAG_LINK_GROUP_SLOTS];
    size_t payload_bytes_in_use;
    uint8_t global_fence;
    uint64_t now_mono;
    /* Publication staging: app payload only after COMPLETE commit. */
    uint8_t pub_valid;
    uint32_t pub_e2e_context_id;
    uint64_t pub_transfer_handle;
    uint32_t pub_total_len;
    uint8_t pub_payload[NINLIL_R7_FRAG_TOTAL_LEN_MAX];
    uint32_t publish_count; /* exact-once counter for tests */
} ninlil_r7_frag_engine;

/* Restart snapshot header + opaque body (volatile only; tombstones discarded). */
typedef struct ninlil_r7_frag_restart_header {
    uint32_t magic;
    uint16_t version;
    uint16_t lane_count;
    uint16_t reasm_count;
    uint16_t link_count;
    uint64_t now_mono;
    uint8_t global_fence;
    uint8_t reserved0;
    uint16_t reserved1;
} ninlil_r7_frag_restart_header;

/* COMMIT_UNKNOWN classifier entry (abstraction over storage get results). */
typedef struct ninlil_r7_frag_cu_entry {
    uint8_t old_present;
    uint8_t proposed_present;
    uint16_t key_len;
    uint16_t old_len;
    uint16_t proposed_len;
    uint8_t key[NINLIL_R7_FRAG_CU_KEY_MAX];
    uint8_t old_bytes[NINLIL_R7_FRAG_CU_VALUE_MAX];
    uint8_t proposed_bytes[NINLIL_R7_FRAG_CU_VALUE_MAX];
    /* Observed durable value after COMMIT_UNKNOWN (caller supplies). */
    uint8_t observed_status; /* 0=OK found, 1=NOT_FOUND, 2=BUSY, 3=IO, 4=OTHER */
    uint16_t observed_len;
    uint8_t observed_bytes[NINLIL_R7_FRAG_CU_VALUE_MAX];
} ninlil_r7_frag_cu_entry;

typedef struct ninlil_r7_frag_cu_result {
    uint8_t class_code; /* CU_* */
    uint8_t entry_class[NINLIL_R7_FRAG_CU_MAX_ENTRIES];
    uint8_t entry_count;
} ninlil_r7_frag_cu_result;

/* -------------------------------------------------------------------------- */
/* Fragmentation plan API                                                     */
/* -------------------------------------------------------------------------- */

/*
 * Build a canonical fragmentation plan for total_len in 2..2048 that cannot
 * fit SINGLE (or any total_len >= 2 requiring multi-fragment).
 *
 * Positive boundaries:
 *   - empty rejected (total_len 0)
 *   - total_len 1 with force_single_path out of domain for FRAG (need S < total)
 *   - all total_len in 2..2048 with maximal S strategy (S=min(126, total_len-1))
 *
 * Returns OK and fills plan, or LENGTH_CLASS / INVALID_ARGUMENT.
 */
ninlil_r7_frag_status ninlil_r7_frag_plan_build(
    uint32_t total_len,
    ninlil_r7_frag_plan *out_plan);

/* Validate an existing START-derived plan against total_len/S/frag_count. */
ninlil_r7_frag_status ninlil_r7_frag_plan_validate(
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint16_t frag_count,
    uint16_t continuation_unit);

/* -------------------------------------------------------------------------- */
/* LINK_ACK body / outer wire                                                 */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_link_ack_body_validate(
    const ninlil_r7_frag_link_ack_body *body);

ninlil_r7_frag_status ninlil_r7_frag_pack_link_ack_body(
    const ninlil_r7_frag_link_ack_body *body,
    uint8_t out16[NINLIL_R7_FRAG_LINK_ACK_PT_LEN]);

ninlil_r7_frag_status ninlil_r7_frag_parse_link_ack_body(
    const uint8_t in16[NINLIL_R7_FRAG_LINK_ACK_PT_LEN],
    ninlil_r7_frag_link_ack_body *out_body);

ninlil_r7_frag_status ninlil_r7_frag_seal_outer_link_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t ack_key16[16],
    const uint8_t ack_iv12[12],
    const ninlil_r7_frag_outer_link_ack_fields *outer,
    const ninlil_r7_frag_link_ack_body *body,
    uint8_t out_frame[NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN],
    size_t *out_len);

ninlil_r7_frag_status ninlil_r7_frag_open_outer_link_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t ack_key16[16],
    const uint8_t ack_iv12[12],
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_frag_outer_link_ack_fields *out_outer,
    ninlil_r7_frag_link_ack_body *out_body);

/* -------------------------------------------------------------------------- */
/* FRAG E2E seal/open (START / CONT / ACK)                                    */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_seal_e2e_start(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_frag_e2e_fields *fields,
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_frag_status ninlil_r7_frag_open_e2e_start(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields,
    ninlil_r7_frag_start_body *out_body,
    uint8_t *out_first_chunk,
    size_t out_capacity,
    size_t *out_first_len);

ninlil_r7_frag_status ninlil_r7_frag_seal_e2e_cont(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_frag_e2e_fields *fields,
    const ninlil_r7_frag_cont_body *body,
    const uint8_t *chunk,
    size_t chunk_len,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_frag_status ninlil_r7_frag_open_e2e_cont(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields,
    ninlil_r7_frag_cont_body *out_body,
    uint8_t *out_chunk,
    size_t out_capacity,
    size_t *out_chunk_len);

ninlil_r7_frag_status ninlil_r7_frag_seal_e2e_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_frag_e2e_fields *fields,
    const ninlil_r7_frag_ack_body *body,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_frag_status ninlil_r7_frag_open_e2e_ack(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields,
    ninlil_r7_frag_ack_body *out_body);

/* Outer DATA wrapping any FRAG E2E blob (uses hop DATA lane keys). */
ninlil_r7_frag_status ninlil_r7_frag_seal_outer_data(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t data_key16[16],
    const uint8_t data_iv12[12],
    const ninlil_r7_frag_outer_data_fields *fields,
    const uint8_t *e2e_blob,
    size_t e2e_blob_len,
    uint8_t *out_frame,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_frag_status ninlil_r7_frag_open_outer_data(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t data_key16[16],
    const uint8_t data_iv12[12],
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_frag_outer_data_fields *out_fields,
    uint8_t *out_e2e_blob,
    size_t out_capacity,
    size_t *out_len);

/* Structural-only E2E header parse of HopPT (relay path; no Open). */
ninlil_r7_frag_status ninlil_r7_frag_structural_e2e_header(
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_frag_e2e_fields *out_fields);

/* START manifest fingerprint (docs/30 §12.1). */
ninlil_r7_frag_status ninlil_r7_frag_start_fingerprint(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    uint8_t out_fp32[32]);

/* content_digest = SHA-256(reassembled[0..total_len)). */
ninlil_r7_frag_status ninlil_r7_frag_content_digest(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t *payload,
    size_t total_len,
    uint8_t out_digest32[32]);

/* -------------------------------------------------------------------------- */
/* Private engine: lanes, reassembly, link groups, restart                    */
/* -------------------------------------------------------------------------- */

void ninlil_r7_frag_engine_init(ninlil_r7_frag_engine *eng);
void ninlil_r7_frag_engine_zeroize(ninlil_r7_frag_engine *eng);
void ninlil_r7_frag_engine_set_now(ninlil_r7_frag_engine *eng, uint64_t now_mono);

/* Install a lane (heap-free slot). key_generation domain 1..MAX. */
ninlil_r7_frag_status ninlil_r7_frag_lane_install(
    ninlil_r7_frag_engine *eng,
    uint8_t lane_kind,
    uint32_t context_id,
    uint64_t key_generation,
    size_t *out_slot);

ninlil_r7_frag_status ninlil_r7_frag_lane_find(
    const ninlil_r7_frag_engine *eng,
    uint8_t lane_kind,
    uint32_t context_id,
    size_t *out_slot);

/* TX allocate/burn (docs/30 §9) — in-RAM private candidate. */
ninlil_r7_frag_status ninlil_r7_frag_lane_tx_allocate(
    ninlil_r7_frag_engine *eng,
    size_t slot,
    uint64_t *out_counter);

/* RX precheck before AEAD (docs/30 §10). */
ninlil_r7_frag_status ninlil_r7_frag_lane_rx_precheck(
    const ninlil_r7_frag_engine *eng,
    size_t slot,
    uint64_t counter);

/* RX admit after AEAD success. */
ninlil_r7_frag_status ninlil_r7_frag_lane_rx_admit(
    ninlil_r7_frag_engine *eng,
    size_t slot,
    uint64_t counter);

/* Simulate sticky fence on lane (COMMIT_UNKNOWN path). */
void ninlil_r7_frag_lane_fence(ninlil_r7_frag_engine *eng, size_t slot);

/* -------------------------------------------------------------------------- */
/* Receiver reassembly path                                                   */
/* -------------------------------------------------------------------------- */

/*
 * Admit opened START body into reassembly. Dual-index conflict rules apply.
 * Returns EXACT_RETRY for same-fingerprint active/tombstone; CONFLICT else.
 * On first admit reserves tombstone capacity; RESOURCE if full.
 */
ninlil_r7_frag_status ninlil_r7_frag_reasm_admit_start(
    ninlil_r7_frag_engine *eng,
    const ninlil_r7_crypto_provider *provider,
    uint32_t e2e_context_id,
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    ninlil_r7_frag_ack_body *out_ack_intent);

/*
 * Admit opened CONT. CONT-before-START => NO_TRANSFER.
 * Duplicate same bytes => DUPLICATE (no mutation); different => CONFLICT tombstone.
 */
ninlil_r7_frag_status ninlil_r7_frag_reasm_admit_cont(
    ninlil_r7_frag_engine *eng,
    const ninlil_r7_crypto_provider *provider,
    uint32_t e2e_context_id,
    const ninlil_r7_frag_cont_body *body,
    const uint8_t *chunk,
    size_t chunk_len,
    ninlil_r7_frag_ack_body *out_ack_intent);

/* Tick timeouts / idle / tombstone expiry. */
ninlil_r7_frag_status ninlil_r7_frag_reasm_tick(
    ninlil_r7_frag_engine *eng,
    uint64_t now_mono);

/*
 * Take published payload exactly once after COMPLETE (no partial publish).
 * Returns PUBLISHED when a new publication is available; clears pub_valid.
 */
ninlil_r7_frag_status ninlil_r7_frag_take_publication(
    ninlil_r7_frag_engine *eng,
    uint32_t *out_e2e_context_id,
    uint64_t *out_transfer_handle,
    uint8_t *out_payload,
    size_t out_capacity,
    size_t *out_len);

/* FRAG_ACK RX validation against a live outgoing transfer (sender side). */
ninlil_r7_frag_status ninlil_r7_frag_ack_rx_validate(
    uint16_t expected_frag_count,
    uint64_t expected_handle,
    const ninlil_r7_frag_ack_body *body);

/* -------------------------------------------------------------------------- */
/* LINK group (DATA sender hop retry with bit-identical E2E blob)             */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_link_group_admit(
    ninlil_r7_frag_engine *eng,
    uint32_t hop_data_context_id,
    uint8_t ack_requested,
    uint64_t e2e_counter_fixed,
    const uint8_t *e2e_blob,
    size_t e2e_blob_len,
    uint64_t enclosing_owner_deadline,
    size_t *out_group);

/* Record a hop air attempt (consume+edge done) with allocated hop counter. */
ninlil_r7_frag_status ninlil_r7_frag_link_group_note_air(
    ninlil_r7_frag_engine *eng,
    size_t group,
    uint64_t hop_counter,
    uint64_t tx_mono);

/* True if now allows next hop retry (eligible_at / attempts / deadlines). */
ninlil_r7_frag_status ninlil_r7_frag_link_group_retry_ready(
    const ninlil_r7_frag_engine *eng,
    size_t group,
    uint64_t now_mono);

/* Apply validated LINK_ACK covering any pending hop counter. */
ninlil_r7_frag_status ninlil_r7_frag_link_group_apply_ack(
    ninlil_r7_frag_engine *eng,
    size_t group,
    const ninlil_r7_frag_link_ack_body *body);

/* Complete UNACKED path (ack_requested=0 after edge). */
ninlil_r7_frag_status ninlil_r7_frag_link_group_unacked_success(
    ninlil_r7_frag_engine *eng,
    size_t group);

/* -------------------------------------------------------------------------- */
/* Restart snapshot codec (volatile; tombstones not restored)                 */
/* -------------------------------------------------------------------------- */

/*
 * Encode a compact restart snapshot of lanes + link groups only.
 * Reassembly and tombstones are intentionally omitted (volatile restart).
 * out_len set only on success.
 */
ninlil_r7_frag_status ninlil_r7_frag_restart_encode(
    const ninlil_r7_frag_engine *eng,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

/*
 * Decode into a fresh engine. Does not restore reassembly/tombstones/publication.
 * Old/new/partial/extra/third classes of malformed snapshots fail closed.
 */
ninlil_r7_frag_status ninlil_r7_frag_restart_decode(
    ninlil_r7_frag_engine *eng,
    const uint8_t *in,
    size_t in_len);

/* -------------------------------------------------------------------------- */
/* COMMIT_UNKNOWN classifier abstraction (docs/30 §9.3 pure)                  */
/* -------------------------------------------------------------------------- */

/*
 * Pure classifier over copy-owned write-set + observed durable values.
 * No storage I/O. Classifies ALL_OLD / ALL_PROPOSED / THIRD / CORRUPT / RETRY.
 * observed_status=2 BUSY or 3 IO with empty observation => RETRY_LATER.
 */
ninlil_r7_frag_status ninlil_r7_frag_cu_classify(
    const ninlil_r7_frag_cu_entry *entries,
    size_t entry_count,
    ninlil_r7_frag_cu_result *out);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_FRAG_H */
