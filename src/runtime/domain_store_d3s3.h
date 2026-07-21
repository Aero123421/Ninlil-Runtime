#ifndef NINLIL_DOMAIN_STORE_D3S3_H
#define NINLIL_DOMAIN_STORE_D3S3_H

/*
 * D3-S3 private BLOB lifecycle / chunk stream context
 * (docs/17 §18.14).
 *
 * Production-private; not installed. Not a public C ABI.
 *
 * D3-S3 implementation boundary (this slice):
 *   - Fixed context layout (sizeof 754 / align 1 / ceiling 768)
 *   - Closed modes 27..30 (k₃=4; 1 session = 1 mode = 1 READ_ONLY txn)
 *   - begin_profiled_d3s3 prevalidation (mode ∈ 27..30; dual-bound forbidden)
 *   - KEY_DIGEST digest-match SCAN single arm (no reverse / no rebuild exact_get)
 *   - Known-index chunk stream + owner PVD pins + Mode28 dual re-SCAN
 *   - Mode29 APPLICATION_FIRST RESULT_CACHE setup; Mode30 #14/#15/#16
 *   - BIND reverse + untyped orphan; mutation 0
 * Stage5 D3 bind, D3-S4..S12, D3 overall, D4, and public Runtime are pending.
 * Does not re-claim D3-S1/S2 success. Does not rewrite §18.14 historical freeze.
 */

#include <stddef.h>
#include <stdint.h>

#include <ninlil/platform.h>
#include <ninlil/runtime.h>

#include "domain_store_codec.h"
#include "runtime_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations — avoid circular include with domain_store_scanner.h. */
typedef struct ninlil_domain_scan_session ninlil_domain_scan_session_t;
typedef struct ninlil_domain_scan_workspace ninlil_domain_scan_workspace_t;

/* Closed modes 27..30 (docs/17 §18.14.2). */
typedef enum ninlil_domain_scan_d3s3_mode {
    NINLIL_DOMAIN_SCAN_D3S3_MODE_TX_PAYLOAD_BLOB = 27,
    NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB = 28,
    NINLIL_DOMAIN_SCAN_D3S3_MODE_DLV_PAYLOAD_BLOB = 29,
    NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB = 30
} ninlil_domain_scan_d3s3_mode_t;

#define NINLIL_DOMAIN_SCAN_D3S3_MODE_MIN ((uint8_t)27u)
#define NINLIL_DOMAIN_SCAN_D3S3_MODE_MAX ((uint8_t)30u)
#define NINLIL_DOMAIN_SCAN_D3S3_MODE_IMPLEMENTED_MAX \
    NINLIL_DOMAIN_SCAN_D3S3_MODE_MAX

/* Pass kinds (§18.14.5; same spirit as S2). */
#define NINLIL_DOMAIN_SCAN_D3S3_PASS_BASELINE ((uint8_t)0u)
#define NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL ((uint8_t)1u)

/* Lifecycle class (§18.14.6). */
#define NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE ((uint8_t)0u)
#define NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED ((uint8_t)1u)
#define NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT ((uint8_t)2u)
#define NINLIL_DOMAIN_SCAN_D3S3_LIFE_ILLEGAL_CARRIER ((uint8_t)3u)

/* Phase machine (§18.14.4). */
typedef enum ninlil_domain_scan_d3s3_phase {
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_IDLE = 0,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_BASELINE = 1,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER = 2,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN = 3,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF = 4,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS = 5,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B = 6,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_OWNER_PVD_PROOF_B = 7,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS_B = 8,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET = 9,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK = 10,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST = 11,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_CHUNK = 12,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE = 13,
    NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED = 14
} ninlil_domain_scan_d3s3_phase_t;

/* flags bits (private drive coordination + complete). */
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE ((uint8_t)0x01u)
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE ((uint8_t)0x02u)
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_BIND_PHASE_ACTIVE ((uint8_t)0x04u)
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_COMPLETE_READY ((uint8_t)0x08u)
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN ((uint8_t)0x10u)
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_CARRIER_INSTALLED ((uint8_t)0x20u)
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED ((uint8_t)0x40u)
#define NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_DUPLICATE ((uint8_t)0x80u)

/*
 * count_complete_mask / binding_complete_mask (§18.14.12):
 * count bit0 MANIFEST, bit1 CHUNKS, bit2 SEMANTIC;
 * binding bit3 MANIFEST, bit4 CHUNK.
 */
#define NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST ((uint8_t)0x01u)
#define NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS ((uint8_t)0x02u)
#define NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC ((uint8_t)0x04u)
#define NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_MANIFEST ((uint8_t)0x08u)
#define NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_CHUNK ((uint8_t)0x10u)

#define NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_SIZE_BYTES ((uint32_t)754u)
#define NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_CEILING_BYTES ((uint32_t)768u)
#define NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY ((uint32_t)45u)
#define NINLIL_DOMAIN_SCAN_D3S3_FOCUS_RAW_CAPACITY ((uint32_t)80u)
#define NINLIL_DOMAIN_SCAN_D3S3_TX_ID_BYTES ((uint32_t)16u)
#define NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES ((uint32_t)32u)
#define NINLIL_DOMAIN_SCAN_D3S3_RECEIPT_EVIDENCE_CAPACITY ((uint32_t)128u)

/*
 * Doc-first aggregate ceilings (§18.14.13). Scanner 8192 and Stage5-alone
 * 8704 unchanged. Outer future aggregate when S1+S2+S3 co-resident = 9920.
 */
#define NINLIL_DOMAIN_SCAN_D3S3_STAGE5_SEAM_ALONE_CEILING_BYTES \
    ((uint32_t)8704u)
#define NINLIL_DOMAIN_SCAN_D3S3_STAGE5_FUTURE_PACKED_BYTES ((uint32_t)8384u)
#define NINLIL_DOMAIN_SCAN_D3S3_S1_CONTEXT_CEILING_BYTES ((uint32_t)448u)
#define NINLIL_DOMAIN_SCAN_D3S3_S2_CONTEXT_CEILING_BYTES ((uint32_t)320u)
#define NINLIL_DOMAIN_SCAN_D3S3_OUTER_AGGREGATE_CEILING_BYTES \
    ((uint32_t)9920u)
#define NINLIL_DOMAIN_SCAN_D3S3_AGGREGATE_PACKED_SUM_BYTES \
    ((uint32_t)(NINLIL_DOMAIN_SCAN_D3S3_STAGE5_FUTURE_PACKED_BYTES \
        + 421u + 306u + NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_SIZE_BYTES)) /* 9865 */

/*
 * Fixed D3-S3 BLOB multipass context (all uint8 fields; natural align 1).
 * Exact offsets per docs/17 §18.14.12. Mutation of Storage: never.
 */
struct ninlil_domain_scan_d3s3_context {
    uint8_t last_carrier_key[NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY];
    uint8_t last_carrier_key_len;
    uint8_t focus_raw80[NINLIL_DOMAIN_SCAN_D3S3_FOCUS_RAW_CAPACITY];
    uint8_t focus_raw_len;
    uint8_t focus_id16[NINLIL_DOMAIN_SCAN_D3S3_TX_ID_BYTES];
    uint8_t focus_key_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t blob_id_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t content_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t owner_primary_key_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t expected_manifest_value_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t total_length[8];
    uint8_t chunk_count[4];
    uint8_t next_chunk_index[4];
    uint8_t length_sum[8];
    uint8_t sha_state[32];
    uint8_t sha_bitcount[8];
    uint8_t sha_block[64];
    uint8_t sha_block_len;
    uint8_t peer_key[NINLIL_DOMAIN_SCAN_D3S3_PEER_KEY_CAPACITY];
    uint8_t peer_key_len;
    uint8_t owner_kind;
    uint8_t blob_kind;
    uint8_t expected_live;
    uint8_t observed_live;
    uint8_t lifecycle_class;
    uint8_t phase;
    uint8_t pass_kind;
    uint8_t flags;
    uint8_t count_complete_mask;
    uint8_t binding_complete_mask;
    uint8_t focus_mode;
    uint8_t focus_sub;
    uint8_t semantic_pass;
    uint8_t reply_kind;
    uint8_t view_a_key_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t view_b_key_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t expected_owner_pvd[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t expected_semantic_digest[NINLIL_DOMAIN_SCAN_D3S3_DIGEST_BYTES];
    uint8_t receipt_evidence_bytes[NINLIL_DOMAIN_SCAN_D3S3_RECEIPT_EVIDENCE_CAPACITY];
    uint8_t receipt_evidence_len;
    uint8_t pad0;
    uint8_t pinned_receipt_stage[4];
};
typedef struct ninlil_domain_scan_d3s3_context ninlil_domain_scan_d3s3_context_t;

#if defined(__cplusplus)
static_assert(
    sizeof(ninlil_domain_scan_d3s3_context_t)
        == NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_SIZE_BYTES,
    "D3-S3 context sizeof must be exactly 754");
static_assert(
    sizeof(ninlil_domain_scan_d3s3_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_CEILING_BYTES,
    "D3-S3 context exceeds object ceiling 768");
static_assert(
    alignof(ninlil_domain_scan_d3s3_context_t) == 1,
    "D3-S3 context alignment must be 1");
#else
_Static_assert(
    sizeof(ninlil_domain_scan_d3s3_context_t)
        == NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_SIZE_BYTES,
    "D3-S3 context sizeof must be exactly 754");
_Static_assert(
    sizeof(ninlil_domain_scan_d3s3_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_CEILING_BYTES,
    "D3-S3 context exceeds object ceiling 768");
_Static_assert(
    _Alignof(ninlil_domain_scan_d3s3_context_t) == 1,
    "D3-S3 context alignment must be 1");
#endif

/*
 * Production-private D3-S3 profiled begin (docs/17 §18.14.14).
 * Prevalidation (before mutation / Port): mode ∈ 27..30, context non-NULL,
 * pairwise disjoint session/workspace/ops/handle/candidate/context,
 * context within object ceiling. Success: focus_mode := mode (immutable),
 * baseline D2 once (PASS_BASELINE), phase BASELINE.
 * Violation: Port 0, INVALID_ARGUMENT, state unchanged.
 * Dual-bound with D3-S1/S2 forbidden. begin_profiled remains D2-only;
 * begin_profiled_d3s1 modes 1..20; begin_profiled_d3s2 modes 21..26.
 */
ninlil_status_t ninlil_domain_scan_begin_profiled_d3s3(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    ninlil_domain_scan_d3s3_context_t *context);

/*
 * Same-txn sequential zero-prefix iterator reopen (shared with D3-S2;
 * docs/17 §18.14.14). Declared here so S3 does not depend on d3s2.h.
 */
ninlil_status_t ninlil_domain_scan_reopen_zero_prefix_iter(
    ninlil_domain_scan_session_t *session);

/*
 * S3 phase-machine drive (docs/17 §18.14.5 B0–B11 mapping).
 * May call advance with caller budget; known-index CHUNKS / OWNER_PVD /
 * SEMANTIC do not consume row_budget. row_budget==0 → INVALID_ARGUMENT.
 */
ninlil_status_t ninlil_domain_scan_d3s3_drive(
    ninlil_domain_scan_session_t *session,
    uint32_t row_budget);

/*
 * H1: after S3 success under PASS_INTERNAL, before previous_key update.
 * SELECT / FOCUS SCAN / BIND predicates. Must not touch frozen D2 counters.
 */
ninlil_status_t ninlil_domain_scan_d3s3_on_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t typed_current_ok);

/*
 * H2: inside advance after true EXHAUSTED, before return OK.
 * FOCUS_MANIFEST_SCAN / BIND stream close.
 */
ninlil_status_t ninlil_domain_scan_d3s3_on_exhausted(
    ninlil_domain_scan_session_t *session);

/* Required mask helpers (pure; mode-scoped). */
uint8_t ninlil_domain_scan_d3s3_required_count_mask(uint8_t focus_mode);
uint8_t ninlil_domain_scan_d3s3_required_binding_mask(uint8_t focus_mode);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_DOMAIN_STORE_D3S3_H */
