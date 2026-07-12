#ifndef NINLIL_DOMAIN_STORE_D3S1_H
#define NINLIL_DOMAIN_STORE_D3S1_H

/*
 * D3-S1 chunk-A/B/C private exact-1 relationship context + peer-key rebuild
 * + begin_profiled_d3s1 (docs/17 §18.12).
 *
 * Production-private; not installed. Not a public C ABI.
 *
 * D3-S1 implementation boundary:
 *   - Modes 1..20 enum + fixed context layout (sizeof 421 / align 1 / ceiling 448)
 *   - Forward peer-key rebuild Modes 1–16 + Mode 17 REV_PRIMARY reverse table
 *   - Modes 18–20 local gates (attempt/index, RESULT→CALLBACK RES, retention)
 *   - begin_profiled_d3s1: modes 1..20 valid after implement; 0/>20 INVALID
 *   - Per-row evaluator Modes 1–20 after full CURRENT typed S3 success
 *     (typed_current_ok) / before previous_key+ok_count
 * The independent crossrow oracle and production bridge cover all 20 modes.
 * Stage5 D3 bind, D3-S2..S12, D3 overall, D4, and public Runtime are pending.
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

/* Closed modes 1..20 (docs/17 §18.12.1). */
typedef enum ninlil_domain_scan_d3s1_mode {
    NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_QUOTA = 1,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_SERVICE_RESERVATION = 2,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SEQUENCE_INDEX = 3,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_STATE = 4,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_IDEMPOTENCY_MAP = 5,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_RESERVATION = 6,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_SCHEDULER_OWNER = 7,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_ID_MAP = 8,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_EVENT_SPOOL = 9,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_CANCEL_STATE = 10,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESULT_CACHE = 11,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_RESERVATION = 12,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_SCHEDULER_OWNER = 13,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_DELIVERY_CANCEL_STATE = 14,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_RESERVATION = 15,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_INGRESS_SCHEDULER_OWNER = 16,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_REV_PRIMARY = 17,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_ATTEMPT_INDEX_LOCAL = 18,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES = 19,
    NINLIL_DOMAIN_SCAN_D3S1_MODE_GATE_RETENTION_BASIS = 20
} ninlil_domain_scan_d3s1_mode_t;

#define NINLIL_DOMAIN_SCAN_D3S1_MODE_MIN ((uint8_t)1u)
#define NINLIL_DOMAIN_SCAN_D3S1_MODE_MAX ((uint8_t)20u)
/* Historical chunk-A implemented max (modes 1..10). */
#define NINLIL_DOMAIN_SCAN_D3S1_MODE_CHUNK_A_MAX ((uint8_t)10u)
/* Historical chunk-B implemented max (modes 1..16). */
#define NINLIL_DOMAIN_SCAN_D3S1_MODE_CHUNK_B_MAX ((uint8_t)16u)
/* Chunk-C implemented max (modes 1..20). Stage5 D3 bind remains pending. */
#define NINLIL_DOMAIN_SCAN_D3S1_MODE_CHUNK_C_MAX ((uint8_t)20u)
#define NINLIL_DOMAIN_SCAN_D3S1_MODE_IMPLEMENTED_MAX \
    NINLIL_DOMAIN_SCAN_D3S1_MODE_CHUNK_C_MAX

/* Context flags (copy-before-get / verify control). */
#define NINLIL_DOMAIN_SCAN_D3S1_FLAG_SKIP_PEER_PVD ((uint8_t)0x01u)

#define NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_SIZE_BYTES ((uint32_t)421u)
#define NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_CEILING_BYTES ((uint32_t)448u)
#define NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY ((uint32_t)45u)
#define NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY ((uint32_t)255u)
#define NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW2_CAPACITY ((uint32_t)64u)
#define NINLIL_DOMAIN_SCAN_D3S1_SOURCE_AUX_CAPACITY ((uint32_t)16u)

/*
 * Doc-first aggregate ceilings (§18.12.5). Scanner 8192 and Stage5-alone
 * 8704 are unchanged; NEW aggregate with D3 context = 8832.
 */
#define NINLIL_DOMAIN_SCAN_D3S1_STAGE5_SEAM_ALONE_CEILING_BYTES \
    ((uint32_t)8704u)
#define NINLIL_DOMAIN_SCAN_D3S1_STAGE5_FUTURE_PACKED_BYTES ((uint32_t)8384u)
#define NINLIL_DOMAIN_SCAN_D3S1_AGGREGATE_ARENA_CEILING_BYTES ((uint32_t)8832u)
#define NINLIL_DOMAIN_SCAN_D3S1_SESSION_FUTURE_BYTES ((uint32_t)144u)
#define NINLIL_DOMAIN_SCAN_D3S1_AGGREGATE_PACKED_SUM_BYTES \
    ((uint32_t)(NINLIL_DOMAIN_SCAN_D3S1_STAGE5_FUTURE_PACKED_BYTES \
        + NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_SIZE_BYTES)) /* 8805 */

/*
 * Fixed D3 relationship context (all uint8 fields; natural align 1).
 * Separate from scanner workspace. Mutation of Storage: never.
 */
struct ninlil_domain_scan_d3s1_context {
    uint8_t expected_pvd[NINLIL_MODEL_DOMAIN_DIGEST_BYTES];
    uint8_t peer_key[NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY];
    uint8_t source_raw[NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW_CAPACITY];
    uint8_t source_raw2[NINLIL_DOMAIN_SCAN_D3S1_SOURCE_RAW2_CAPACITY];
    uint8_t source_aux[NINLIL_DOMAIN_SCAN_D3S1_SOURCE_AUX_CAPACITY];
    uint8_t peer_key_len;
    uint8_t source_raw_len;
    uint8_t source_raw2_len;
    uint8_t source_aux_len;
    uint8_t mode; /* 1..20 */
    uint8_t flags;
    uint8_t source_subtype;
    uint8_t expect_presence; /* ABSENT / PRESENT (exact_get enum) */
    uint8_t owner_kind;
};
typedef struct ninlil_domain_scan_d3s1_context ninlil_domain_scan_d3s1_context_t;

#if defined(__cplusplus)
static_assert(
    sizeof(ninlil_domain_scan_d3s1_context_t)
        == NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_SIZE_BYTES,
    "D3-S1 context sizeof must be exactly 421");
static_assert(
    sizeof(ninlil_domain_scan_d3s1_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_CEILING_BYTES,
    "D3-S1 context exceeds object ceiling 448");
static_assert(
    alignof(ninlil_domain_scan_d3s1_context_t) == 1,
    "D3-S1 context alignment must be 1");
#else
_Static_assert(
    sizeof(ninlil_domain_scan_d3s1_context_t)
        == NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_SIZE_BYTES,
    "D3-S1 context sizeof must be exactly 421");
_Static_assert(
    sizeof(ninlil_domain_scan_d3s1_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_CEILING_BYTES,
    "D3-S1 context exceeds object ceiling 448");
_Static_assert(
    _Alignof(ninlil_domain_scan_d3s1_context_t) == 1,
    "D3-S1 context alignment must be 1");
#endif

/*
 * Pure forward peer-key rebuild (Modes 1–16). KEY_DIGEST reverse forbidden.
 * out_key capacity must be >= NINLIL_DOMAIN_SCAN_D3S1_PEER_KEY_CAPACITY.
 * On success *out_key_len is 13..45. On failure out is unchanged only when
 * out pointers are NULL; otherwise out_key_len set to 0 when writable.
 */
ninlil_status_t ninlil_domain_scan_d3s1_rebuild_service_quota_key(
    const uint8_t *service_key_raw,
    uint16_t service_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_service_reservation_key(
    const uint8_t *service_key_raw,
    uint16_t service_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_sequence_index_key(
    uint64_t transaction_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_state_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
    const uint8_t *scope_raw,
    uint16_t scope_raw_length,
    const uint8_t *idempotency_key,
    uint16_t idempotency_key_length,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_reservation_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_scheduler_owner_key(
    uint64_t scheduler_owner_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_event_id_map_key(
    const uint8_t *scope_raw,
    uint16_t scope_raw_length,
    const uint8_t event_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_event_spool_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_tx_cancel_state_key(
    const uint8_t transaction_id[NINLIL_MODEL_DOMAIN_ID_BYTES],
    uint8_t *out_key,
    uint8_t *out_key_len);

/* Modes 11–14: DELIVERY source; delivery_key_raw contents exact 80. */
ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_result_cache_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_reservation_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_scheduler_owner_key(
    uint64_t scheduler_owner_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_delivery_cancel_state_key(
    const uint8_t *delivery_key_raw,
    uint16_t delivery_key_raw_length,
    uint8_t *out_key,
    uint8_t *out_key_len);

/* Modes 15–16: ORDERED_INGRESS; sequence identity is BE8. */
ninlil_status_t ninlil_domain_scan_d3s1_rebuild_ingress_reservation_key(
    uint64_t ordered_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len);

ninlil_status_t ninlil_domain_scan_d3s1_rebuild_ingress_scheduler_owner_key(
    uint64_t owner_sequence,
    uint8_t *out_key,
    uint8_t *out_key_len);

/*
 * Dispatcher: mode 1..20 rebuilds from context source_raw/raw2/aux / subtype
 * into context->peer_key / peer_key_len. Mode 17 uses closed reverse table
 * on source_subtype (+ owner_kind). Unknown mode → INVALID_ARGUMENT.
 */
ninlil_status_t ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(
    ninlil_domain_scan_d3s1_context_t *context);

/*
 * Production-private D3-S1 profiled begin (docs/17 §18.12.6).
 * Prevalidation (before mutation / Port): mode ∈ 1..20, context non-NULL,
 * pairwise disjoint session/workspace/ops/handle/candidate/context.
 * Modes 1..20: valid begin (evaluator implements all closed modes).
 * Mode 0 / >20 / alias / null: INVALID_ARGUMENT, Port 0, state unchanged.
 * Existing begin_profiled remains D2-only (bound_d3_context stays NULL).
 */
ninlil_status_t ninlil_domain_scan_begin_profiled_d3s1(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    ninlil_domain_scan_d3s1_context_t *context);

/*
 * Per-row evaluator after S3 structural success, before previous_key/ok_count.
 * Modes 1–20. Non-applicable row: OK, get 0. Port terminal: no note.
 * Presence/PVD/raw bijection finding: note_terminal_corrupt.
 * Mode 16 EXISTING_* skips peer PVD vs ingress (Mode 17 owns live PVD).
 * Mode 17: source header PVD vs primary VALUE_DIGEST (before envelope decode)
 *   + raw when current-framed (not KEY_DIGEST); future framing may skip body.
 * Mode 19: never compares reservation header PVD to RESULT value.
 * Production path only; called from process_ok_row when D3 is bound.
 */
ninlil_status_t ninlil_domain_scan_d3s1_evaluate_after_s3(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_DOMAIN_STORE_D3S1_H */
