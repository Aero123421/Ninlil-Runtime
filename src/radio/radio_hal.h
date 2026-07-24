#ifndef NINLIL_RADIO_RADIO_HAL_H
#define NINLIL_RADIO_RADIO_HAL_H

/*
 * R1: ninlil_radio_hal (H1) — production-private sole physical TX entry.
 *
 * Normative:
 *   docs/23-usb-radio-boundary.md §2, §9, §10.2 R1
 *   docs/05-security-and-compliance.md (NIN-CMP-001..005, 012, 013)
 *   docs/adr/0003-radio-usb-dependency-direction.md §3.2 / H1
 *
 * Sole physical transmit entry:
 *   ninlil_radio_hal_transmit_with_permit(...)
 * No other TX API / beacon / ACK / retry / relay / diagnostic exception path.
 * Raw SPI / SX1262 backends MUST only be reachable through the bound edge
 * callback invoked from that sole entry after permit validate+consume success.
 *
 * R1 scope:
 *   - HAL contract + host spy proof of order:
 *     digest → validate → consume → edge×1
 *   - R2-connectable opaque permit ops (validate / consume) without implementing
 *     Physical Compliance Permit authority, legal certification, or Japan profile
 *   - Production default-deny unless edge + permit + live + digest authorities
 *     are all bound (any NULL/clear → TX edge calls = 0)
 *   - Full §9.3 future bind snapshot fields (not simplified)
 *   - Call-entry immutable local plan: full permit snapshot + frame bytes
 *     (≤256) copied into HAL-owned fixed storage; validate/consume/recheck/edge
 *     use only that plan. Caller bytes/metadata are never passed to edge.
 *   - Local one-shot: after successful consume, any permit_sequence <=
 *     last_consumed_seq is rejected (monotonic, reuse forbidden). After
 *     last_consumed_seq == UINT64_MAX, further TX fail-closed.
 *
 * Nonclaims (must not be asserted by this slice):
 *   - Not R2 complete / not Physical Compliance Permit authority
 *   - Not real SX1262 / R4 / R9 SPI TX path
 *   - Not secure radio wire version (unallocated) / R6 / R7 algorithm freeze
 *   - Not Japan production RegulatoryProfile numeric values / legal TX limits
 *   - Not legal certification / RF HIL / production radio complete
 *   - Not NIN-CMP-003 compliance proof / not R2 time authority
 *   - Not R1 series complete (host candidate only)
 *   - Not public include/ninlil ABI / not installed
 *   - Not product-specific vocabulary
 *
 * Concurrency / sole owner / reentrancy:
 *   - Single owner after successful init for the object lifetime until shutdown.
 *   - No internal multi-thread locks; concurrent calls are undefined behavior.
 *   - Nested re-entry into transmit_with_permit (including from validate /
 *     consume / digest / edge callbacks) fails closed with BUSY and must not
 *     invoke a second physical edge call.
 *
 * Frame / permit plan / TOCTOU:
 *   - At call entry HAL copies permit snapshot + frame bytes into dual fixed
 *     buffers (working plan + sealed gold). Callbacks receive only working
 *     plan pointers. After each callback, working is compared to seal; mutation
 *     fails closed. Edge is invoked only with the sealed plan.
 *   - Digest verify callback is REQUIRED (R1). Algorithm id remains opaque;
 *     R6 freezes production wire digests. R1 does not fix SHA-256/AEAD.
 *   - Pointer aliasing fail-closed order (no field dereference of untrusted
 *     frame before containers are cleared):
 *     (A) Fixed-size overlap of permit object / frame-view object / out_error
 *         vs HAL and each other — before any frame->bytes/length read. Unsafe
 *         out_error: write 0 (last_error only).
 *     (B) Copy frame fields to local scalars; null / zero / max checks.
 *     (C) Bounded frame-bytes range vs HAL / permit / out_error / frame-view.
 *     (D) length mismatch vs permit.frame_byte_length + structural validation.
 *     Early errors: zero mutation of caller/HAL authority fields except
 *     stats/last_error (and in_transmit only while an attempt is entered).
 *   - Overlap checks use uintptr_t arithmetic; payload size only after bound.
 *
 * Shutdown (idempotent when already SHUTDOWN / idle):
 *   - Clears HAL-owned plans (working+seal), live binding, all ops/ctx, bound
 *     flags. One-shot watermark (has_consumed_seq / last_consumed_seq) is also
 *     cleared: a new watermark domain begins only after a later init_object.
 *   - Subsequent transmit → INVALID_STATE until init_object.
 *
 * Structural (R1 freeze — not Japan legal authority):
 *   - Reject zero-length frames, oversize, length mismatch, seq 0, reserved
 *     nonzero, phy_flags nonzero, zero IDs, zero bandwidth / SF / CR denom /
 *     max_airtime, expiry <= not_before. Does NOT invent region channel lists,
 *     certified power ceilings, or LBT timing values.
 *
 * Storage: fixed, bounded, no heap, no VLA. Strict C11 portable.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SX1262-class packet ceiling; R1 does not claim production wire layout. */
#define NINLIL_RADIO_HAL_MAX_FRAME_BYTES ((uint32_t)256u)
#define NINLIL_RADIO_HAL_ID_BYTES ((size_t)16u)
#define NINLIL_RADIO_HAL_DIGEST_BYTES ((size_t)32u)
#define NINLIL_RADIO_HAL_HINT_BYTES ((size_t)160u)

/*
 * Size / alignment contracts (do not confuse minimum with actual):
 *   NINLIL_RADIO_HAL_OBJECT_BYTES — fixed size ceiling (sizeof actual <=).
 *   NINLIL_RADIO_HAL_OBJECT_ALIGN — public minimum alignment guarantee.
 *   ninlil_radio_hal_object_size() — actual sizeof(ninlil_radio_hal_t).
 *   ninlil_radio_hal_object_align() — actual _Alignof(ninlil_radio_hal_t)
 *     (may be > OBJECT_ALIGN when the complete type requires it).
 */
#define NINLIL_RADIO_HAL_OBJECT_BYTES ((size_t)2048u)
#define NINLIL_RADIO_HAL_OBJECT_ALIGN ((size_t)8u)

typedef uint32_t ninlil_radio_hal_status_t;

#define NINLIL_RADIO_HAL_OK ((ninlil_radio_hal_status_t)0u)
#define NINLIL_RADIO_HAL_INVALID_ARGUMENT ((ninlil_radio_hal_status_t)1u)
#define NINLIL_RADIO_HAL_INVALID_STATE ((ninlil_radio_hal_status_t)2u)
#define NINLIL_RADIO_HAL_DEFAULT_DENY ((ninlil_radio_hal_status_t)3u)
#define NINLIL_RADIO_HAL_PERMIT_DENIED ((ninlil_radio_hal_status_t)4u)
#define NINLIL_RADIO_HAL_PERMIT_ERROR ((ninlil_radio_hal_status_t)5u)
/*
 * Consume non-OK closed partition (R2 seam ABI — fixed, not "R2 later"):
 *
 * CONSUME_DENIED — only consume-callback status that is definitely unconsumed
 *   (no working-plan mutation). HAL does not burn local watermark; same
 *   permit_sequence may be retried. PERMIT_DENIED is validate-side only and
 *   MUST NOT be treated as consume retryable if returned from consume.
 *
 * CONSUME_FENCED — authority permanently fenced this permit (or durable
 *   consume already applied). HAL burns local watermark; same sequence must
 *   not authorize another TX. Edge is never called.
 *
 * CONSUME_ERROR — contract/invalid consume result. Treated as CONSUME_FENCED
 *   for watermark purposes (fail-closed). NOT a retryable "commit unknown".
 *
 * NOT_BEFORE / EXPIRED — pre-consume time reject is validate-stage (before
 *   consume callback); watermark unchanged. If consume returns them, HAL
 *   fail-closed burns sealed seq (not a retryable consume deny).
 *
 * PERMIT_DENIED / DEFAULT_DENY / PERMIT_ERROR / unknown / any other non-OK
 *   from consume — terminal burn sealed seq, edge 0; same seq not retryable.
 *
 * There is NO consume-unknown / commit-unknown status. R2 MUST NOT return
 * ambiguous durable-commit-unknown as a retryable non-OK.
 *
 * Plan mutation during consume is a callback contract fault: terminal
 * sealed-seq burn for every status (including CONSUME_DENIED).
 */
#define NINLIL_RADIO_HAL_CONSUME_DENIED ((ninlil_radio_hal_status_t)6u)
#define NINLIL_RADIO_HAL_CONSUME_ERROR ((ninlil_radio_hal_status_t)7u)
#define NINLIL_RADIO_HAL_EDGE_ERROR ((ninlil_radio_hal_status_t)8u)
#define NINLIL_RADIO_HAL_BUSY ((ninlil_radio_hal_status_t)9u)
#define NINLIL_RADIO_HAL_FRAME_MISMATCH ((ninlil_radio_hal_status_t)10u)
#define NINLIL_RADIO_HAL_NOT_BEFORE ((ninlil_radio_hal_status_t)11u)
#define NINLIL_RADIO_HAL_EXPIRED ((ninlil_radio_hal_status_t)12u)
#define NINLIL_RADIO_HAL_SEQ_REUSE ((ninlil_radio_hal_status_t)13u)
#define NINLIL_RADIO_HAL_LIVE_MISMATCH ((ninlil_radio_hal_status_t)14u)
#define NINLIL_RADIO_HAL_UNSUPPORTED ((ninlil_radio_hal_status_t)15u)
#define NINLIL_RADIO_HAL_SEQ_EXHAUSTED ((ninlil_radio_hal_status_t)16u)
#define NINLIL_RADIO_HAL_CONSUME_FENCED ((ninlil_radio_hal_status_t)17u)

typedef uint32_t ninlil_radio_hal_stage_t;

#define NINLIL_RADIO_HAL_STAGE_NONE ((ninlil_radio_hal_stage_t)0u)
#define NINLIL_RADIO_HAL_STAGE_INIT ((ninlil_radio_hal_stage_t)1u)
#define NINLIL_RADIO_HAL_STAGE_BIND ((ninlil_radio_hal_stage_t)2u)
#define NINLIL_RADIO_HAL_STAGE_ARGS ((ninlil_radio_hal_stage_t)3u)
#define NINLIL_RADIO_HAL_STAGE_LIVE ((ninlil_radio_hal_stage_t)4u)
#define NINLIL_RADIO_HAL_STAGE_TIME ((ninlil_radio_hal_stage_t)5u)
#define NINLIL_RADIO_HAL_STAGE_DIGEST ((ninlil_radio_hal_stage_t)6u)
#define NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE ((ninlil_radio_hal_stage_t)7u)
#define NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME ((ninlil_radio_hal_stage_t)8u)
#define NINLIL_RADIO_HAL_STAGE_TOCTOU ((ninlil_radio_hal_stage_t)9u)
#define NINLIL_RADIO_HAL_STAGE_EDGE ((ninlil_radio_hal_stage_t)10u)
#define NINLIL_RADIO_HAL_STAGE_OWNER ((ninlil_radio_hal_stage_t)11u)
#define NINLIL_RADIO_HAL_STAGE_SHUTDOWN ((ninlil_radio_hal_stage_t)12u)
#define NINLIL_RADIO_HAL_STAGE_PLAN ((ninlil_radio_hal_stage_t)13u)

/*
 * Closed tagged reason domain (structured fact; not free-form strings).
 * Production logs must not emit secrets or full frame payloads.
 */
typedef uint32_t ninlil_radio_hal_reason_t;

#define NINLIL_RADIO_HAL_REASON_NONE ((ninlil_radio_hal_reason_t)0u)
#define NINLIL_RADIO_HAL_REASON_NULL_ARG ((ninlil_radio_hal_reason_t)1u)
#define NINLIL_RADIO_HAL_REASON_ZERO_LENGTH ((ninlil_radio_hal_reason_t)2u)
#define NINLIL_RADIO_HAL_REASON_OVERSIZE ((ninlil_radio_hal_reason_t)3u)
#define NINLIL_RADIO_HAL_REASON_LENGTH_MISMATCH ((ninlil_radio_hal_reason_t)4u)
#define NINLIL_RADIO_HAL_REASON_UNBOUND_EDGE ((ninlil_radio_hal_reason_t)5u)
#define NINLIL_RADIO_HAL_REASON_UNBOUND_PERMIT ((ninlil_radio_hal_reason_t)6u)
#define NINLIL_RADIO_HAL_REASON_DEFAULT_DENY ((ninlil_radio_hal_reason_t)7u)
#define NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY ((ninlil_radio_hal_reason_t)8u)
#define NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR ((ninlil_radio_hal_reason_t)9u)
#define NINLIL_RADIO_HAL_REASON_CONSUME_DENY ((ninlil_radio_hal_reason_t)10u)
#define NINLIL_RADIO_HAL_REASON_CONSUME_ERROR ((ninlil_radio_hal_reason_t)11u)
#define NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED \
    ((ninlil_radio_hal_reason_t)41u)
#define NINLIL_RADIO_HAL_REASON_CONSUME_FENCED \
    ((ninlil_radio_hal_reason_t)42u)
#define NINLIL_RADIO_HAL_REASON_EDGE_FAIL ((ninlil_radio_hal_reason_t)12u)
#define NINLIL_RADIO_HAL_REASON_REENTRANT ((ninlil_radio_hal_reason_t)13u)
#define NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH ((ninlil_radio_hal_reason_t)14u)
#define NINLIL_RADIO_HAL_REASON_FRAME_MUTATED ((ninlil_radio_hal_reason_t)15u)
#define NINLIL_RADIO_HAL_REASON_NOT_BEFORE ((ninlil_radio_hal_reason_t)16u)
#define NINLIL_RADIO_HAL_REASON_EXPIRED ((ninlil_radio_hal_reason_t)17u)
#define NINLIL_RADIO_HAL_REASON_SEQ_ZERO ((ninlil_radio_hal_reason_t)18u)
#define NINLIL_RADIO_HAL_REASON_SEQ_REUSE ((ninlil_radio_hal_reason_t)19u)
#define NINLIL_RADIO_HAL_REASON_LIVE_HW_ID ((ninlil_radio_hal_reason_t)20u)
#define NINLIL_RADIO_HAL_REASON_LIVE_HW_REV ((ninlil_radio_hal_reason_t)21u)
#define NINLIL_RADIO_HAL_REASON_LIVE_REG_ID ((ninlil_radio_hal_reason_t)22u)
#define NINLIL_RADIO_HAL_REASON_LIVE_REG_REV ((ninlil_radio_hal_reason_t)23u)
#define NINLIL_RADIO_HAL_REASON_LIVE_SITE_ID ((ninlil_radio_hal_reason_t)24u)
#define NINLIL_RADIO_HAL_REASON_LIVE_SITE_REV ((ninlil_radio_hal_reason_t)25u)
#define NINLIL_RADIO_HAL_REASON_LIVE_SITE_EPOCH ((ninlil_radio_hal_reason_t)26u)
#define NINLIL_RADIO_HAL_REASON_LIVE_TX_ID ((ninlil_radio_hal_reason_t)27u)
#define NINLIL_RADIO_HAL_REASON_LIVE_CHANNEL ((ninlil_radio_hal_reason_t)28u)
#define NINLIL_RADIO_HAL_REASON_LIVE_PHY ((ninlil_radio_hal_reason_t)29u)
#define NINLIL_RADIO_HAL_REASON_LIVE_AIRTIME ((ninlil_radio_hal_reason_t)30u)
#define NINLIL_RADIO_HAL_REASON_NOT_ACTIVE ((ninlil_radio_hal_reason_t)31u)
#define NINLIL_RADIO_HAL_REASON_SHUTDOWN ((ninlil_radio_hal_reason_t)32u)
#define NINLIL_RADIO_HAL_REASON_COUNTER_SAT ((ninlil_radio_hal_reason_t)33u)
#define NINLIL_RADIO_HAL_REASON_UNBOUND_LIVE ((ninlil_radio_hal_reason_t)34u)
#define NINLIL_RADIO_HAL_REASON_UNBOUND_DIGEST ((ninlil_radio_hal_reason_t)35u)
#define NINLIL_RADIO_HAL_REASON_SEQ_EXHAUSTED ((ninlil_radio_hal_reason_t)36u)
#define NINLIL_RADIO_HAL_REASON_ALIAS ((ninlil_radio_hal_reason_t)37u)
#define NINLIL_RADIO_HAL_REASON_ZERO_ID ((ninlil_radio_hal_reason_t)38u)
#define NINLIL_RADIO_HAL_REASON_STRUCT_INVALID ((ninlil_radio_hal_reason_t)39u)
#define NINLIL_RADIO_HAL_REASON_PLAN_MUTATED ((ninlil_radio_hal_reason_t)40u)

typedef struct ninlil_radio_hal_id {
    uint8_t bytes[NINLIL_RADIO_HAL_ID_BYTES];
} ninlil_radio_hal_id_t;

/*
 * PHY parameters bound into the permit (profile-range values).
 * Exact Japan/legal numeric meaning is NOT claimed in R1.
 */
typedef struct ninlil_radio_hal_phy {
    uint32_t bandwidth_hz;
    uint8_t spreading_factor;
    uint8_t coding_rate_denom; /* CR = 4/coding_rate_denom when non-zero */
    uint16_t preamble_symbols;
    int32_t tx_power_mdb; /* millidBm; profile units opaque to HAL */
    uint32_t phy_flags;   /* reserved closed bits; must be 0 in R1 */
} ninlil_radio_hal_phy_t;

/*
 * Physical Compliance Permit binding snapshot (docs/23 §9.3 / NIN-CMP-001).
 * All future bind fields are present; R1 does NOT implement R2 issuance
 * authority. Values are re-validated at consume time against live + frame.
 *
 * Time fields (not_before_ms / expiry_ms) are permit-domain timestamps.
 * Compliance time authority is owned by R2 permit ops via ctx-authoritative
 * clock domain (MUST). R1 HAL does not accept caller now as compliance proof
 * and does not claim NIN-CMP-003 completion.
 */
typedef struct ninlil_radio_hal_permit_snapshot {
    ninlil_radio_hal_id_t hardware_profile_id;
    uint32_t hardware_profile_rev;

    ninlil_radio_hal_id_t regulatory_profile_id;
    uint32_t regulatory_profile_rev;

    ninlil_radio_hal_id_t site_assignment_id;
    uint32_t site_assignment_rev;
    uint64_t site_assignment_epoch;

    ninlil_radio_hal_id_t transmitter_id;
    uint32_t channel_id;
    ninlil_radio_hal_phy_t phy;

    uint8_t frame_digest[NINLIL_RADIO_HAL_DIGEST_BYTES];
    /*
     * Digest algorithm id: 0 = unspecified / host-test only.
     * Production wire algorithm is unallocated until R6; do not treat nonzero
     * as a fixed production suite in R1.
     */
    uint32_t frame_digest_algorithm;
    uint32_t frame_byte_length;

    uint32_t max_airtime_us;
    uint64_t not_before_ms;
    uint64_t expiry_ms;

    /* Monotonic permit sequence; zero is invalid; reuse forbidden after consume. */
    uint64_t permit_sequence;
    uint32_t reserved_zero;
} ninlil_radio_hal_permit_snapshot_t;

/*
 * Live radio / profile binding held by the sole owner for H1 re-validation.
 * REQUIRED for any TX (unbound live → default-deny).
 * Set via ninlil_radio_hal_set_live_binding. Every transmit re-checks §9.3
 * fields against this snapshot (independent mismatch reasons).
 */
typedef struct ninlil_radio_hal_live_binding {
    ninlil_radio_hal_id_t hardware_profile_id;
    uint32_t hardware_profile_rev;
    ninlil_radio_hal_id_t regulatory_profile_id;
    uint32_t regulatory_profile_rev;
    ninlil_radio_hal_id_t site_assignment_id;
    uint32_t site_assignment_rev;
    uint64_t site_assignment_epoch;
    ninlil_radio_hal_id_t transmitter_id;
    uint32_t channel_id;
    ninlil_radio_hal_phy_t phy;
    uint32_t max_airtime_us; /* current ledger-conservative ceiling for plan */
    uint32_t reserved_zero;
} ninlil_radio_hal_live_binding_t;

/* Caller-owned immutable frame view at call entry (copied immediately). */
typedef struct ninlil_radio_hal_frame_view {
    const uint8_t *bytes;
    uint32_t length;
} ninlil_radio_hal_frame_view_t;

typedef struct ninlil_radio_hal_error {
    ninlil_radio_hal_status_t status;
    ninlil_radio_hal_stage_t stage;
    ninlil_radio_hal_reason_t reason;
    uint32_t reserved_zero;
    char hint[NINLIL_RADIO_HAL_HINT_BYTES];
} ninlil_radio_hal_error_t;

/* Saturating private measurement snapshot (no secrets / no payload bytes). */
typedef struct ninlil_radio_hal_stats {
    uint64_t attempts;
    uint64_t default_deny;
    uint64_t invalid_argument;
    uint64_t invalid_state;
    uint64_t live_mismatch;
    uint64_t time_reject;
    uint64_t digest_reject;
    uint64_t permit_validate_ok;
    uint64_t permit_validate_deny;
    uint64_t permit_validate_error;
    uint64_t permit_consume_ok;
    uint64_t permit_consume_deny;   /* definitely unconsumed */
    uint64_t permit_consume_error;  /* terminal fail-closed (fenced) */
    uint64_t permit_consume_fenced; /* terminal fenced consume outcomes */
    uint64_t toctou_reject;
    uint64_t edge_calls;
    uint64_t edge_ok;
    uint64_t edge_error;
    uint64_t seq_reuse;
    uint64_t reentrant_reject;
    uint64_t success;
    uint64_t plan_mutated;
    uint64_t alias_reject;
    uint64_t seq_exhausted;
} ninlil_radio_hal_stats_t;

/*
 * Physical TX edge (D1 backend or host spy). Invoked at most once per
 * successful validate+consume path, with the sealed local plan only.
 * MUST NOT call back into transmit_with_permit (reentrancy → BUSY).
 */
typedef struct ninlil_radio_hal_edge_ops {
    ninlil_radio_hal_status_t (*transmit)(
        void *ctx,
        const ninlil_radio_hal_permit_snapshot_t *permit,
        const ninlil_radio_hal_frame_view_t *frame,
        ninlil_radio_hal_error_t *out_error);
} ninlil_radio_hal_edge_ops_t;

/*
 * R2-connectable Physical Compliance Permit seam (opaque authority).
 * R1 does not implement issuance / ledger / legal authority.
 * Production default: unbound → DEFAULT_DENY, exact zero edge calls.
 *
 * validate: pure re-check; MUST NOT consume or durable-side-effect.
 * consume: one-shot single-use; MUST be the last authority callback before
 *   edge (after live/digest/plan re-validation complete).
 *
 * Consume return contract (closed partition; ABI fixed in R1):
 *   OK              — consumed; HAL burns watermark; edge may proceed.
 *   CONSUME_DENIED  — only retryable non-OK from consume; no watermark burn
 *                     (no plan mutation). PERMIT_DENIED is NOT retryable here.
 *   CONSUME_FENCED  — terminal fence; burn watermark; edge 0.
 *   CONSUME_ERROR   — terminal fence (as FENCED for watermark); edge 0.
 *   SEQ_REUSE       — burn watermark if not already; edge 0.
 *   PERMIT_DENIED / DEFAULT_DENY / PERMIT_ERROR / NOT_BEFORE / EXPIRED /
 *   unknown / any other non-OK from consume — fail-closed FENCED burn;
 *   same seq not retry-eligible. (Pre-consume NOT_BEFORE/EXPIRED are
 *   validate-stage time rejects with watermark unchanged — separate path.)
 *   MUST NOT invent commit-unknown / LOST_UNKNOWN as retryable consume.
 *   Plan mutation during consume: terminal burn sealed seq for ALL statuses.
 *
 * Time (NIN-CMP-003 domain):
 *   validate/consume MUST sample authoritative time only from ctx-owned
 *   trusted clock domain (R2). There is no caller-supplied now_ms on this
 *   seam or on transmit_with_permit. Application wall/app time is not
 *   compliance authority. R1 host spy simulates ctx clock for tests only.
 *
 * Both receive the working local plan (not raw caller storage after entry).
 */
typedef struct ninlil_radio_hal_permit_ops {
    ninlil_radio_hal_status_t (*validate)(
        void *ctx,
        const ninlil_radio_hal_permit_snapshot_t *permit,
        const ninlil_radio_hal_frame_view_t *frame,
        ninlil_radio_hal_error_t *out_error);
    ninlil_radio_hal_status_t (*consume)(
        void *ctx,
        const ninlil_radio_hal_permit_snapshot_t *permit,
        const ninlil_radio_hal_frame_view_t *frame,
        ninlil_radio_hal_error_t *out_error);
} ninlil_radio_hal_permit_ops_t;

/*
 * REQUIRED digest re-verify seam (immutable plan / TOCTOU closure).
 * Algorithm is not fixed in R1 (R6 wire freeze). Unbound → default-deny.
 * Host spy may implement a test-only fold.
 */
typedef struct ninlil_radio_hal_digest_ops {
    ninlil_radio_hal_status_t (*verify)(
        void *ctx,
        const ninlil_radio_hal_frame_view_t *frame,
        const uint8_t digest[NINLIL_RADIO_HAL_DIGEST_BYTES],
        uint32_t digest_algorithm,
        ninlil_radio_hal_error_t *out_error);
} ninlil_radio_hal_digest_ops_t;

/*
 * Complete production-private HAL object (C11 effective type).
 *
 * The object type IS the actual HAL struct — no opaque uint8_t storage
 * union and no cast from declared byte storage to struct ninlil_radio_hal*
 * (that pattern is outside C11 effective-type guarantees). Private header
 * completeness is intentional: this is not public include/ninlil ABI.
 *
 * NINLIL_RADIO_HAL_OBJECT_BYTES is a fixed OBJECT_BYTES ceiling only
 * (sizeof(struct) <= ceiling). Callers allocate ninlil_radio_hal_object_t
 * (or ninlil_radio_hal_t — same type) on stack/static/heap; no type-pun buffer.
 */
struct ninlil_radio_hal {
    uint32_t magic;
    uint32_t lifecycle;
    uint32_t in_transmit;
    uint32_t edge_bound;
    uint32_t permit_bound;
    uint32_t digest_bound;
    uint32_t live_bound;
    uint32_t has_consumed_seq;
    uint32_t reserved_zero;
    uint64_t last_consumed_seq;

    ninlil_radio_hal_edge_ops_t edge_ops;
    void *edge_ctx;
    ninlil_radio_hal_permit_ops_t permit_ops;
    void *permit_ctx;
    ninlil_radio_hal_digest_ops_t digest_ops;
    void *digest_ctx;
    ninlil_radio_hal_live_binding_t live;

    ninlil_radio_hal_permit_snapshot_t plan_permit;
    ninlil_radio_hal_permit_snapshot_t seal_permit;
    uint8_t plan_frame[NINLIL_RADIO_HAL_MAX_FRAME_BYTES];
    uint8_t seal_frame[NINLIL_RADIO_HAL_MAX_FRAME_BYTES];
    ninlil_radio_hal_frame_view_t plan_view;
    ninlil_radio_hal_frame_view_t seal_view;

    ninlil_radio_hal_stats_t stats;
    ninlil_radio_hal_error_t last_error;
};

typedef struct ninlil_radio_hal ninlil_radio_hal_t;
/* Object storage type: the actual HAL (no type-pun buffer). */
typedef ninlil_radio_hal_t ninlil_radio_hal_object_t;

/*
 * Explicit member-zero initializer for first init_object.
 *
 * C11: `{0}` zeros all named members of the complete struct. It does NOT
 * guarantee that padding bytes of an automatic object are zero. First init
 * therefore checks semantic members/tags only — never full representation
 * padding. Equivalent member-zero paths: this macro, or field-wise zero, or
 * static storage duration zero-init. `memset` of the whole object also works
 * but is stronger than the required member-zero precondition.
 *
 * Usage:
 *   ninlil_radio_hal_object_t obj = NINLIL_RADIO_HAL_OBJECT_INIT;
 *   ninlil_radio_hal_t *hal = NULL;
 *   status = ninlil_radio_hal_init_object(&obj, &hal);
 */
#define NINLIL_RADIO_HAL_OBJECT_INIT {0}

/* Actual sizeof the HAL object type (≤ OBJECT_BYTES ceiling). */
size_t ninlil_radio_hal_object_size(void);
/* Actual _Alignof(ninlil_radio_hal_t); ≥ OBJECT_ALIGN minimum. */
size_t ninlil_radio_hal_object_align(void);

/* Compile-time alignment / size contracts. */
_Static_assert(
    NINLIL_RADIO_HAL_OBJECT_ALIGN >= 8u,
    "OBJECT_ALIGN minimum must be at least 8");
_Static_assert(
    _Alignof(ninlil_radio_hal_object_t) >= NINLIL_RADIO_HAL_OBJECT_ALIGN,
    "object type actual align must meet OBJECT_ALIGN minimum");
_Static_assert(
    sizeof(ninlil_radio_hal_t) <= NINLIL_RADIO_HAL_OBJECT_BYTES,
    "radio_hal object exceeds fixed OBJECT_BYTES ceiling");
_Static_assert(
    _Alignof(ninlil_radio_hal_t) <= _Alignof(max_align_t),
    "ninlil_radio_hal actual alignment exceeds max_align_t");
_Static_assert(
    offsetof(struct ninlil_radio_hal, magic) == 0u,
    "magic must be first field for byte-safe tag load");
_Static_assert(
    offsetof(struct ninlil_radio_hal, lifecycle) == sizeof(uint32_t),
    "lifecycle must follow magic with no padding");

/*
 * Init places the object in ACTIVE with no edge/permit/digest/live bound.
 * Contract (semantic member zero first; no representation/padding scan):
 *   - out_hal must not alias object storage (checked before any write).
 *   - First init precondition: all named members are semantic-zero
 *     (magic==0, lifecycle==ZERO, unbound ops/ctx, empty plans/stats, …)
 *     via NINLIL_RADIO_HAL_OBJECT_INIT / member zero / static zero-init.
 *     Padding is not part of the precondition (not C11-guaranteed by {0}).
 *   - Re-init after SHUTDOWN only (MAGIC+SHUTDOWN via byte-safe tag load).
 *   - ACTIVE re-init → INVALID_STATE (preserves one-shot watermark domain).
 *   - Semantic poison (wrong tags or non-fresh non-SHUTDOWN members) →
 *     INVALID_STATE. Arbitrary padding-only raw bytes are not a reject reason.
 *   - After SHUTDOWN re-init, watermark domain restarts.
 *   - *out_hal points at the object itself (same effective type).
 */
ninlil_radio_hal_status_t ninlil_radio_hal_init_object(
    ninlil_radio_hal_object_t *object,
    ninlil_radio_hal_t **out_hal);

/*
 * Bind physical edge. Required before any successful TX.
 * Replaces prior edge. NULL ops → unbind (default-deny).
 */
ninlil_radio_hal_status_t ninlil_radio_hal_bind_edge(
    ninlil_radio_hal_t *hal,
    const ninlil_radio_hal_edge_ops_t *ops,
    void *ctx,
    ninlil_radio_hal_error_t *out_error);

/*
 * Bind R2 permit seam. NULL ops → production default-deny (TX 0).
 */
ninlil_radio_hal_status_t ninlil_radio_hal_bind_permit_ops(
    ninlil_radio_hal_t *hal,
    const ninlil_radio_hal_permit_ops_t *ops,
    void *ctx,
    ninlil_radio_hal_error_t *out_error);

/*
 * Bind REQUIRED digest re-verify seam. NULL clears → default-deny.
 */
ninlil_radio_hal_status_t ninlil_radio_hal_bind_digest_ops(
    ninlil_radio_hal_t *hal,
    const ninlil_radio_hal_digest_ops_t *ops,
    void *ctx,
    ninlil_radio_hal_error_t *out_error);

/*
 * Set or clear live binding. live == NULL clears → default-deny on TX.
 * Structural validation applied at set (zero IDs / reserved / zero PHY core).
 */
ninlil_radio_hal_status_t ninlil_radio_hal_set_live_binding(
    ninlil_radio_hal_t *hal,
    const ninlil_radio_hal_live_binding_t *live,
    ninlil_radio_hal_error_t *out_error);

/*
 * Sole physical transmit-with-permit entry (docs/23 §9.2 step 3).
 *
 * Order (R1 host candidate; not R2/NIN-CMP complete):
 *   alias/args → authorities bound → monotonic seq → copy dual plan (working+seal) →
 *   structural → live → digest(working only) → plan==seal →
 *   validate(working only) → plan==seal →
 *   consume(working only; last authority callback) → plan==seal → watermark seal seq →
 *   local plan==seal only (no external digest/permit) → edge×1 on **seal only**.
 * Seal storage is never passed to digest/validate/consume (const-cast mutation
 * of working cannot silently become TX payload).
 *
 * No caller now_ms: compliance expiry/not-before is enforced only inside
 * permit validate/consume via ctx authoritative clock (R2 seam). HAL does not
 * claim NIN-CMP-003 production compliance proof.
 *
 * Fail closed: exact zero edge on any pre-edge failure. After successful
 * consume, edge error still leaves the permit non-reusable.
 *
 * R1 is a host implementation candidate only — not R1 series complete.
 */
ninlil_radio_hal_status_t ninlil_radio_hal_transmit_with_permit(
    ninlil_radio_hal_t *hal,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error);

void ninlil_radio_hal_stats(
    const ninlil_radio_hal_t *hal,
    ninlil_radio_hal_stats_t *out_stats);

void ninlil_radio_hal_last_error(
    const ninlil_radio_hal_t *hal,
    ninlil_radio_hal_error_t *out_error);

/*
 * Idempotent shutdown: wipe plans/live/ops/ctx and clear one-shot watermark;
 * lifecycle → SHUTDOWN. Subsequent transmit → INVALID_STATE until init_object.
 */
ninlil_radio_hal_status_t ninlil_radio_hal_shutdown(
    ninlil_radio_hal_t *hal,
    ninlil_radio_hal_error_t *out_error);

/* Saturating u64 add for stats (public for host fixtures; no heap). */
static inline uint64_t ninlil_radio_hal_sat_add_u64(uint64_t a, uint64_t b)
{
    uint64_t sum;

    if (a == UINT64_MAX || b == UINT64_MAX) {
        return UINT64_MAX;
    }
    sum = a + b;
    if (sum < a) {
        return UINT64_MAX;
    }
    return sum;
}

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_RADIO_HAL_H */
