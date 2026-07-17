#ifndef NINLIL_RADIO_PROFILE_LOADER_H
#define NINLIL_RADIO_PROFILE_LOADER_H

/*
 * R5 LAB_ONLY Hardware/Regulatory profile loader + full §9.3 permit bind.
 *
 * Normative: docs/29-r5-lab-only-profile-loader.md + ADR-0009.
 * Not public include/ninlil. Not FIELD/PRODUCTION/Japan legal/HIL complete.
 *
 * SEMANTIC: R5_HOST_CANDIDATE_ONLY
 * SEMANTIC: LAB_ONLY_FAIL_CLOSED
 * SEMANTIC: FULL_BIND_MATRIX_ISSUE_AND_CONSUME
 * SEMANTIC: NO_JAPAN_PRODUCTION_NUMERIC_CLAIM
 * SEMANTIC: R2_DURABLE_SCHEMA1_UNCHANGED
 * SEMANTIC: BIND_ITEM_SINGLE_MISMATCH_DENY
 * SEMANTIC: R2_ASSIGNMENT_GENERATION_SYNC
 */

#include "airtime_calculator.h"
#include "pcp_authority.h"
#include "radio_hal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_R5_SCHEMA_VERSION ((uint16_t)1u)
#define NINLIL_R5_HW_DOC_BYTES ((size_t)128u)
#define NINLIL_R5_REG_DOC_BYTES ((size_t)160u)
#define NINLIL_R5_HW_MAGIC ((uint32_t)0x31504857u)  /* LE 'WHP1' */
#define NINLIL_R5_REG_MAGIC ((uint32_t)0x31505247u) /* LE 'GRP1' */
#define NINLIL_R5_ID_BYTES ((size_t)16u)
#define NINLIL_R5_DIGEST_BYTES ((size_t)32u)
#define NINLIL_R5_MAX_OUTSTANDING ((uint32_t)8u)
#define NINLIL_R5_OBJECT_BYTES ((size_t)4096u)
#define NINLIL_R5_OBJECT_ALIGN ((size_t)8u)
#define NINLIL_R5_HINT_BYTES ((size_t)160u)

/* Approval: LAB_ONLY only (docs/29 §2.2). */
#define NINLIL_R5_APPROVAL_LAB_ONLY ((uint8_t)1u)
#define NINLIL_R5_APPROVAL_CANDIDATE ((uint8_t)2u)
#define NINLIL_R5_APPROVAL_DEPLOYMENT_APPROVED ((uint8_t)3u)
#define NINLIL_R5_APPROVAL_REVOKED ((uint8_t)4u)

typedef uint32_t ninlil_r5_status_t;
typedef uint32_t ninlil_r5_reason_t;
typedef uint32_t ninlil_r5_stage_t;
typedef uint32_t ninlil_r5_bind_item_t;

#define NINLIL_R5_OK ((ninlil_r5_status_t)0u)
#define NINLIL_R5_INVALID_ARGUMENT ((ninlil_r5_status_t)1u)
#define NINLIL_R5_INVALID_STATE ((ninlil_r5_status_t)2u)
#define NINLIL_R5_STRUCT ((ninlil_r5_status_t)3u)
#define NINLIL_R5_PROFILE_DENIED ((ninlil_r5_status_t)4u)
#define NINLIL_R5_BIND_MISMATCH ((ninlil_r5_status_t)5u)
#define NINLIL_R5_CAPACITY ((ninlil_r5_status_t)6u)
#define NINLIL_R5_BUSY_OUTSTANDING ((ninlil_r5_status_t)7u)
#define NINLIL_R5_AIRTIME ((ninlil_r5_status_t)8u)
#define NINLIL_R5_PCP ((ninlil_r5_status_t)9u)
#define NINLIL_R5_REGISTRY_MISS ((ninlil_r5_status_t)10u)
#define NINLIL_R5_UNSUPPORTED ((ninlil_r5_status_t)11u)
#define NINLIL_R5_SHUTDOWN ((ninlil_r5_status_t)12u)
#define NINLIL_R5_ALIAS ((ninlil_r5_status_t)13u)
#define NINLIL_R5_BUSY_REENTRY ((ninlil_r5_status_t)14u)
#define NINLIL_R5_PROFILE_EXPIRED ((ninlil_r5_status_t)15u)
#define NINLIL_R5_PROFILE_NOT_EFFECTIVE ((ninlil_r5_status_t)16u)

#define NINLIL_R5_REASON_NONE ((ninlil_r5_reason_t)0u)
#define NINLIL_R5_REASON_NULL_ARG ((ninlil_r5_reason_t)1u)
#define NINLIL_R5_REASON_STRUCT ((ninlil_r5_reason_t)2u)
#define NINLIL_R5_REASON_CRC ((ninlil_r5_reason_t)3u)
#define NINLIL_R5_REASON_TRUNCATION ((ninlil_r5_reason_t)4u)
#define NINLIL_R5_REASON_OVERSIZE ((ninlil_r5_reason_t)5u)
#define NINLIL_R5_REASON_NOT_LAB_ONLY ((ninlil_r5_reason_t)6u)
#define NINLIL_R5_REASON_UNKNOWN_APPROVAL ((ninlil_r5_reason_t)7u)
#define NINLIL_R5_REASON_HW_REG_MISMATCH ((ninlil_r5_reason_t)8u)
#define NINLIL_R5_REASON_RANGE ((ninlil_r5_reason_t)9u)
#define NINLIL_R5_REASON_ROLLBACK ((ninlil_r5_reason_t)10u)
#define NINLIL_R5_REASON_OUTSTANDING ((ninlil_r5_reason_t)11u)
#define NINLIL_R5_REASON_UNBOUND ((ninlil_r5_reason_t)12u)
#define NINLIL_R5_REASON_AIRTIME ((ninlil_r5_reason_t)13u)
#define NINLIL_R5_REASON_CEILING ((ninlil_r5_reason_t)14u)
#define NINLIL_R5_REASON_PCP ((ninlil_r5_reason_t)15u)
#define NINLIL_R5_REASON_REGISTRY_MISS ((ninlil_r5_reason_t)16u)
#define NINLIL_R5_REASON_REGISTRY_FULL ((ninlil_r5_reason_t)17u)
#define NINLIL_R5_REASON_FORMULA_VERSION ((ninlil_r5_reason_t)18u)
#define NINLIL_R5_REASON_SHUTDOWN ((ninlil_r5_reason_t)19u)
#define NINLIL_R5_REASON_BIND_ITEM ((ninlil_r5_reason_t)20u)
#define NINLIL_R5_REASON_ZERO_ID ((ninlil_r5_reason_t)21u)
#define NINLIL_R5_REASON_DUPLICATE ((ninlil_r5_reason_t)22u)
#define NINLIL_R5_REASON_ALIAS ((ninlil_r5_reason_t)23u)
#define NINLIL_R5_REASON_REENTRY ((ninlil_r5_reason_t)24u)
#define NINLIL_R5_REASON_PROFILE_EXPIRED ((ninlil_r5_reason_t)25u)
#define NINLIL_R5_REASON_PROFILE_NOT_EFFECTIVE ((ninlil_r5_reason_t)26u)
#define NINLIL_R5_REASON_GEN_REQUIRED ((ninlil_r5_reason_t)27u)
#define NINLIL_R5_REASON_IDEMPOTENT ((ninlil_r5_reason_t)28u)

#define NINLIL_R5_STAGE_NONE ((ninlil_r5_stage_t)0u)
#define NINLIL_R5_STAGE_INIT ((ninlil_r5_stage_t)1u)
#define NINLIL_R5_STAGE_LOAD ((ninlil_r5_stage_t)2u)
#define NINLIL_R5_STAGE_ACTIVATE ((ninlil_r5_stage_t)3u)
#define NINLIL_R5_STAGE_ASSIGN ((ninlil_r5_stage_t)4u)
#define NINLIL_R5_STAGE_ISSUE ((ninlil_r5_stage_t)5u)
#define NINLIL_R5_STAGE_VALIDATE ((ninlil_r5_stage_t)6u)
#define NINLIL_R5_STAGE_CONSUME ((ninlil_r5_stage_t)7u)
#define NINLIL_R5_STAGE_FENCE ((ninlil_r5_stage_t)8u)
#define NINLIL_R5_STAGE_SHUTDOWN ((ninlil_r5_stage_t)9u)

/* Closed bind-item tags for single-mismatch diagnostics (not free-form). */
#define NINLIL_R5_BIND_NONE ((ninlil_r5_bind_item_t)0u)
#define NINLIL_R5_BIND_HW_ID ((ninlil_r5_bind_item_t)1u)
#define NINLIL_R5_BIND_HW_REV ((ninlil_r5_bind_item_t)2u)
#define NINLIL_R5_BIND_REG_ID ((ninlil_r5_bind_item_t)3u)
#define NINLIL_R5_BIND_REG_REV ((ninlil_r5_bind_item_t)4u)
#define NINLIL_R5_BIND_SITE_ID ((ninlil_r5_bind_item_t)5u)
#define NINLIL_R5_BIND_SITE_REV ((ninlil_r5_bind_item_t)6u)
#define NINLIL_R5_BIND_SITE_EPOCH ((ninlil_r5_bind_item_t)7u)
#define NINLIL_R5_BIND_CONTROLLER_TERM ((ninlil_r5_bind_item_t)8u)
#define NINLIL_R5_BIND_ASSIGNMENT_DIGEST ((ninlil_r5_bind_item_t)9u)
#define NINLIL_R5_BIND_PERMIT_GEN ((ninlil_r5_bind_item_t)10u)
#define NINLIL_R5_BIND_TX_ID ((ninlil_r5_bind_item_t)11u)
#define NINLIL_R5_BIND_CHANNEL ((ninlil_r5_bind_item_t)12u)
#define NINLIL_R5_BIND_PHY ((ninlil_r5_bind_item_t)13u)
#define NINLIL_R5_BIND_FRAME_DIGEST ((ninlil_r5_bind_item_t)14u)
#define NINLIL_R5_BIND_FRAME_DIGEST_ALG ((ninlil_r5_bind_item_t)20u)
#define NINLIL_R5_BIND_FRAME_LEN ((ninlil_r5_bind_item_t)15u)
#define NINLIL_R5_BIND_AIRTIME ((ninlil_r5_bind_item_t)16u)
#define NINLIL_R5_BIND_NOT_BEFORE ((ninlil_r5_bind_item_t)17u)
#define NINLIL_R5_BIND_EXPIRY ((ninlil_r5_bind_item_t)18u)
#define NINLIL_R5_BIND_PERMIT_SEQ ((ninlil_r5_bind_item_t)19u)

typedef struct ninlil_r5_error {
    ninlil_r5_status_t status;
    ninlil_r5_stage_t stage;
    ninlil_r5_reason_t reason;
    ninlil_r5_bind_item_t bind_item;
    char hint[NINLIL_R5_HINT_BYTES];
} ninlil_r5_error_t;

typedef struct ninlil_r5_hardware_profile {
    ninlil_radio_hal_id_t profile_id;
    uint32_t profile_rev;
    ninlil_radio_hal_id_t device_model_id;
    ninlil_radio_hal_id_t radio_sku_id;
    uint32_t hardware_revision;
    ninlil_radio_hal_id_t antenna_model_id;
    int32_t antenna_gain_mdb;
    uint32_t available_bearer_count;
} ninlil_r5_hardware_profile_t;

typedef struct ninlil_r5_regulatory_profile {
    ninlil_radio_hal_id_t profile_id;
    uint32_t profile_rev;
    uint8_t approval_state;
    uint8_t reserved_zero;
    uint16_t reserved_zero2;
    uint32_t region_code;
    uint32_t service_category;
    ninlil_radio_hal_id_t applicable_hardware_profile_id;
    uint32_t applicable_hw_rev_min;
    uint32_t applicable_hw_rev_max;
    uint32_t channel_id_min;
    uint32_t channel_id_max;
    uint32_t max_airtime_ceiling_us;
    uint32_t airtime_formula_version;
    uint32_t bw_hz;
    uint8_t sf_min;
    uint8_t sf_max;
    uint8_t cr_denom_min;
    uint8_t cr_denom_max;
    uint16_t preamble_symbols_min;
    uint16_t preamble_symbols_max;
    int32_t tx_power_mdb_min;
    int32_t tx_power_mdb_max;
    uint64_t effective_not_before_ms;
    uint64_t profile_expiry_ms;
} ninlil_r5_regulatory_profile_t;

/*
 * Full §9.3 bind plan (R5-owned). Includes U5 term/digest/generation which
 * are NOT in R2 issued 232B durable layout (schema1 unchanged).
 */
typedef struct ninlil_r5_bind_plan {
    ninlil_radio_hal_id_t hardware_profile_id;
    uint32_t hardware_profile_rev;
    ninlil_radio_hal_id_t regulatory_profile_id;
    uint32_t regulatory_profile_rev;
    ninlil_radio_hal_id_t site_assignment_id;
    uint32_t site_assignment_rev;
    uint64_t site_assignment_epoch;
    uint64_t controller_term;
    uint8_t assignment_digest[NINLIL_R5_DIGEST_BYTES];
    uint64_t permit_bind_generation;
    ninlil_radio_hal_id_t transmitter_id;
    uint32_t channel_id;
    ninlil_radio_hal_phy_t phy;
    uint8_t frame_digest[NINLIL_R5_DIGEST_BYTES];
    uint32_t frame_digest_algorithm;
    uint32_t frame_byte_length;
    uint32_t max_airtime_us;
    uint64_t not_before_ms;
    uint64_t expiry_ms;
    uint64_t permit_sequence; /* 0 at issue request; filled after issue */
    uint32_t reserved_zero;
} ninlil_r5_bind_plan_t;

typedef struct ninlil_r5_site_assignment {
    ninlil_radio_hal_id_t site_assignment_id;
    uint32_t site_assignment_rev;
    uint64_t site_assignment_epoch;
    uint64_t controller_term;
    uint8_t assignment_digest[NINLIL_R5_DIGEST_BYTES];
    uint64_t permit_bind_generation;
    ninlil_radio_hal_id_t transmitter_id;
    uint32_t channel_id;
    ninlil_radio_hal_phy_t phy;
    uint32_t reserved_zero;
} ninlil_r5_site_assignment_t;

typedef struct ninlil_r5_issue_plan {
    const uint8_t *frame_bytes;
    uint32_t frame_byte_length;
    uint8_t frame_digest[NINLIL_R5_DIGEST_BYTES];
    uint32_t frame_digest_algorithm;
    ninlil_airtime_lora_input_t airtime_in; /* R3 inputs; must match phy */
    uint64_t not_before_ms;
    uint64_t expiry_ms;
    uint32_t reserved_zero;
} ninlil_r5_issue_plan_t;

typedef struct ninlil_r5_registry_slot {
    uint32_t occupied;
    uint32_t reserved_zero;
    ninlil_r5_bind_plan_t plan;
} ninlil_r5_registry_slot_t;

typedef struct ninlil_r5_stats {
    uint64_t load_hw_ok;
    uint64_t load_hw_deny;
    uint64_t load_reg_ok;
    uint64_t load_reg_deny;
    uint64_t activate_ok;
    uint64_t activate_deny;
    uint64_t assign_ok;
    uint64_t assign_deny;
    uint64_t issue_ok;
    uint64_t issue_deny;
    uint64_t validate_ok;
    uint64_t validate_deny;
    uint64_t consume_ok;
    uint64_t consume_deny;
    uint64_t fence_ok;
    uint64_t bind_mismatch;
    uint64_t registry_miss;
    uint64_t reserved_zero_0;
} ninlil_r5_stats_t;

struct ninlil_r5 {
    uint32_t magic;
    uint32_t lifecycle; /* 0 zero, 1 active, 2 shutdown */
    uint32_t in_api;
    uint32_t hw_staged_loaded;
    uint32_t reg_staged_loaded;
    uint32_t profiles_active; /* active HW+REG committed */
    uint32_t assignment_bound;
    uint32_t pcp_bound;
    uint32_t fence_pending; /* durable gen fence not completed */
    uint32_t reserved_zero_head;
    /*
     * Two-phase fence target (RAM owner only): set with fence_pending on first
     * attempt on this object. Same-object retry uses this (not current gen).
     * Not durable across process restart — after restart R5 RAM is empty and
     * the owner must re-establish fence intent. Cleared only after verified
     * durable success on this object.
     */
    uint64_t fence_target_generation;

    ninlil_r5_hardware_profile_t hw_staged;
    ninlil_r5_regulatory_profile_t reg_staged;
    ninlil_r5_hardware_profile_t hw; /* active */
    ninlil_r5_regulatory_profile_t reg; /* active */
    ninlil_r5_site_assignment_t assignment;

    ninlil_pcp_t *pcp; /* non-owning; set by bind_pcp */

    ninlil_r5_registry_slot_t registry[NINLIL_R5_MAX_OUTSTANDING];
    uint32_t registry_count;
    uint32_t reserved_zero_reg;

    ninlil_r5_stats_t stats;
    ninlil_r5_error_t last_error;
};

typedef struct ninlil_r5 ninlil_r5_t;
typedef ninlil_r5_t ninlil_r5_object_t;

#define NINLIL_R5_OBJECT_INIT {0}
#define NINLIL_R5_MAGIC_VALUE ((uint32_t)0x52355043u) /* 'R5PC' */

static inline size_t ninlil_r5_object_size(void)
{
    return sizeof(ninlil_r5_t);
}

static inline size_t ninlil_r5_object_align(void)
{
    return _Alignof(ninlil_r5_t);
}

_Static_assert(sizeof(ninlil_r5_t) <= NINLIL_R5_OBJECT_BYTES, "R5 object ceiling");
_Static_assert(_Alignof(ninlil_r5_t) >= NINLIL_R5_OBJECT_ALIGN, "R5 align");
_Static_assert(NINLIL_R5_HW_DOC_BYTES == 128u, "hw doc 128");
_Static_assert(NINLIL_R5_REG_DOC_BYTES == 160u, "reg doc 160");

/* ---- Lifecycle ---- */

ninlil_r5_status_t ninlil_r5_init_object(
    ninlil_r5_object_t *object,
    ninlil_r5_t **out_r5);

ninlil_r5_status_t ninlil_r5_shutdown(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error);

/*
 * Non-owning bind to an ACTIVE R2 authority (published or pre-publish).
 * Transactional: previous pcp/pcp_bound preserved on invalid candidate and on
 * every definite/unknown sync failure; new pointer published only after
 * verified commit_live success or accepted ACTIVE+unpublished defer.
 * Single-owner reentry: R5 in_api wraps storage-capable PCP ops (not threads).
 * ALIAS (owner↔pcp / pcp↔out_error / owner↔out_error): NINLIL_R5_ALIAS only,
 * zero mutation of owner, pcp object, and out_error; prior binding unchanged.
 * fence_pending: INVALID_STATE + REASON_PCP — no pointer swap / commit_live;
 * keep prior pcp and fence_target_generation. Recovery is original-PCP
 * fence_after_revoke retry (not peer rebind). Host candidate only.
 */
ninlil_r5_status_t ninlil_r5_bind_pcp(
    ninlil_r5_t *r5,
    ninlil_pcp_t *pcp,
    ninlil_r5_error_t *out_error);

/* ---- Profile load / activate ---- */

/*
 * Load staged HW/REG fixed-length docs. ALIAS only on actual geometric overlap
 * (doc length capped at expected_size+1 for range math — pure oversize/SIZE_MAX
 * is not ALIAS; decoder returns STRUCT+OVERSIZE). ALIAS: zero mutation of owner,
 * doc bytes, out_error; staged/active unchanged. Not FIELD/PRODUCTION/Japan legal.
 */
ninlil_r5_status_t ninlil_r5_load_hardware_profile(
    ninlil_r5_t *r5,
    const uint8_t *doc,
    size_t doc_len,
    ninlil_r5_error_t *out_error);

ninlil_r5_status_t ninlil_r5_load_regulatory_profile(
    ninlil_r5_t *r5,
    const uint8_t *doc,
    size_t doc_len,
    ninlil_r5_error_t *out_error);

/*
 * Activate staged HW+REG pair.
 * - outstanding registry non-empty or same-id revision rollback → deny.
 * - Same id+rev with different full content → PROFILE_DENIED DUPLICATE;
 *   only exact full-struct HW+REG equality is idempotent.
 * - When assignment is bound: strict generation bump + full durable L_core
 *   rebind (commit_live) before swapping active. Definite durable failure
 *   preserves local active. COMMIT_UNKNOWN preserves local active but durable
 *   outcome is unknown until recover (not claimed mixed-free atomic).
 * - When assignment unbound: staged→active only (no durable gen).
 */
ninlil_r5_status_t ninlil_r5_activate_profiles(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error);

/* ---- Site assignment ---- */

/*
 * ALIAS (owner↔assignment / assignment↔out_error / owner↔out_error):
 * NINLIL_R5_ALIAS only — zero mutation of owner, assignment, out_error;
 * prior assignment_bound and registry unchanged.
 * fence_pending: INVALID_STATE + REASON_PCP before any durable/local change
 * (including idempotent same assignment). Must not clear/retarget fence;
 * complete fence_after_revoke on the original authority first.
 */
ninlil_r5_status_t ninlil_r5_bind_site_assignment(
    ninlil_r5_t *r5,
    const ninlil_r5_site_assignment_t *assignment,
    ninlil_r5_error_t *out_error);

/* Build R1/R2 live_binding: L_core from assignment; max_airtime = ceiling. */
ninlil_r5_status_t ninlil_r5_build_live_binding(
    const ninlil_r5_t *r5,
    ninlil_radio_hal_live_binding_t *out_live,
    ninlil_r5_error_t *out_error);

/* ---- Issue / validate / consume (full bind) ---- */

/*
 * Compose expected full §9.3 bind from active profiles/assignment + R3 airtime
 * + issue_plan frame/window. permit_sequence left 0. Fail-closed on R3/ceiling.
 * SEMANTIC: FULL_BIND_MATRIX_ISSUE_AND_CONSUME
 */
ninlil_r5_status_t ninlil_r5_compose_issue_bind(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    ninlil_r5_bind_plan_t *out_expected,
    ninlil_r5_error_t *out_error);

/*
 * Issue with explicit full bind. Compares proposed to compose_issue_bind
 * expected (all fields except permit_sequence); any single-field mismatch
 * → BIND_MISMATCH with bind_item (issue-time matrix). Then R2 issue + registry.
 * Also requires R2 durable assignment_generation == permit_bind_generation.
 */
ninlil_r5_status_t ninlil_r5_issue_with_bind(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    const ninlil_r5_bind_plan_t *proposed,
    ninlil_r5_bind_plan_t *out_full_bind,
    ninlil_radio_hal_permit_snapshot_t *out_hal_snapshot,
    ninlil_r5_error_t *out_error);

/*
 * Compose expected bind then issue_with_bind(expected).
 * out_hal_snapshot is R1-compatible (U5 fields held in R5 registry).
 */
ninlil_r5_status_t ninlil_r5_issue(
    ninlil_r5_t *r5,
    const ninlil_r5_issue_plan_t *plan,
    ninlil_r5_bind_plan_t *out_full_bind,
    ninlil_radio_hal_permit_snapshot_t *out_hal_snapshot,
    ninlil_r5_error_t *out_error);

/*
 * R1 permit_ops seam: full bind then R2 validate/consume. ctx = ninlil_r5_t*.
 * Alias rejection (actual geometric owner/input/out_error overlap only; pure
 * oversize is not ALIAS): INVALID_ARGUMENT + REASON_ALIAS with zero mutation of
 * owner (stats/last_error/in_api/registry), const permit, frame container,
 * bounded frame bytes; never write unsafe out_error. Safe disjoint out_error
 * may receive HAL ALIAS. Disjoint oversize / NULL+nonzero length:
 * INVALID_ARGUMENT + REASON_OVERSIZE or REASON_STRUCT_INVALID (not ALIAS);
 * no validate/consume work.
 */
ninlil_radio_hal_status_t ninlil_r5_permit_validate(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error);

ninlil_radio_hal_status_t ninlil_r5_permit_consume(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error);

void ninlil_r5_permit_ops(ninlil_radio_hal_permit_ops_t *out_ops);

/*
 * Fence outstanding: caller must have invoked ninlil_pcp_revoke_all_outstanding
 * (or equivalent). Two-phase on this RAM object: stores fence_target_generation
 * (= old+1) with fence_pending before durable commit; same-object retry uses
 * stored target (never current assignment gen). Not process-restart durable.
 * While fence_pending: bind_pcp / bind_site_assignment (and activate/issue) are
 * fail-closed — do not swap PCP or clear/retarget the fence. Recovery =
 * recover original PCP then fence_after_revoke retry. Clears registry / bumps
 * local gen / clears pending only after verified durable success at that target.
 */
ninlil_r5_status_t ninlil_r5_fence_after_revoke(
    ninlil_r5_t *r5,
    ninlil_r5_error_t *out_error);

void ninlil_r5_stats(const ninlil_r5_t *r5, ninlil_r5_stats_t *out_stats);

void ninlil_r5_last_error(const ninlil_r5_t *r5, ninlil_r5_error_t *out_error);

/* Encode helpers for tests/fixtures (deterministic; production may use). */
ninlil_r5_status_t ninlil_r5_encode_hardware_profile(
    const ninlil_r5_hardware_profile_t *hw,
    uint8_t out_doc[NINLIL_R5_HW_DOC_BYTES]);

ninlil_r5_status_t ninlil_r5_encode_regulatory_profile(
    const ninlil_r5_regulatory_profile_t *reg,
    uint8_t out_doc[NINLIL_R5_REG_DOC_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_PROFILE_LOADER_H */
