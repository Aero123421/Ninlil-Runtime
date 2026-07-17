#ifndef NINLIL_RADIO_PCP_AUTHORITY_H
#define NINLIL_RADIO_PCP_AUTHORITY_H

/*
 * R2 Physical Compliance Permit authority — production-private complete C11 API.
 *
 * Normative companion: docs/24-r2-physical-compliance-permit-authority.md
 * Not public include/ninlil ABI. Not KGuard. Not R3/R5/legal/HIL complete.
 *
 * Completeness policy (same family as radio_hal.h):
 *   - The object type IS the complete struct (no opaque byte buffer pun).
 *   - Callers allocate ninlil_pcp_object_t on stack/static/heap.
 *   - NINLIL_PCP_OBJECT_BYTES is a fixed sizeof ceiling only.
 */

#include "radio_hal.h"

#include "ninlil/platform.h"
#include "ninlil/version.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Constants (schema / capacity) ---- */

#define NINLIL_PCP_SCHEMA_VERSION ((uint16_t)1u)
#define NINLIL_PCP_MAGIC ((uint32_t)0x31504350u) /* LE 'PCP1' */
#define NINLIL_PCP_NAMESPACE_BYTES ((size_t)12u)  /* "ninlil.pcp.v1" */
#define NINLIL_PCP_META_KEY_BYTES ((size_t)4u)
#define NINLIL_PCP_ISS_KEY_BYTES ((size_t)20u)
#define NINLIL_PCP_META_VALUE_BYTES ((size_t)200u)
#define NINLIL_PCP_ISSUED_VALUE_BYTES ((size_t)232u)
#define NINLIL_PCP_MAX_OUTSTANDING ((uint32_t)8u)
#define NINLIL_PCP_MAX_PERMIT_TTL_MS ((uint64_t)600000u)
#define NINLIL_PCP_OBJECT_BYTES ((size_t)4096u)
#define NINLIL_PCP_OBJECT_ALIGN ((size_t)8u)
#define NINLIL_PCP_HINT_BYTES ((size_t)160u)
#define NINLIL_PCP_SCRATCH_KEY_BYTES ((size_t)32u)
#define NINLIL_PCP_SCRATCH_VALUE_BYTES ((size_t)256u)
#define NINLIL_PCP_ID_BYTES ((size_t)16u)
#define NINLIL_PCP_DIGEST_BYTES ((size_t)32u)

/* ---- Status / reason / stage / fence codes (closed numeric) ---- */

typedef uint32_t ninlil_pcp_status_t;
typedef uint32_t ninlil_pcp_reason_t;
typedef uint32_t ninlil_pcp_stage_t;
typedef uint32_t ninlil_pcp_fence_code_t;
typedef uint32_t ninlil_pcp_lifecycle_t;

#define NINLIL_PCP_OK ((ninlil_pcp_status_t)0u)
#define NINLIL_PCP_INVALID_ARGUMENT ((ninlil_pcp_status_t)1u)
#define NINLIL_PCP_INVALID_STATE ((ninlil_pcp_status_t)2u)
#define NINLIL_PCP_STRUCT ((ninlil_pcp_status_t)3u)
#define NINLIL_PCP_CLOCK_UNCERTAIN ((ninlil_pcp_status_t)4u)
#define NINLIL_PCP_CLOCK_FAULT ((ninlil_pcp_status_t)5u)
#define NINLIL_PCP_PROFILE_MISMATCH ((ninlil_pcp_status_t)6u)
#define NINLIL_PCP_CAPACITY ((ninlil_pcp_status_t)7u)
#define NINLIL_PCP_SEQ_EXHAUSTED ((ninlil_pcp_status_t)8u)
#define NINLIL_PCP_STORAGE_FENCE ((ninlil_pcp_status_t)9u)
#define NINLIL_PCP_CORRUPT_FENCE ((ninlil_pcp_status_t)10u)
#define NINLIL_PCP_COMMIT_UNKNOWN ((ninlil_pcp_status_t)11u)
#define NINLIL_PCP_STORAGE_IO ((ninlil_pcp_status_t)12u)
#define NINLIL_PCP_BUSY ((ninlil_pcp_status_t)13u)
#define NINLIL_PCP_BUSY_OUTSTANDING ((ninlil_pcp_status_t)14u)
#define NINLIL_PCP_BUSY_REENTRY ((ninlil_pcp_status_t)15u)
#define NINLIL_PCP_ALIAS ((ninlil_pcp_status_t)16u)
#define NINLIL_PCP_UNBOUND_STORAGE ((ninlil_pcp_status_t)17u)
#define NINLIL_PCP_UNBOUND_CLOCK ((ninlil_pcp_status_t)18u)
#define NINLIL_PCP_UNBOUND_ASSIGNMENT ((ninlil_pcp_status_t)19u)
#define NINLIL_PCP_RECOVER_FAIL ((ninlil_pcp_status_t)20u)
#define NINLIL_PCP_STORAGE_UNSUPPORTED ((ninlil_pcp_status_t)21u)
#define NINLIL_PCP_SHUTDOWN ((ninlil_pcp_status_t)22u)
#define NINLIL_PCP_EMPTY_OK ((ninlil_pcp_status_t)23u)

#define NINLIL_PCP_REASON_NONE ((ninlil_pcp_reason_t)0u)
#define NINLIL_PCP_REASON_NULL_ARG ((ninlil_pcp_reason_t)1u)
#define NINLIL_PCP_REASON_STRUCT_INVALID ((ninlil_pcp_reason_t)2u)
#define NINLIL_PCP_REASON_UNBOUND_STORAGE ((ninlil_pcp_reason_t)3u)
#define NINLIL_PCP_REASON_UNBOUND_CLOCK ((ninlil_pcp_reason_t)4u)
#define NINLIL_PCP_REASON_UNBOUND_ASSIGNMENT ((ninlil_pcp_reason_t)5u)
#define NINLIL_PCP_REASON_CLOCK_UNCERTAIN ((ninlil_pcp_reason_t)6u)
#define NINLIL_PCP_REASON_CLOCK_FAULT ((ninlil_pcp_reason_t)7u)
#define NINLIL_PCP_REASON_EPOCH_MISMATCH ((ninlil_pcp_reason_t)8u)
#define NINLIL_PCP_REASON_NOT_BEFORE ((ninlil_pcp_reason_t)9u)
#define NINLIL_PCP_REASON_EXPIRED ((ninlil_pcp_reason_t)10u)
#define NINLIL_PCP_REASON_PROFILE_MISMATCH ((ninlil_pcp_reason_t)11u)
#define NINLIL_PCP_REASON_FABRICATED ((ninlil_pcp_reason_t)12u)
#define NINLIL_PCP_REASON_ALREADY_CONSUMED ((ninlil_pcp_reason_t)13u)
#define NINLIL_PCP_REASON_REVOKED ((ninlil_pcp_reason_t)14u)
#define NINLIL_PCP_REASON_CAPACITY ((ninlil_pcp_reason_t)15u)
#define NINLIL_PCP_REASON_SEQ_EXHAUSTED ((ninlil_pcp_reason_t)16u)
#define NINLIL_PCP_REASON_STORAGE_FENCE ((ninlil_pcp_reason_t)17u)
#define NINLIL_PCP_REASON_CORRUPT_FENCE ((ninlil_pcp_reason_t)18u)
#define NINLIL_PCP_REASON_COMMIT_UNKNOWN ((ninlil_pcp_reason_t)19u)
#define NINLIL_PCP_REASON_STORAGE_IO ((ninlil_pcp_reason_t)20u)
#define NINLIL_PCP_REASON_STORAGE_CORRUPT ((ninlil_pcp_reason_t)21u)
#define NINLIL_PCP_REASON_BUSY_REENTRY ((ninlil_pcp_reason_t)22u)
#define NINLIL_PCP_REASON_BUSY_OUTSTANDING ((ninlil_pcp_reason_t)23u)
#define NINLIL_PCP_REASON_ALIAS ((ninlil_pcp_reason_t)24u)
#define NINLIL_PCP_REASON_COUNTER_SAT ((ninlil_pcp_reason_t)25u)
#define NINLIL_PCP_REASON_SHUTDOWN ((ninlil_pcp_reason_t)26u)
#define NINLIL_PCP_REASON_INVALID_STATE ((ninlil_pcp_reason_t)27u)
#define NINLIL_PCP_REASON_CONTRACT ((ninlil_pcp_reason_t)28u)
#define NINLIL_PCP_REASON_OUT_OF_ORDER ((ninlil_pcp_reason_t)29u)
#define NINLIL_PCP_REASON_INSTANCE_MISMATCH ((ninlil_pcp_reason_t)30u)
#define NINLIL_PCP_REASON_RECOVER_FAIL ((ninlil_pcp_reason_t)31u)
#define NINLIL_PCP_REASON_FOREIGN_KEY ((ninlil_pcp_reason_t)32u)
#define NINLIL_PCP_REASON_STORAGE_UNSUPPORTED ((ninlil_pcp_reason_t)33u)
#define NINLIL_PCP_REASON_HEAD_ADVANCED ((ninlil_pcp_reason_t)34u)

#define NINLIL_PCP_STAGE_NONE ((ninlil_pcp_stage_t)0u)
#define NINLIL_PCP_STAGE_INIT ((ninlil_pcp_stage_t)1u)
#define NINLIL_PCP_STAGE_BIND ((ninlil_pcp_stage_t)2u)
#define NINLIL_PCP_STAGE_RECOVER ((ninlil_pcp_stage_t)3u)
#define NINLIL_PCP_STAGE_PUBLISH ((ninlil_pcp_stage_t)4u)
#define NINLIL_PCP_STAGE_ISSUE ((ninlil_pcp_stage_t)5u)
#define NINLIL_PCP_STAGE_VALIDATE ((ninlil_pcp_stage_t)6u)
#define NINLIL_PCP_STAGE_CONSUME ((ninlil_pcp_stage_t)7u)
#define NINLIL_PCP_STAGE_ADVANCE ((ninlil_pcp_stage_t)8u)
#define NINLIL_PCP_STAGE_REVOKE ((ninlil_pcp_stage_t)9u)
#define NINLIL_PCP_STAGE_SHUTDOWN ((ninlil_pcp_stage_t)10u)
#define NINLIL_PCP_STAGE_GC ((ninlil_pcp_stage_t)11u)

#define NINLIL_PCP_FC_NONE ((ninlil_pcp_fence_code_t)0u)
#define NINLIL_PCP_FC_CLOCK_REGRESSION ((ninlil_pcp_fence_code_t)1u)
#define NINLIL_PCP_FC_CLOCK_PERM ((ninlil_pcp_fence_code_t)2u)
#define NINLIL_PCP_FC_CLOCK_ILLFORMED ((ninlil_pcp_fence_code_t)3u)
#define NINLIL_PCP_FC_CLOCK_UNKNOWN ((ninlil_pcp_fence_code_t)4u)
#define NINLIL_PCP_FC_STORAGE ((ninlil_pcp_fence_code_t)5u)
#define NINLIL_PCP_FC_CORRUPT ((ninlil_pcp_fence_code_t)6u)

#define NINLIL_PCP_LC_ZERO ((ninlil_pcp_lifecycle_t)0u)
#define NINLIL_PCP_LC_ACTIVE ((ninlil_pcp_lifecycle_t)1u)
#define NINLIL_PCP_LC_SHUTDOWN ((ninlil_pcp_lifecycle_t)2u)

#define NINLIL_PCP_FENCE_BIT_STORAGE ((uint32_t)1u << 0)
#define NINLIL_PCP_FENCE_BIT_CLOCK ((uint32_t)1u << 1)
#define NINLIL_PCP_FENCE_BIT_CORRUPT ((uint32_t)1u << 2)

/* ---- Public-to-private input / error / stats types ---- */

typedef struct ninlil_pcp_error {
    ninlil_pcp_status_t status;
    ninlil_pcp_stage_t stage;
    ninlil_pcp_reason_t reason;
    uint32_t reserved_zero;
    char hint[NINLIL_PCP_HINT_BYTES];
} ninlil_pcp_error_t;

typedef struct ninlil_pcp_instance_seed {
    uint8_t bytes[NINLIL_PCP_ID_BYTES];
} ninlil_pcp_instance_seed_t;

/*
 * Issue request: L_core + per-permit airtime + plan P.
 * MUST NOT contain permit_sequence (authority assigns).
 */
typedef struct ninlil_pcp_issue_request {
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
    uint32_t max_airtime_us; /* per-permit; must be <= bound ceiling */
    uint8_t frame_digest[NINLIL_PCP_DIGEST_BYTES];
    uint32_t frame_digest_algorithm;
    uint32_t frame_byte_length;
    uint64_t not_before_ms;
    uint64_t expiry_ms;
    uint32_t reserved_zero;
} ninlil_pcp_issue_request_t;

/* Live profile layout matches R1 live_binding; max_airtime_us is ceiling at bind. */
typedef ninlil_radio_hal_live_binding_t ninlil_pcp_live_profile_t;

typedef struct ninlil_pcp_r2_stats {
    uint64_t issue_ok;
    uint64_t issue_deny;
    uint64_t validate_ok;
    uint64_t validate_deny;
    uint64_t validate_error;
    uint64_t consume_ok;
    uint64_t consume_denied;
    uint64_t consume_fenced;
    uint64_t consume_error;
    uint64_t advance_ok;
    uint64_t advance_nop;
    uint64_t revoke_ok;
    uint64_t recover_ok;
    uint64_t recover_fail;
    uint64_t fence_set;
    uint64_t storage_commit_unknown;
    uint64_t fifo_out_of_order;
    uint64_t reentry_reject;
    uint64_t alias_reject;
    uint64_t gc_erased;
    uint64_t reserved_zero_0;
    uint64_t reserved_zero_1;
    uint64_t reserved_zero_2;
    uint64_t reserved_zero_3;
} ninlil_pcp_r2_stats_t;

/*
 * Packed 24×uint64_t only: no padding holes. Every field width is bound by
 * sizeof(((T*)0)->field) == sizeof(uint64_t) so uint8_t/narrowing cannot
 * greenwash via trailing padding while sizeof(T)==192 still holds.
 */
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, issue_ok) == 0u, "stats issue_ok@0");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, issue_deny) == 8u, "stats issue_deny@8");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, validate_ok) == 16u, "stats validate_ok");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, validate_deny) == 24u, "stats validate_deny");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, validate_error) == 32u, "stats validate_error");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_ok) == 40u, "stats consume_ok");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_denied) == 48u, "stats consume_denied");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_fenced) == 56u, "stats consume_fenced@56");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_error) == 64u, "stats consume_error");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, advance_ok) == 72u, "stats advance_ok");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, advance_nop) == 80u, "stats advance_nop");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, revoke_ok) == 88u, "stats revoke_ok");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, recover_ok) == 96u, "stats recover_ok");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, recover_fail) == 104u, "stats recover_fail");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, fence_set) == 112u, "stats fence_set");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, storage_commit_unknown) == 120u, "stats cu");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, fifo_out_of_order) == 128u, "stats fifo");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reentry_reject) == 136u, "stats reentry");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, alias_reject) == 144u, "stats alias");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, gc_erased) == 152u, "stats gc");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_0) == 160u, "stats r0");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_1) == 168u, "stats r1");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_2) == 176u, "stats r2");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_3) == 184u, "stats r3");
_Static_assert(sizeof(ninlil_pcp_r2_stats_t) == 192u, "stats sizeof 24*8");
_Static_assert(_Alignof(ninlil_pcp_r2_stats_t) == 8u, "stats align 8");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->issue_ok) == sizeof(uint64_t), "w issue_ok");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->issue_deny) == sizeof(uint64_t), "w issue_deny");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->validate_ok) == sizeof(uint64_t), "w validate_ok");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->validate_deny) == sizeof(uint64_t), "w validate_deny");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->validate_error) == sizeof(uint64_t), "w validate_error");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->consume_ok) == sizeof(uint64_t), "w consume_ok");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->consume_denied) == sizeof(uint64_t), "w consume_denied");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->consume_fenced) == sizeof(uint64_t), "w consume_fenced");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->consume_error) == sizeof(uint64_t), "w consume_error");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->advance_ok) == sizeof(uint64_t), "w advance_ok");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->advance_nop) == sizeof(uint64_t), "w advance_nop");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->revoke_ok) == sizeof(uint64_t), "w revoke_ok");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->recover_ok) == sizeof(uint64_t), "w recover_ok");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->recover_fail) == sizeof(uint64_t), "w recover_fail");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->fence_set) == sizeof(uint64_t), "w fence_set");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->storage_commit_unknown) == sizeof(uint64_t), "w scu");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->fifo_out_of_order) == sizeof(uint64_t), "w fifo");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->reentry_reject) == sizeof(uint64_t), "w reentry");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->alias_reject) == sizeof(uint64_t), "w alias");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->gc_erased) == sizeof(uint64_t), "w gc");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->reserved_zero_0) == sizeof(uint64_t), "w r0");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->reserved_zero_1) == sizeof(uint64_t), "w r1");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->reserved_zero_2) == sizeof(uint64_t), "w r2");
_Static_assert(sizeof(((ninlil_pcp_r2_stats_t *)0)->reserved_zero_3) == sizeof(uint64_t), "w r3");

/* ---- Bound L_core + ceiling cache (RAM mirror of meta bound fields) ---- */

typedef struct ninlil_pcp_bound_live {
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
    uint32_t max_airtime_ceiling_us;
    uint64_t assignment_generation;
    uint32_t bound;
    uint32_t reserved_zero;
} ninlil_pcp_bound_live_t;

typedef struct ninlil_pcp_ram_validate {
    uint32_t valid;
    uint32_t reserved_zero;
    uint64_t permit_sequence;
    uint8_t frame_digest[NINLIL_PCP_DIGEST_BYTES];
    uint8_t clock_epoch_id[NINLIL_PCP_ID_BYTES];
    uint64_t now_ms;
} ninlil_pcp_ram_validate_t;

typedef struct ninlil_pcp_ram_trust {
    uint8_t clock_epoch_id[NINLIL_PCP_ID_BYTES];
    uint64_t now_ms;
    uint32_t valid;
    uint32_t reserved_zero;
} ninlil_pcp_ram_trust_t;

/*
 * Complete authority object (C11 effective type).
 * Implementation may use private fields below; field order is Normative for
 * layout contracts and consumer offsetof of public-facing tail is not required.
 * Callers treat the object as complete storage for init_object.
 */
struct ninlil_pcp {
    uint32_t magic;
    ninlil_pcp_lifecycle_t lifecycle;
    uint32_t in_api;
    uint32_t storage_bound;
    uint32_t clock_bound;
    uint32_t entropy_bound;
    uint32_t live_bound;
    uint32_t published;
    uint32_t fence_bits;
    ninlil_pcp_fence_code_t fence_code;
    uint32_t reserved_zero_head;

    ninlil_storage_ops_t storage_ops;
    ninlil_clock_ops_t clock_ops;
    ninlil_entropy_ops_t entropy_ops;
    /* ops.user is sole user; no parallel user fields */

    ninlil_storage_handle_t storage_handle;
    uint32_t storage_handle_live;
    uint32_t reserved_zero_handle;

    ninlil_pcp_bound_live_t bound_live;
    uint8_t authority_instance_id[NINLIL_PCP_ID_BYTES];
    uint64_t next_issue_seq_cache;
    uint64_t last_consumed_seq_cache;
    uint32_t outstanding_count_cache;
    uint32_t reserved_zero_cache;

    ninlil_pcp_ram_trust_t ram_trust;
    ninlil_pcp_ram_validate_t ram_validate;

    ninlil_pcp_r2_stats_t stats;
    ninlil_pcp_error_t last_error;

    uint8_t key_scratch[NINLIL_PCP_SCRATCH_KEY_BYTES];
    uint8_t value_scratch[NINLIL_PCP_SCRATCH_VALUE_BYTES];
    uint8_t meta_scratch[NINLIL_PCP_META_VALUE_BYTES];
    uint8_t iss_scratch[NINLIL_PCP_ISSUED_VALUE_BYTES];
};

typedef struct ninlil_pcp ninlil_pcp_t;
typedef ninlil_pcp_t ninlil_pcp_object_t;

#define NINLIL_PCP_OBJECT_INIT {0}
#define NINLIL_PCP_MAGIC_VALUE ((uint32_t)0x50435032u) /* 'PCP2' tag in RAM */

static inline size_t ninlil_pcp_object_size(void)
{
    return sizeof(ninlil_pcp_t);
}

static inline size_t ninlil_pcp_object_align(void)
{
    return _Alignof(ninlil_pcp_t);
}

_Static_assert(
    NINLIL_PCP_OBJECT_ALIGN >= 8u,
    "PCP OBJECT_ALIGN minimum");
_Static_assert(
    _Alignof(ninlil_pcp_object_t) >= NINLIL_PCP_OBJECT_ALIGN,
    "PCP object align below minimum");
_Static_assert(
    sizeof(ninlil_pcp_t) <= NINLIL_PCP_OBJECT_BYTES,
    "PCP object exceeds OBJECT_BYTES ceiling");
_Static_assert(
    _Alignof(ninlil_pcp_t) <= _Alignof(max_align_t),
    "PCP object align exceeds max_align_t");
_Static_assert(
    offsetof(struct ninlil_pcp, magic) == 0u,
    "magic must be first");
_Static_assert(
    sizeof(ninlil_pcp_error_t) >= 16u + NINLIL_PCP_HINT_BYTES,
    "error type size floor");
_Static_assert(
    sizeof(ninlil_pcp_issue_request_t) > 64u,
    "issue_request must be complete non-empty");

/* ---- API (ops->user sole; no parallel user args) ---- */

ninlil_pcp_status_t ninlil_pcp_init_object(
    ninlil_pcp_object_t *object,
    ninlil_pcp_t **out_pcp);

ninlil_pcp_status_t ninlil_pcp_shutdown(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_bind_storage(
    ninlil_pcp_t *pcp,
    const ninlil_storage_ops_t *ops,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_bind_clock(
    ninlil_pcp_t *pcp,
    const ninlil_clock_ops_t *ops,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_bind_entropy(
    ninlil_pcp_t *pcp,
    const ninlil_entropy_ops_t *ops,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_bind_live_profile(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_live_profile_t *live,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_publish_initial_meta(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_instance_seed_t *seed,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_recover(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_recover_storage(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_recover_clock(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_issue(
    ninlil_pcp_t *pcp,
    const ninlil_pcp_issue_request_t *request,
    ninlil_radio_hal_permit_snapshot_t *out_snapshot,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_advance_expired_heads(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_revoke_all_outstanding(
    ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error);

ninlil_pcp_status_t ninlil_pcp_gc_terminal_records(
    ninlil_pcp_t *pcp,
    const uint64_t *seqs,
    uint32_t seq_count,
    ninlil_pcp_error_t *out_error);

/* R1 seam — exact signatures from radio_hal.h */
ninlil_radio_hal_status_t ninlil_pcp_validate(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error);

ninlil_radio_hal_status_t ninlil_pcp_consume(
    void *ctx,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error);

void ninlil_pcp_permit_ops(ninlil_radio_hal_permit_ops_t *out_ops);

void ninlil_pcp_stats(
    const ninlil_pcp_t *pcp,
    ninlil_pcp_r2_stats_t *out_stats);

void ninlil_pcp_last_error(
    const ninlil_pcp_t *pcp,
    ninlil_pcp_error_t *out_error);

/*
 * Ownership / lifetime (Normative):
 *   - Caller owns ninlil_pcp_object_t storage for the object lifetime.
 *   - init_object publishes ACTIVE; shutdown → SHUTDOWN; re-init only after SHUTDOWN.
 *   - bind_* copies ops tables; ops->user is sole callback user for that port.
 *   - storage handle is authority-owned after successful open inside recover/publish;
 *     close only on shutdown/unbind (platform close is void).
 *   - Sole owner; reentry → BUSY_REENTRY; no heap; no VLA.
 *   - Functions are declared here; R2 implementation TU is a later PR.
 *     This header is the compile-time contract freeze (docs gate + consumer test).
 */

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_PCP_AUTHORITY_H */
