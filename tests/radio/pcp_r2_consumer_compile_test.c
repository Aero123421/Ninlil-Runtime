/*
 * Independent consumer compile test for R2 pcp_authority.h complete type.
 * Verifies C11 can compile against the private header without public ABI.
 * Does not implement authority body / not R2 runtime complete.
 *
 * Stats contract: all 24 fields are uint64_t width — padding cannot hide a
 * narrowed field while sizeof(stats)==192 still holds.
 */

#include "pcp_authority.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

_Static_assert(sizeof(ninlil_pcp_t) <= NINLIL_PCP_OBJECT_BYTES, "ceiling");
_Static_assert(_Alignof(ninlil_pcp_t) >= NINLIL_PCP_OBJECT_ALIGN, "align min");
_Static_assert(sizeof(ninlil_pcp_r2_stats_t) == 192u, "stats sizeof");
_Static_assert(_Alignof(ninlil_pcp_r2_stats_t) == 8u, "stats align");
_Static_assert(NINLIL_PCP_STAGE_GC == 11u, "stage GC=11");

/* offsetof exact order (i * 8). */
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, issue_ok) == 0u, "issue_ok@0");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, issue_deny) == 8u, "issue_deny@8");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, validate_ok) == 16u, "validate_ok@16");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, validate_deny) == 24u, "validate_deny@24");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, validate_error) == 32u, "validate_error@32");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_ok) == 40u, "consume_ok@40");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_denied) == 48u, "consume_denied@48");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_fenced) == 56u, "consume_fenced@56");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, consume_error) == 64u, "consume_error@64");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, advance_ok) == 72u, "advance_ok@72");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, advance_nop) == 80u, "advance_nop@80");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, revoke_ok) == 88u, "revoke_ok@88");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, recover_ok) == 96u, "recover_ok@96");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, recover_fail) == 104u, "recover_fail@104");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, fence_set) == 112u, "fence_set@112");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, storage_commit_unknown) == 120u, "scu@120");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, fifo_out_of_order) == 128u, "fifo@128");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reentry_reject) == 136u, "reentry@136");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, alias_reject) == 144u, "alias@144");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, gc_erased) == 152u, "gc@152");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_0) == 160u, "r0@160");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_1) == 168u, "r1@168");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_2) == 176u, "r2@176");
_Static_assert(offsetof(ninlil_pcp_r2_stats_t, reserved_zero_3) == 184u, "r3@184");

/* Width: every field must be full uint64_t (padding cannot hide uint8_t). */
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

_Static_assert(
    offsetof(ninlil_pcp_error_t, hint) == 16u,
    "error hint offset after 4xu32");
_Static_assert(
    offsetof(ninlil_pcp_issue_request_t, reserved_zero)
        > offsetof(ninlil_pcp_issue_request_t, expiry_ms),
    "issue_request field order");
/* No permit_sequence field: size must match hand layout expectation floor. */
_Static_assert(sizeof(ninlil_pcp_issue_request_t) >= 128u, "request floor");

int main(void)
{
    ninlil_pcp_object_t object = NINLIL_PCP_OBJECT_INIT;
    ninlil_pcp_r2_stats_t stats;
    ninlil_pcp_error_t err;
    ninlil_radio_hal_permit_ops_t ops;
    size_t sz;
    size_t al;

    (void)memset(&stats, 0, sizeof(stats));
    (void)memset(&err, 0, sizeof(err));
    (void)memset(&ops, 0, sizeof(ops));

    sz = ninlil_pcp_object_size();
    al = ninlil_pcp_object_align();
    if (sz == 0u || sz > NINLIL_PCP_OBJECT_BYTES) {
        return 1;
    }
    if (al < NINLIL_PCP_OBJECT_ALIGN) {
        return 2;
    }
    if (object.magic != 0u || object.lifecycle != 0u) {
        return 3;
    }
    /* Typed stats field access (not void*). Touch first + reserved. */
    stats.issue_ok = 0u;
    stats.consume_denied = 0u;
    stats.reserved_zero_0 = 0u;
    stats.reserved_zero_3 = 0u;
    err.status = NINLIL_PCP_OK;
    err.stage = NINLIL_PCP_STAGE_NONE;
    err.reason = NINLIL_PCP_REASON_NONE;
    err.reserved_zero = 0u;
    err.hint[0] = '\0';
    /* Function pointers exist as symbols only after implementation links;
     * consumer compile test must not require unresolved externals at link
     * of this TU alone beyond what is inline. permit_ops is declared extern —
     * do not call it here. */
    (void)ops;
    (void)stats;
    (void)err;
    return 0;
}
