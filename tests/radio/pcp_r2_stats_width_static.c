/*
 * Static TU: include private PCP header only to force all 24 stats field
 * width/offset _Static_assert contracts. Used by docs-gate self-test under
 * header mutations (issue_ok/reserved_zero_0 → uint8_t must fail compile).
 * No main; compile with -c.
 */

#include "pcp_authority.h"

/* Redundant consumer-side width locks (header already asserts; this TU must
 * still fail if header asserts are stripped while fields are narrowed). */
_Static_assert(sizeof(ninlil_pcp_r2_stats_t) == 192u, "stats sizeof");
_Static_assert(
    sizeof(((ninlil_pcp_r2_stats_t *)0)->issue_ok) == sizeof(uint64_t),
    "static TU issue_ok width");
_Static_assert(
    sizeof(((ninlil_pcp_r2_stats_t *)0)->reserved_zero_0) == sizeof(uint64_t),
    "static TU reserved_zero_0 width");
_Static_assert(
    sizeof(((ninlil_pcp_r2_stats_t *)0)->consume_fenced) == sizeof(uint64_t),
    "static TU consume_fenced width");
_Static_assert(
    offsetof(ninlil_pcp_r2_stats_t, reserved_zero_3) == 184u,
    "static TU r3@184");
