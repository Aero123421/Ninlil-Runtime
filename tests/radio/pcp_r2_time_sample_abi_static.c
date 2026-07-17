/*
 * Header-only static_assert probe for ninlil_time_sample_t.
 * Compiled as a .c TU on host LP64 and (when available) arm-none-eabi ILP32.
 * No main — link not required; compile success is the gate.
 */
#include "ninlil/platform.h"
#include <stddef.h>
#include <stdint.h>

_Static_assert(offsetof(ninlil_time_sample_t, abi_version) == 0u, "abi@0");
_Static_assert(offsetof(ninlil_time_sample_t, struct_size) == 2u, "size@2");
_Static_assert(offsetof(ninlil_time_sample_t, clock_epoch_id) == 4u, "epoch@4");
_Static_assert(offsetof(ninlil_time_sample_t, now_ms) == 24u, "now@24");
_Static_assert(offsetof(ninlil_time_sample_t, trust) == 32u, "trust@32");
_Static_assert(offsetof(ninlil_time_sample_t, reserved_zero) == 36u, "res@36");
_Static_assert(sizeof(ninlil_time_sample_t) == 40u, "sizeof40");

/* Anchor so the TU is not empty under -Werror=unused. */
int ninlil_pcp_r2_time_sample_abi_static_anchor(void)
{
    return (int)sizeof(ninlil_time_sample_t);
}
