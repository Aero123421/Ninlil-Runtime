/*
 * Compile-time + runtime verification of ninlil_time_sample_t field offsets
 * from the real platform.h (not a Python hardcode).
 *
 * Normative for both:
 *   - POSIX host LP64 (pointer 8)
 *   - ESP32-S3 / ILP32-class (pointer 4; natural C11 long-long align 8)
 *
 * Layout (both classes under natural C11):
 *   abi_version@0, struct_size@2, clock_epoch_id@4,
 *   pad@20..23, now_ms@24, trust@32, reserved_zero@36, sizeof==40
 */

#include "ninlil/platform.h"
#include "ninlil/version.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

_Static_assert(offsetof(ninlil_time_sample_t, abi_version) == 0u, "abi@0");
_Static_assert(offsetof(ninlil_time_sample_t, struct_size) == 2u, "size@2");
_Static_assert(offsetof(ninlil_time_sample_t, clock_epoch_id) == 4u, "epoch@4");
_Static_assert(offsetof(ninlil_time_sample_t, now_ms) == 24u, "now@24");
_Static_assert(offsetof(ninlil_time_sample_t, trust) == 32u, "trust@32");
_Static_assert(offsetof(ninlil_time_sample_t, reserved_zero) == 36u, "res@36");
_Static_assert(sizeof(ninlil_time_sample_t) == 40u, "sizeof 40");
_Static_assert(_Alignof(ninlil_time_sample_t) >= 8u, "align>=8");

/* Field order must match platform.h; swapping would break these names. */
_Static_assert(
    offsetof(ninlil_time_sample_t, now_ms)
        > offsetof(ninlil_time_sample_t, clock_epoch_id),
    "now after epoch");
_Static_assert(
    offsetof(ninlil_time_sample_t, trust)
        > offsetof(ninlil_time_sample_t, now_ms),
    "trust after now");

int main(void)
{
    printf(
        "ninlil_time_sample_t ptr=%zu sizeof=%zu align=%zu "
        "now=%zu trust=%zu\n",
        sizeof(void *),
        sizeof(ninlil_time_sample_t),
        (size_t)_Alignof(ninlil_time_sample_t),
        offsetof(ninlil_time_sample_t, now_ms),
        offsetof(ninlil_time_sample_t, trust));
    if (offsetof(ninlil_time_sample_t, now_ms) != 24u) {
        return 1;
    }
    if (offsetof(ninlil_time_sample_t, trust) != 32u) {
        return 2;
    }
    if (sizeof(ninlil_time_sample_t) != 40u) {
        return 3;
    }
    return 0;
}
