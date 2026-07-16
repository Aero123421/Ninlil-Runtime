#include "ninlil_posix_sqlite_token_advance.h"

uint64_t ninlil_posix_sqlite_generation_advance(
    uint64_t current,
    uint64_t gen_max)
{
    uint64_t next;

    if (gen_max == 0u || current >= gen_max) {
        return 0u;
    }
    next = current + 1u;
    /* Overflow or wrap-around is permanent exhaustion, never restart at 1. */
    if (next == 0u || next > gen_max) {
        return 0u;
    }
    return next;
}

uint64_t ninlil_posix_sqlite_lease_token_advance(
    uint64_t current,
    uint64_t token_max)
{
    uint64_t next;

    if (token_max == 0u || current >= token_max) {
        return 0u;
    }
    next = current + 1u;
    if (next == 0u || next > token_max) {
        return 0u;
    }
    return next;
}
