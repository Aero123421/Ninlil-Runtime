#ifndef NINLIL_POSIX_SQLITE_TOKEN_ADVANCE_H
#define NINLIL_POSIX_SQLITE_TOKEN_ADVANCE_H

/*
 * Private pure helpers for generation / lease-token sequences.
 * Not installed. Linked into the production archive for storage use and for
 * direct unit tests of the monotonic no-wrap contract (docs/08).
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pure monotonic advance. Return 0 on exhaustion.
 * Never wrap to a lower value: zero means permanent fail-closed under max
 * (inclusive last issuable value).
 */
uint64_t ninlil_posix_sqlite_generation_advance(
    uint64_t current,
    uint64_t gen_max);

uint64_t ninlil_posix_sqlite_lease_token_advance(
    uint64_t current,
    uint64_t token_max);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_SQLITE_TOKEN_ADVANCE_H */
