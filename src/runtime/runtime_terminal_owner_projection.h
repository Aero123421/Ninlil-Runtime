#ifndef NINLIL_RUNTIME_TERMINAL_OWNER_PROJECTION_H
#define NINLIL_RUNTIME_TERMINAL_OWNER_PROJECTION_H

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_rt_private_terminal_owner_v1 {
    ninlil_id128_t transaction_id;
    uint64_t release_token;
} ninlil_rt_private_terminal_owner_v1_t;

/*
 * Composition calls this only after owner-thread/re-entry validation.  The
 * query reads Runtime-owned RAM and invokes no Port callback.
 */
ninlil_status_t ninlil_rt_private_has_pending_work_v1(
    ninlil_runtime_t *runtime, uint32_t *out_present);

/*
 * Composition owns *inout_cursor and may reset it to zero for restart replay.
 * The composition owner must validate owner-thread/re-entry before calling;
 * this read-only projection intentionally invokes no Port callback.
 */
ninlil_status_t ninlil_rt_private_terminal_owner_next_v1(
    ninlil_runtime_t *runtime,
    uint32_t *inout_cursor,
    uint32_t *inout_wrap_pending,
    ninlil_rt_private_terminal_owner_v1_t *out_owner,
    uint32_t *out_present,
    uint32_t *out_more);

#ifdef __cplusplus
}
#endif

#endif
